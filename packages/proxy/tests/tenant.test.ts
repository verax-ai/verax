import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { approvePending } from "../src/approvals.ts";
import { sha256Canonical } from "../src/hash.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { tenantKey } from "../src/tenant.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

describe("S4 tenant key", () => {
  it("hashes { iss, sub } and never an aud field", () => {
    const key = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.equal(key, sha256Canonical({ iss: "https://issuer-a.example", sub: "alice" }));
    assert.equal(key.includes("aud"), false);
    const again = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.equal(again, key);
  });

  it("same iss+sub stay equal when a tenant/org claim is absent", () => {
    const a = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    const b = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.equal(a, b);
  });

  it("different sub or iss, or a tenant claim, change the key", () => {
    const base = tenantKey({ brain: "alice", iss: "https://issuer-a.example" });
    assert.notEqual(base, tenantKey({ brain: "bob", iss: "https://issuer-a.example" }));
    assert.notEqual(base, tenantKey({ brain: "alice", iss: "https://issuer-b.example" }));
    assert.notEqual(
      base,
      tenantKey({ brain: "alice", iss: "https://issuer-a.example", tenant: "org-1" }),
    );
  });
});

const SPEND_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "spend-true",
      tool: "spend",
      requires: ["verax:pay"],
      mode: "approve",
      text: "Spends need operator approval.",
      spend: { maxAmountMinor: 200_000, currency: "TRY", payees: ["true-ads"] },
    },
  ],
} as const;

const spendArgs = { amountMinor: 125_050, currency: "TRY", payee: "true-ads", reference: "verax:d1" };

function spendProxy(ledger: MemoryLedger, allowRef: string) {
  let inner = 0;
  const now = tickingNow();
  const proxy = createProxy({
    policy: loadPolicy(SPEND_POLICY),
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now,
    nonce: queuedNonce([allowRef]),
    inner: async () => {
      inner += 1;
      return { content: [{ type: "text", text: "ok" }], isError: false };
    },
  });
  return { proxy, now, ran: () => inner };
}

describe("S4 tenant _ref and the approval loop", () => {
  const payer = { brain: "brain-1", scopes: new Set(["verax:pay"]), iss: "https://issuer-a.example" };
  const call = { name: "spend", arguments: { ...spendArgs, _ref: "d1" } };

  it("a token that carries iss can retry the _ref an operator approved", async () => {
    const ledger = new MemoryLedger();
    const { proxy, now, ran } = spendProxy(ledger, "t-spare");
    const deferred = await proxy.call(call, payer);
    // The brain must get back a ref it can resend as `_ref`; `_ref` takes no colon.
    assert.equal(deferred.content[0]?.text, "deferred:approval-required:d1");

    const scoped = `${tenantKey(payer)}:d1`;
    const record = (await ledger.decisions())[0]!;
    assert.equal(record.claims.ref, scoped);

    const approved = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["t-op"]),
      ref: scoped,
      approverId: "op",
      policyHash: record.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(approved.ok, true);

    const retry = await proxy.call(call, payer);
    assert.equal(retry.content[0]?.text, "allowed:t-op");
    assert.equal(ran(), 0);
  });

  it("an approval in one tenant does not resolve the same _ref in another", async () => {
    const other = { brain: "brain-1", scopes: new Set(["verax:pay"]), iss: "https://issuer-b.example" };
    const ledger = new MemoryLedger();
    const { proxy, now } = spendProxy(ledger, "t-spare");
    await proxy.call(call, payer);
    await proxy.call(call, other);

    const mine = (await ledger.decisions()).find((d) => d.claims.ref === `${tenantKey(payer)}:d1`)!;
    const approved = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["t-op"]),
      ref: `${tenantKey(payer)}:d1`,
      approverId: "op",
      policyHash: mine.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(approved.ok, true);

    const theirs = await proxy.call(call, other);
    assert.equal(theirs.content[0]?.text, "deferred:approval-required:d1");
    const mineRetry = await proxy.call(call, payer);
    assert.equal(mineRetry.content[0]?.text, "allowed:t-op");
  });
});
