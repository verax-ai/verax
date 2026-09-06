import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { approvePending } from "../src/approvals.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

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
      spend: { maxAmountMinor: 200_000, currency: "TRY", payees: ["true-ads"], dailyMaxMinor: 300_000 },
    },
  ],
} as const;

const payer = { brain: "brain-1", scopes: new Set(["verax:pay"]) };
const spendArgs = {
  amountMinor: 125_050,
  currency: "TRY",
  payee: "true-ads",
  reference: "verax:d1",
};

function spendCall(extra: Record<string, unknown> = {}) {
  return { name: "spend", arguments: { ...spendArgs, ...extra } };
}

describe("spend policy and authorize-once", () => {
  it("pay stays spend-not-wired and unruled spend stays spend-not-wired", () => {
    const bare = loadPolicy({ version: 1, default: "deny", rules: [] });
    assert.deepEqual(bare.evaluate({ name: "pay", arguments: {} }, payer), {
      decision: "deny",
      reasonCode: "spend-not-wired",
      rule: null,
    });
    assert.deepEqual(bare.evaluate(spendCall(), payer), {
      decision: "deny",
      reasonCode: "spend-not-wired",
      rule: null,
    });
  });

  it("spend rule without approve mode or spend field is a parse error", () => {
    assert.throws(
      () =>
        loadPolicy({
          version: 1,
          default: "deny",
          rules: [{ id: "s", tool: "spend", requires: ["verax:pay"], text: "x" }],
        }),
      /policy-rule-spend-mode:s/,
    );
    assert.throws(
      () =>
        loadPolicy({
          version: 1,
          default: "deny",
          rules: [{ id: "s", tool: "spend", requires: ["verax:pay"], mode: "approve", text: "x" }],
        }),
      /policy-rule-spend-missing:s/,
    );
  });

  it("each spend deny is a signed ledger row", async () => {
    const cases: Array<{ args: Record<string, unknown>; scopes?: string[]; code: string }> = [
      { args: { amountMinor: 1.5, currency: "TRY", payee: "true-ads", reference: "r" }, code: "spend-args-invalid" },
      { args: { ...spendArgs, currency: "USD" }, code: "spend-currency" },
      { args: { ...spendArgs, amountMinor: 200_001 }, code: "spend-cap" },
      { args: { ...spendArgs, payee: "other" }, code: "spend-payee" },
    ];
    for (const c of cases) {
      const ledger = new MemoryLedger();
      const proxy = createProxy({
        policy: loadPolicy(SPEND_POLICY),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce([`n-${c.code}`]),
        inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
      });
      const out = await proxy.call(
        { name: "spend", arguments: c.args },
        { brain: "brain-1", scopes: new Set(c.scopes ?? ["verax:pay"]) },
      );
      assert.match(out.content[0]?.text ?? "", new RegExp(`denied:${c.code}:`));
      const rec = (await ledger.decisions())[0]!;
      assert.equal(rec.claims.decision, "deny");
      assert.equal(rec.claims.reasonCode, c.code);
      assert.equal(typeof rec.coseHex, "string");
    }
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy: loadPolicy(SPEND_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["n-scope"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    const scoped = await proxy.call(spendCall(), { brain: "brain-1", scopes: new Set() });
    assert.match(scoped.content[0]?.text ?? "", /denied:scope-missing:/);
  });

  it("passing checks defer and pending counts toward the daily cap", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow(Date.UTC(2026, 8, 6, 12), 10);
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy(SPEND_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now,
      nonce: queuedNonce(["d1", "d2"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    const first = await proxy.call({ name: "spend", arguments: { ...spendArgs, _ref: "d1" } }, payer);
    assert.match(first.content[0]?.text ?? "", /deferred:approval-required:d1/);
    const second = await proxy.call(
      { name: "spend", arguments: { ...spendArgs, amountMinor: 200_000, reference: "verax:d2", _ref: "d2" } },
      payer,
    );
    assert.match(second.content[0]?.text ?? "", /denied:spend-daily:/);
    assert.equal(inner, 0);
    const rec = (await ledger.decisions()).find((d) => d.claims.reasonCode === "spend-daily");
    assert.ok(rec);
    assert.equal(rec.claims.decision, "deny");
  });

  it("p: spend retry after a missing effect is spend-reauth-required and does not run inner", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    let inner = 0;
    const orig = ledger.appendEffect.bind(ledger);
    let skip = true;
    ledger.appendEffect = async (...args: Parameters<typeof orig>) => {
      if (skip) {
        skip = false;
        throw new Error("crash before effect");
      }
      return orig(...args);
    };
    const proxy = createProxy({
      policy: loadPolicy(SPEND_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now,
      nonce: queuedNonce(["reauth-1"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    await proxy.call({ name: "spend", arguments: { ...spendArgs, _ref: "p1" } }, payer);
    const policyHash = (await ledger.decisions())[0]!.claims.policyHash;
    await assert.rejects(
      () =>
        approvePending({
          ledger,
          recordSigner: RECORD_SIGNER,
          now,
          nonce: queuedNonce(["a1"]),
          ref: "p1",
          approverId: "op",
          policyHash,
          approvals: proxy.approvals,
          inputsLog: proxy.inputsLog,
        }),
      /crash before effect/,
    );
    const retry = await proxy.call({ name: "spend", arguments: { ...spendArgs, _ref: "p1" } }, payer);
    assert.match(retry.content[0]?.text ?? "", /denied:spend-reauth-required:reauth-1/);
    assert.equal(inner, 0);
    const recs = await ledger.decisions();
    const reauth = recs.find((d) => d.claims.reasonCode === "spend-reauth-required");
    assert.ok(reauth);
    assert.notEqual(reauth.claims.ref, "p1");
    assert.notEqual(reauth.claims.ref, "a1");
    assert.equal(reauth.claims.requestHash, recs[0]!.claims.requestHash);
  });

  it("q: memory.put still re-runs inner when the effect row is missing", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    let inner = 0;
    const orig = ledger.appendEffect.bind(ledger);
    let skip = true;
    ledger.appendEffect = async (...args: Parameters<typeof orig>) => {
      if (skip) {
        skip = false;
        return;
      }
      return orig(...args);
    };
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        approvalTtlMs: 86_400_000,
        rules: [
          {
            id: "put",
            tool: "memory.put",
            requires: ["verax:memory"],
            mode: "approve",
            text: "Writes need operator approval.",
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now,
      nonce: queuedNonce(["gen"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    const call = {
      name: "memory.put",
      arguments: { id: "n1", body: "hello", source: { kind: "t" }, validUntilMs: 9_999, _ref: "q1" },
    };
    await proxy.call(call, { brain: "brain-1", scopes: new Set(["verax:memory"]) });
    await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["aq"]),
      ref: "q1",
      approverId: "op",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    const first = await proxy.call(call, { brain: "brain-1", scopes: new Set(["verax:memory"]) });
    assert.equal(first.isError, false);
    assert.equal(inner, 1);
    const again = await proxy.call(call, { brain: "brain-1", scopes: new Set(["verax:memory"]) });
    assert.equal(again.isError, false);
    assert.equal(inner, 2);
  });
});
