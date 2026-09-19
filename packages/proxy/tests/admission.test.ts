import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { approvePending } from "../src/approvals.ts";
import { sha256Canonical } from "../src/hash.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { tenantKey } from "../src/tenant.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

const READ_POLICY = {
  version: 1,
  default: "deny",
  limits: { ratePerMinute: 1 },
  rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
} as const;

const APPROVE_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
  ],
} as const;

describe("admission lock", () => {
  it("a: eight parallel calls with ratePerMinute 1 write one allow", async () => {
    const ledger = new MemoryLedger();
    let n = 0;
    const proxy = createProxy({
      policy: loadPolicy(READ_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_700_000_000_000, 10),
      nonce: () => `n-${++n}`,
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        proxy.call({ name: "memory.get", arguments: { id: `x${i}` } }, reader),
      ),
    );
    const recs = await ledger.decisions();
    const allows = recs.filter((d) => d.claims.decision === "allow");
    const limited = recs.filter((d) => d.claims.reasonCode === "rate-limited" || d.claims.reasonCode === "daily-limited");
    assert.equal(allows.length, 1);
    assert.equal(limited.length, 7);
    assert.equal(recs.length, 8);
    assert.equal(results.filter((r) => r.isError).length, 7);
  });

  it("b: eight parallel calls with the same _ref run inner once and replay the rest", async () => {
    const ledger = new MemoryLedger();
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["unused"]),
      inner: async () => {
        inner += 1;
        // Slow enough that the other seven reach the ledger while this one is
        // still in flight; an instant tool would hide a missing registry.
        await new Promise((resolve) => setTimeout(resolve, 40));
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    const call = { name: "memory.get", arguments: { id: "same", _ref: "same" } };
    const results = await Promise.all(Array.from({ length: 8 }, () => proxy.call(call, reader)));
    assert.equal(inner, 1);
    const replays = results.filter((r) => (r.content[0]?.text ?? "").startsWith("allowed:"));
    const ran = results.filter((r) => r.content[0]?.text === "ok");
    assert.equal(ran.length, 1);
    assert.equal(replays.length, 7);
  });

  it("e: a retry after :threw is isError, does not start with allowed:, and does not run inner again", async () => {
    const ledger = new MemoryLedger();
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["unused"]),
      inner: async () => {
        inner += 1;
        throw new Error("arac patladi");
      },
    });
    const call = { name: "memory.get", arguments: { id: "same", _ref: "r-b4" } };
    await assert.rejects(() => proxy.call(call, reader));
    const replay = await proxy.call(call, reader);
    assert.equal(inner, 1);
    assert.equal(replay.isError, true);
    const text = replay.content[0]?.text ?? "";
    assert.ok(!text.startsWith("allowed:"), text);
    assert.equal(text, "threw:r-b4");
    const effects = await ledger.effects();
    const primary = effects.find((e) => e.row.effectClass !== "duplicate-effect");
    assert.equal(primary?.row.effectClass, "memory.get:threw");
  });

  it("c: an allow with no effect and no in-flight row is outcome-unknown and does not run inner", async () => {
    const ledger = new MemoryLedger();
    const policy = loadPolicy({
      version: 1,
      default: "deny",
      rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
    });
    const requestHash = sha256Canonical({ name: "memory.get", arguments: { id: "a" } });
    await ledger.appendDecision({
      claims: {
        decider: "verax-proxy",
        subject: "memory.get",
        requestHash,
        policyHash: policy.hash,
        inputsHash: "00".repeat(32),
        decision: "allow",
        reasonCode: "allow",
        ref: "ghost-1",
        effectHash: "11".repeat(32),
        effectClass: "memory.get",
        timestampMs: 1,
        nonce: "ghost-1",
        prevRecordHash: null,
      },
      publicKeyPem: RECORD_SIGNER.publicKeyPem,
      encoding: "cose",
      coseHex: "aa".repeat(64),
    });
    ledger.noteTenantRef(tenantKey(reader), "ghost-1");
    let inner = 0;
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["unk-1"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    const out = await proxy.call({ name: "memory.get", arguments: { id: "a", _ref: "ghost-1" } }, reader);
    assert.equal(inner, 0);
    assert.match(out.content[0]?.text ?? "", /denied:outcome-unknown:unk-1/);
    const recs = await ledger.decisions();
    const unknown = recs.find((d) => d.claims.reasonCode === "outcome-unknown");
    assert.ok(unknown);
    assert.equal(unknown.claims.decision, "deny");
    assert.equal(unknown.claims.ref, "unk-1");
  });

  it("d: four parallel approvePending calls resolve once", async () => {
    const ledger = new MemoryLedger();
    const writer = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    const put = {
      name: "memory.put",
      arguments: { id: "n1", body: "hello", source: { kind: "test" }, validUntilMs: 9_999 },
    };
    const proxy = createProxy({
      policy: loadPolicy(APPROVE_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(100, 10),
      nonce: queuedNonce(["d1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(put, writer);
    const defer = (await ledger.decisions())[0]!;
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        approvePending({
          ledger,
          recordSigner: RECORD_SIGNER,
          now: () => 200,
          nonce: () => `a-${crypto.randomUUID()}`,
          ref: "d1",
          approverId: "op-1",
          via: "cli",
          policyHash: defer.claims.policyHash,
          approvals: proxy.approvals,
          inputsLog: proxy.inputsLog,
        }),
      ),
    );
    const ok = results.filter((r) => r.ok);
    const refused = results.filter((r) => !r.ok);
    assert.equal(ok.length, 1);
    assert.equal(refused.length, 3);
    assert.ok(refused.every((r) => r.ok === false && r.reason === "already-resolved"));
    const recs = await ledger.decisions();
    assert.equal(recs.filter((d) => d.claims.reasonCode === "approved-by-operator").length, 1);
  });
});
