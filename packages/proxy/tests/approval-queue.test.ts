import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { decisionRecordHash } from "@cedulon/core";

import { approvePending } from "../src/approvals.ts";
import { explain } from "../src/explain.ts";
import { effectDescriptor, sha256Canonical } from "../src/hash.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const APPROVE_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 1_000,
  rules: [
    {
      id: "memory-put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
  ],
} as const;

const principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
const putCall = {
  name: "memory.put",
  arguments: { id: "n1", body: "hello", source: { kind: "test" }, validUntilMs: 9_999 },
};

function proxyOf(opts: {
  ledger: MemoryLedger;
  now: () => number;
  nonce: () => string;
  inner?: () => Promise<{ content: { type: "text"; text: string }[]; isError: boolean }>;
}) {
  let innerCalls = 0;
  const proxy = createProxy({
    policy: loadPolicy(APPROVE_POLICY),
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger: opts.ledger,
    now: opts.now,
    nonce: opts.nonce,
    inner: async () => {
      innerCalls += 1;
      return opts.inner
        ? opts.inner()
        : { content: [{ type: "text", text: "ok" }], isError: false };
    },
  });
  return { proxy, innerCalls: () => innerCalls };
}

describe("approval queue", () => {
  it("a: mode approve writes a signed chained defer and does not call inner", async () => {
    const ledger = new MemoryLedger();
    const { proxy, innerCalls } = proxyOf({
      ledger,
      now: tickingNow(100, 10),
      nonce: queuedNonce(["d1"]),
    });
    const out = await proxy.call(putCall, principal);
    assert.equal(out.isError, true);
    assert.match(out.content[0]?.text ?? "", /deferred:approval-required:d1/);
    assert.equal(innerCalls(), 0);
    const rec = (await ledger.decisions())[0]!;
    assert.equal(rec.claims.decision, "defer");
    assert.equal(rec.claims.reasonCode, "approval-required");
    assert.equal(rec.claims.ref, "d1");
    assert.equal(rec.claims.effectHash, null);
    assert.equal(rec.claims.prevRecordHash, null);
    const q = await proxy.approvals.listPending();
    assert.equal(q.length, 1);
    assert.equal(q[0]!.ref, "d1");
    assert.equal(q[0]!.ruleText, "Writes need operator approval.");
    assert.equal(q[0]!.subject, "memory.put");
  });

  it("b: approve is a second signed allow bound by requestHash", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow(100, 10);
    const { proxy } = proxyOf({ ledger, now, nonce: queuedNonce(["d1", "a1"]) });
    await proxy.call(putCall, principal);
    const defer = (await ledger.decisions())[0]!;
    const result = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["a1"]),
      ref: "d1",
      approverId: "op-1",
      policyHash: defer.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(result.ok, true);
    const recs = await ledger.decisions();
    assert.equal(recs.length, 2);
    assert.equal(recs[1]!.claims.decision, "allow");
    assert.equal(recs[1]!.claims.reasonCode, "approved-by-operator");
    assert.equal(recs[1]!.claims.requestHash, defer.claims.requestHash);
    assert.equal(recs[1]!.claims.prevRecordHash, decisionRecordHash(defer));
    const dispatched = { id: "n1", body: "hello", source: { kind: "test" }, validUntilMs: 9_999 };
    assert.equal(
      recs[1]!.claims.effectHash,
      sha256Canonical(effectDescriptor("memory.put", dispatched)),
    );
    assert.notEqual(recs[1]!.claims.effectHash, recs[1]!.claims.requestHash);
    const inputs = await proxy.inputsLog.get(recs[1]!.claims.ref!);
    assert.equal(inputs?.approver?.id, "op-1");
    assert.equal(inputs?.approver?.via, "cli");
  });

  it("c: different arguments are a new defer", async () => {
    const ledger = new MemoryLedger();
    const { proxy } = proxyOf({ ledger, now: tickingNow(), nonce: queuedNonce(["d1", "d2"]) });
    await proxy.call(putCall, principal);
    await proxy.call(
      { ...putCall, arguments: { ...putCall.arguments, body: "other" } },
      principal,
    );
    const recs = await ledger.decisions();
    assert.equal(recs.length, 2);
    assert.equal(recs[0]!.claims.decision, "defer");
    assert.equal(recs[1]!.claims.decision, "defer");
    assert.notEqual(recs[0]!.claims.requestHash, recs[1]!.claims.requestHash);
  });

  it("d: after TTL, approve writes deny expired", async () => {
    const ledger = new MemoryLedger();
    let t = 100;
    const { proxy } = proxyOf({
      ledger,
      now: () => t,
      nonce: queuedNonce(["d1", "e1"]),
    });
    await proxy.call(putCall, principal);
    t = 100 + 1_000 + 1;
    const result = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now: () => t,
      nonce: queuedNonce(["e1"]),
      ref: "d1",
      approverId: "op-1",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(result.ok, false);
    if (result.ok === false) assert.equal(result.reason, "expired");
    const recs = await ledger.decisions();
    assert.equal(recs[1]!.claims.decision, "deny");
    assert.equal(recs[1]!.claims.reasonCode, "expired");
  });

  it("e: same _ref + same requestHash does not write a third record", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    const { proxy, innerCalls } = proxyOf({
      ledger,
      now,
      nonce: queuedNonce(["gen1"]),
    });
    const call = { ...putCall, arguments: { ...putCall.arguments, _ref: "idem-1" } };
    await proxy.call(call, principal);
    await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["a1"]),
      ref: "idem-1",
      approverId: "op-1",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    const again = await proxy.call(call, principal);
    assert.equal(again.isError, false);
    assert.equal((await ledger.decisions()).length, 2);
    assert.equal(innerCalls(), 1);
    const replay = await proxy.call(call, principal);
    assert.equal(replay.isError, false);
    assert.equal((await ledger.decisions()).length, 2);
    assert.equal(innerCalls(), 1);
  });

  it("f: same _ref + different args is deny ref-reuse under a new nonce", async () => {
    const ledger = new MemoryLedger();
    const { proxy } = proxyOf({ ledger, now: tickingNow(), nonce: queuedNonce(["n-reuse"]) });
    await proxy.call({ ...putCall, arguments: { ...putCall.arguments, _ref: "same" } }, principal);
    const out = await proxy.call(
      { ...putCall, arguments: { ...putCall.arguments, body: "swap", _ref: "same" } },
      principal,
    );
    assert.match(out.content[0]?.text ?? "", /denied:ref-reuse:n-reuse/);
    const recs = await ledger.decisions();
    assert.equal(recs.length, 2);
    assert.equal(recs[1]!.claims.reasonCode, "ref-reuse");
    assert.equal(recs[1]!.claims.ref, "n-reuse");
    assert.notEqual(recs[1]!.claims.ref, "same");
  });

  it("g: invalid _ref is deny ref-invalid with a generated ref", async () => {
    const ledger = new MemoryLedger();
    const { proxy } = proxyOf({ ledger, now: tickingNow(), nonce: queuedNonce(["n-bad"]) });
    const out = await proxy.call(
      { ...putCall, arguments: { ...putCall.arguments, _ref: "bad ref!" } },
      principal,
    );
    assert.match(out.content[0]?.text ?? "", /denied:ref-invalid:n-bad/);
    assert.equal((await ledger.decisions())[0]!.claims.ref, "n-bad");
  });

  it("h: explain pair shows defer and allow", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    const { proxy } = proxyOf({ ledger, now, nonce: queuedNonce(["d1"]) });
    await proxy.call(putCall, principal);
    await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["a1"]),
      ref: "d1",
      approverId: "op-1",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    const fromDefer = await explain(ledger, "d1");
    assert.equal(fromDefer.pair?.defer?.claims.ref, "d1");
    assert.equal(fromDefer.pair?.resolution?.claims.ref, "a1");
    const fromAllow = await explain(ledger, "a1");
    assert.equal(fromAllow.pair?.defer?.claims.ref, "d1");
    assert.equal(fromAllow.pair?.resolution?.claims.decision, "allow");
  });
});
