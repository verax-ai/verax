import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { decisionRecordHash } from "@cedulon/core";

import {
  approvalFs,
  approvePending,
  drainApprovalCommands,
  drainMetrics,
  enqueueApprovalCommand,
} from "../src/approvals.ts";
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

const MIXED_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "memory-put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
    {
      id: "memory-get",
      tool: "memory.get",
      requires: ["verax:read"],
      text: "Reading memory needs the read scope.",
    },
  ],
} as const;

function proxyOf(opts: {
  ledger: MemoryLedger;
  now: () => number;
  nonce: () => string;
  policy?: unknown;
  inner?: () => Promise<{ content: { type: "text"; text: string }[]; isError: boolean }>;
}) {
  let innerCalls = 0;
  const proxy = createProxy({
    policy: loadPolicy(opts.policy ?? APPROVE_POLICY),
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
    assert.equal(inputs?.approver?.resolves, "d1");
    const snap = await proxy.approvals.get("d1");
    assert.equal(snap?.status, "approved");
    assert.equal(snap?.allowRef, "a1");
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

  it("i: an interleaved decision still pairs and a second approve is refused", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    const { proxy } = proxyOf({
      ledger,
      now,
      nonce: queuedNonce(["d1", "g1", "a1", "a2"]),
      policy: MIXED_POLICY,
    });
    await proxy.call(putCall, principal);
    await proxy.call(
      { name: "memory.get", arguments: { id: "x" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    const defer = (await ledger.decisions())[0]!;
    const first = await approvePending({
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
    assert.equal(first.ok, true);
    const second = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["a2"]),
      ref: "d1",
      approverId: "op-1",
      policyHash: defer.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(second.ok, false);
    if (second.ok === false) assert.equal(second.reason, "already-resolved");
    const recs = await ledger.decisions();
    assert.equal(recs.filter((d) => d.claims.reasonCode === "approved-by-operator").length, 1);
    const fromDefer = await explain(ledger, "d1");
    assert.equal(fromDefer.pair?.resolution?.claims.ref, "a1");
    const allowInputs = await proxy.inputsLog.get("a1");
    assert.equal(allowInputs?.approver?.resolves, "d1");
    const snap = await proxy.approvals.get("d1");
    assert.equal(snap?.status, "approved");
    assert.equal(snap?.allowRef, "a1");
  });

  it("j: a second _ref for the same command does not ride the first approval", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    const { proxy, innerCalls } = proxyOf({
      ledger,
      now,
      nonce: queuedNonce(["gen"]),
    });
    const args = putCall.arguments;
    await proxy.call({ name: "memory.put", arguments: { ...args, _ref: "s1" } }, principal);
    await proxy.call({ name: "memory.put", arguments: { ...args, _ref: "s2" } }, principal);
    await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["a1"]),
      ref: "s1",
      approverId: "op-1",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    const out = await proxy.call({ name: "memory.put", arguments: { ...args, _ref: "s2" } }, principal);
    assert.match(out.content[0]?.text ?? "", /deferred:approval-required:s2/);
    assert.equal(innerCalls(), 0);
    const snap = await proxy.approvals.get("s2");
    assert.equal(snap?.status, "pending");
  });

  it("k: drain renames first so a later enqueue is not unlinked", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-drain-"));
    enqueueApprovalCommand(dir, { ref: "a", approverId: "op", atMs: 1 });
    const seen: string[] = [];
    await drainApprovalCommands(dir, async (cmd) => {
      seen.push(cmd.ref);
      if (cmd.ref === "a") enqueueApprovalCommand(dir, { ref: "b", approverId: "op", atMs: 2 });
    });
    assert.deepEqual(seen, ["a"]);
    assert.equal(existsSync(join(dir, "approval-commands.jsonl")), true);
    assert.match(readFileSync(join(dir, "approval-commands.jsonl"), "utf8"), /"ref":"b"/);
  });

  it("l: retry repairs the snapshot after updateStatus throws once", async () => {
    const ledger = new MemoryLedger();
    const now = tickingNow();
    const { proxy, innerCalls } = proxyOf({ ledger, now, nonce: queuedNonce(["unused"]) });
    const call = { ...putCall, arguments: { ...putCall.arguments, _ref: "r1" } };
    await proxy.call(call, principal);
    const policyHash = (await ledger.decisions())[0]!.claims.policyHash;
    const orig = proxy.approvals.updateStatus.bind(proxy.approvals);
    let armed = true;
    proxy.approvals.updateStatus = async (...args: Parameters<typeof orig>) => {
      if (armed) {
        armed = false;
        throw new Error("simulated crash after ledger append");
      }
      return orig(...args);
    };
    await assert.rejects(
      () =>
        approvePending({
          ledger,
          recordSigner: RECORD_SIGNER,
          now,
          nonce: queuedNonce(["a1"]),
          ref: "r1",
          approverId: "op-1",
          policyHash,
          approvals: proxy.approvals,
          inputsLog: proxy.inputsLog,
        }),
      /simulated crash after ledger append/,
    );
    const retry = await proxy.call(call, principal);
    assert.equal(retry.isError, false);
    assert.equal(innerCalls(), 1);
    const second = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now,
      nonce: queuedNonce(["a2"]),
      ref: "r1",
      approverId: "op-1",
      policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(second.ok, false);
    if (second.ok === false) assert.equal(second.reason, "already-resolved");
    assert.equal((await proxy.approvals.listPending()).length, 0);
    const snap = await proxy.approvals.get("r1");
    assert.equal(snap?.status, "approved");
    assert.equal(snap?.allowRef, "a1");
  });

  it("m: expiry crash does not write a second expired record", async () => {
    const ledger = new MemoryLedger();
    let t = 100;
    const { proxy } = proxyOf({
      ledger,
      now: () => t,
      nonce: queuedNonce(["e1", "e2"]),
    });
    const call = { ...putCall, arguments: { ...putCall.arguments, _ref: "m1" } };
    await proxy.call(call, principal);
    const orig = proxy.approvals.updateStatus.bind(proxy.approvals);
    let armed = true;
    proxy.approvals.updateStatus = async (...args: Parameters<typeof orig>) => {
      if (armed) {
        armed = false;
        throw new Error("simulated crash after ledger append");
      }
      return orig(...args);
    };
    t = 100 + 1_000 + 1;
    await assert.rejects(() => proxy.call(call, principal), /simulated crash after ledger append/);
    const second = await proxy.call(call, principal);
    assert.match(second.content[0]?.text ?? "", /denied:expired:e1/);
    const expired = (await ledger.decisions()).filter((d) => d.claims.reasonCode === "expired");
    assert.equal(expired.length, 1);
    assert.equal(expired[0]!.claims.ref, "e1");
  });

  it("n: a truncated queue line is poisoned and drain stays usable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-poison-"));
    writeFileSync(join(dir, "approval-commands.jsonl"), '{"ref":"a","approverId":"op","atMs":1}\n{"ref":"b"', "utf8");
    const seen: string[] = [];
    await drainApprovalCommands(dir, async (cmd) => {
      seen.push(cmd.ref);
    });
    assert.deepEqual(seen, ["a"]);
    const poisonPath = join(dir, "approval-commands.poison.jsonl");
    assert.equal(existsSync(poisonPath), true);
    const poison = readFileSync(poisonPath, "utf8")
      .trim()
      .split("\n")
      .filter((line) => line !== "");
    assert.equal(poison.length, 1);
    const leftover = readdirSync(dir).filter((n) => n.startsWith("approval-commands"));
    assert.equal(
      leftover.some((n) => n.startsWith("approval-commands.processing-")),
      false,
    );
    await drainApprovalCommands(dir, async (cmd) => {
      seen.push(cmd.ref);
    });
    assert.deepEqual(seen, ["a"]);
  });

  it("o: lazy expiry written by the proxy claims via proxy", async () => {
    const ledger = new MemoryLedger();
    let t = 100;
    const { proxy } = proxyOf({
      ledger,
      now: () => t,
      nonce: queuedNonce(["e1"]),
    });
    const call = { ...putCall, arguments: { ...putCall.arguments, _ref: "x1" } };
    await proxy.call(call, principal);
    t = 100 + 1_000 + 1;
    const out = await proxy.call(call, principal);
    assert.match(out.content[0]?.text ?? "", /denied:expired:e1/);
    const inputs = await proxy.inputsLog.get("e1");
    assert.equal(inputs?.approver?.via, "proxy");
    assert.equal(inputs?.approver?.id, "verax-proxy");
    assert.equal(inputs?.approver?.resolves, "x1");
  });

  it("S2-8: a busy rename writes stderr and increments a counter", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-drain-busy-"));
    enqueueApprovalCommand(dir, { ref: "a", approverId: "op", atMs: 1 });
    const orig = approvalFs.renameSync;
    const before = drainMetrics.renameBusy;
    const writes: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
      writes.push(String(chunk));
      return (origWrite as (c: string | Uint8Array, ...a: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stderr.write;
    approvalFs.renameSync = () => {
      const err = new Error("busy") as NodeJS.ErrnoException;
      err.code = "EBUSY";
      throw err;
    };
    try {
      const seen: string[] = [];
      await drainApprovalCommands(dir, async (cmd) => {
        seen.push(cmd.ref);
      });
      assert.deepEqual(seen, []);
      assert.equal(drainMetrics.renameBusy, before + 1);
      assert.ok(writes.some((w) => /verax-drain: rename-busy EBUSY count=/.test(w)));
    } finally {
      approvalFs.renameSync = orig;
      process.stderr.write = origWrite;
    }
  });
});
