import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import type { SignedDecisionRecord } from "@cedulon/core";

import { approvePending } from "../src/approvals.ts";
import { explain } from "../src/explain.ts";
import { FileLedger, ledgerFs } from "../src/ledger.ts";
import { createProxy } from "../src/proxy.ts";
import { loadPolicy } from "../src/policy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const worker = join(here, "ledger-perf-worker.ts");
const policy = loadPolicy(readFileSync(join(here, "..", "policy", "default.json"), "utf8"));

type HandleSync = {
  sync: (...args: unknown[]) => Promise<unknown>;
};

function cheapRecord(i: number, prev: string | null): SignedDecisionRecord {
  return {
    claims: {
      decider: "verax-proxy",
      subject: "memory.get",
      requestHash: "00".repeat(32),
      policyHash: "00".repeat(32),
      inputsHash: "00".repeat(32),
      decision: "allow",
      reasonCode: "allow",
      ref: `perf-${i}`,
      effectHash: "11".repeat(32),
      timestampMs: i,
      nonce: `perf-${i}`,
      prevRecordHash: prev,
    },
    publicKeyPem: "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----\n",
    encoding: "cose",
    coseHex: i.toString(16).padStart(128, "0"),
  };
}

describe("B8 FileLedger append cost and durability", () => {
  it("2000 chained appends reread decisions.jsonl zero times (wall-clock ratio is printed, not asserted)", () => {
    const ran = spawnSync(process.execPath, ["--experimental-strip-types", worker], {
      encoding: "utf8",
      timeout: 60_000,
    });
    const text = `${ran.stdout}${ran.stderr}`;
    const line = text.split(/\r?\n/).find((row) => row.startsWith("ledger-perf "));
    assert.ok(line, text);
    console.log(line);
    assert.equal(ran.status, 0, `${line}\n${text}`);
    const reads = Number(/decisionReads=([0-9]+)/.exec(line)?.[1]);
    assert.equal(reads, 0, line);
  });

  it("chained append does not reread decisions.jsonl", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reread-"));
    const ledger = new FileLedger(dir);
    let reads = 0;
    const origRead = ledgerFs.readFile.bind(ledgerFs);
    const origReadSync = ledgerFs.readFileSync.bind(ledgerFs);
    ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
      if (String(path).endsWith("decisions.jsonl")) reads += 1;
      return origRead(path, ...(rest as []));
    }) as typeof ledgerFs.readFile;
    ledgerFs.readFileSync = ((path: Parameters<typeof origReadSync>[0], ...rest: unknown[]) => {
      if (String(path).endsWith("decisions.jsonl")) reads += 1;
      return origReadSync(path, ...(rest as []));
    }) as typeof ledgerFs.readFileSync;
    try {
      for (let i = 0; i < 200; i += 1) {
        await ledger.appendDecisionChained((prev) => cheapRecord(i, prev));
      }
      assert.equal(reads, 0, `decision rereads during append: ${reads}`);
    } finally {
      ledgerFs.readFile = origRead;
      ledgerFs.readFileSync = origReadSync;
      ledger.close();
    }
  });

  it("fsyncs once per append", async () => {
    const probeDir = mkdtempSync(join(tmpdir(), "verax-sync-probe-"));
    const probe = join(probeDir, "p");
    writeFileSync(probe, "");
    const probeFh = await fsp.open(probe, "r");
    const proto = Object.getPrototypeOf(probeFh) as HandleSync;
    await probeFh.close();
    let syncs = 0;
    const origSync = proto.sync;
    proto.sync = async function syncWrapped(this: unknown, ...args: unknown[]) {
      syncs += 1;
      return origSync.apply(this, args);
    };
    const dir = mkdtempSync(join(tmpdir(), "verax-fsync-"));
    const ledger = new FileLedger(dir);
    try {
      await ledger.appendDecision(cheapRecord(0, null));
      await ledger.appendDecision(cheapRecord(1, "aa".repeat(32)));
      await ledger.appendEffect(
        {
          ref: "e1",
          effectHash: "22".repeat(32),
          effectClass: "memory.get",
          timestampMs: 1,
        },
        "self",
        "33".repeat(32),
      );
      assert.equal(syncs, 3, `fsync count ${syncs} (want 1 per append)`);
    } finally {
      proto.sync = origSync;
      ledger.close();
    }
  });

  it("a deny proxy call fsyncs the inputs document and the decision", async () => {
    const probeDir = mkdtempSync(join(tmpdir(), "verax-inputs-sync-probe-"));
    const probe = join(probeDir, "p");
    writeFileSync(probe, "");
    const probeFh = await fsp.open(probe, "r");
    const proto = Object.getPrototypeOf(probeFh) as HandleSync;
    await probeFh.close();
    let syncs = 0;
    const origSync = proto.sync;
    proto.sync = async function syncWrapped(this: unknown, ...args: unknown[]) {
      syncs += 1;
      return origSync.apply(this, args);
    };
    const dir = mkdtempSync(join(tmpdir(), "verax-inputs-fsync-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["deny-fsync-1"]),
        inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
      });
      await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
      assert.equal(syncs, 2, `fsync count ${syncs} (want inputs + decision)`);
    } finally {
      proto.sync = origSync;
      ledger.close();
    }
  });
});

/**
 * Time one approve against a ledger that already holds `fill` decisions, and
 * count how often it rereads inputs.jsonl.
 */
async function measureApprove(fill: number): Promise<{
  approveMs: number;
  approveReads: number;
  approveDecisionReads: number;
  explainMs: number;
  explainReads: number;
}> {
  const dir = mkdtempSync(join(tmpdir(), "verax-resolve-cost-"));
  const ledger = new FileLedger(dir);
  const approvePolicy = loadPolicy({
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
      { id: "get", tool: "memory.get", requires: ["verax:read"], text: "Reads need the read scope." },
    ],
  });
  const principal = { brain: "brain-1", scopes: new Set(["verax:memory", "verax:read"]) };
  let n = 0;
  const proxy = createProxy({
    policy: approvePolicy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(1_000, 10),
    nonce: () => `g${++n}`,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  try {
    for (let i = 0; i < fill; i += 1) {
      await proxy.call({ name: "memory.get", arguments: { id: `k${i}` } }, principal);
    }
    await proxy.call(
      {
        name: "memory.put",
        arguments: { id: "n5", body: "hello", source: { kind: "t" }, validUntilMs: 9_999, _ref: "r5" },
      },
      principal,
    );
    const origRead = ledgerFs.readFile.bind(ledgerFs);
    let inputReads = 0;
    let decisionReads = 0;
    ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
      const name = String(path);
      if (name.endsWith("inputs.jsonl")) inputReads += 1;
      if (name.endsWith("decisions.jsonl")) decisionReads += 1;
      return origRead(path, ...(rest as []));
    }) as typeof ledgerFs.readFile;
    try {
      inputReads = 0;
      let t0 = performance.now();
      await explain(ledger, "r5");
      const explainMs = performance.now() - t0;
      const explainReads = inputReads;
      inputReads = 0;
      decisionReads = 0;
      t0 = performance.now();
      const approved = await approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: tickingNow(10_000, 10),
        nonce: queuedNonce(["a5"]),
        ref: "r5",
        approverId: "op",
        policyHash: (await ledger.decisions()).find((d) => d.claims.ref === "r5")!.claims.policyHash,
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
      });
      const approveMs = performance.now() - t0;
      assert.equal(approved.ok, true);
      return { approveMs, approveReads: inputReads, approveDecisionReads: decisionReads, explainMs, explainReads };
    } finally {
      ledgerFs.readFile = origRead;
    }
  } finally {
    ledger.close();
  }
}

describe("S1F resolvedBy cost", () => {
  it("approve stays O(1) on inputs.jsonl after 600 decisions", async () => {
    // Two things are measured here, and only one of them used to be true.
    //
    // The claim is that approve does not grow with the ledger. What proves it
    // is the reread count: one read of inputs.jsonl whether the ledger holds
    // 60 decisions or 600. That assertion has never failed.
    //
    // The wall clock is not evidence of the claim, it is evidence about the
    // machine. A fixed `approveMs < 200` ceiling failed on a hosted Windows
    // runner at 294 ms on 10 Sep 2026 while the same tree passed minutes
    // earlier, and locally the same call measured 6, 21, 22, 23, 37 and 63 ms
    // - a tenfold spread on an idle laptop. Raising the ceiling would only
    // raise the stake on the same bet.
    //
    // Comparing time against time on the same machine was tried next and is
    // not good enough either. Mutating approve to walk the whole decision log
    // twice moved the ratio from 1.7 to 2.75 and to 3.01 - inside any budget
    // loose enough not to fire on noise, and three clean runs of this suite
    // produced 1.53, 4.26 and 4.14 with no mutation at all.
    //
    // What does hold is counting. The two numbers below are integers the
    // filesystem hands us: they do not move with the machine, and the same
    // mutation took them from 1 to 3 at once. The timings are still printed,
    // because a human reading a build log can use them; nothing is asserted
    // about them, because nothing true can be.
    const small = await measureApprove(60);
    const large = await measureApprove(600);
    console.log(
      `resolve-cost explain=${large.explainMs.toFixed(0)}ms reads=${large.explainReads}` +
        ` approve=${large.approveMs.toFixed(0)}ms reads=${large.approveReads}` +
        ` approve@60=${small.approveMs.toFixed(0)}ms ratio=${(large.approveMs / Math.max(small.approveMs, 1)).toFixed(2)}` +
        ` decisionReads=${small.approveDecisionReads}/${large.approveDecisionReads}`,
    );
    assert.ok(large.explainReads < 5, `explain(pending defer) reread inputs.jsonl ${large.explainReads} times`);
    assert.ok(small.approveReads < 5, `approve at 60 reread inputs.jsonl ${small.approveReads} times`);
    assert.ok(large.approveReads < 5, `approve at 600 reread inputs.jsonl ${large.approveReads} times`);
    // approve resolves a defer by ref: it opens the decision log once. The
    // mutation that the clock could not see moved this from 1 to 3, and would
    // move the pair apart if a scan grew with the ledger.
    assert.equal(small.approveDecisionReads, large.approveDecisionReads,
      `approve read decisions.jsonl ${small.approveDecisionReads} times at 60 and ${large.approveDecisionReads} at 600`);
    assert.ok(large.approveDecisionReads <= 1,
      `approve read the whole decision log ${large.approveDecisionReads} times; it is meant to resolve by ref`);
  });
});

describe("S2-5 spend-reauth requestHash index", () => {
  it("reauth lookup does not reread decisions.jsonl after 600 records", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reauth-cost-"));
    const ledger = new FileLedger(dir);
    const spendPolicy = loadPolicy({
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
    });
    const payer = { brain: "brain-1", scopes: new Set(["verax:pay"]) };
    const args = { amountMinor: 125_050, currency: "TRY", payee: "true-ads", reference: "verax:d1", _ref: "p1" };
    try {
      for (let i = 0; i < 600; i += 1) {
        await ledger.appendDecisionChained((prev) => cheapRecord(i, prev));
      }
      const origEffect = ledger.appendEffect.bind(ledger);
      let skip = true;
      ledger.appendEffect = async (...args: Parameters<typeof origEffect>) => {
        if (skip) {
          skip = false;
          throw new Error("crash before effect");
        }
        return origEffect(...args);
      };
      const proxy = createProxy({
        policy: spendPolicy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(1_000, 10),
        nonce: queuedNonce(["reauth-1"]),
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call({ name: "spend", arguments: args }, payer);
      const policyHash = (await ledger.decisions()).find((d) => d.claims.ref === "p1")!.claims.policyHash;
      await assert.rejects(
        () =>
          approvePending({
            ledger,
            recordSigner: RECORD_SIGNER,
            now: tickingNow(10_000, 10),
            nonce: queuedNonce(["a1"]),
            ref: "p1",
            approverId: "op",
            policyHash,
            approvals: proxy.approvals,
            inputsLog: proxy.inputsLog,
          }),
        /crash before effect/,
      );
      const origRead = ledgerFs.readFile.bind(ledgerFs);
      let reads = 0;
      ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
        if (String(path).endsWith("decisions.jsonl")) reads += 1;
        return origRead(path, ...(rest as []));
      }) as typeof ledgerFs.readFile;
      try {
        const t0 = performance.now();
        const retry = await proxy.call({ name: "spend", arguments: args }, payer);
        const ms = performance.now() - t0;
        console.log(`reauth-after n=600 reads=${reads} ms=${ms.toFixed(1)}`);
        assert.match(retry.content[0]?.text ?? "", /denied:spend-reauth-required:reauth-1/);
        assert.equal(reads, 0, `reauth reread decisions.jsonl ${reads} times`);
      } finally {
        ledgerFs.readFile = origRead;
      }
    } finally {
      ledger.close();
    }
  });
});
