#!/usr/bin/env node
// Relative cost probe for the body's hot path. The numbers are not an absolute
// latency claim: they are compared against what this same machine measured
// before, by check-baseline.mjs, which is where the threshold lives.
//
// Why this exists. The unit suite guards approve's shape by counting file
// reads, which is a fact the filesystem hands us and does not move with the
// machine. That count cannot see a regression which burns processor time
// without touching a file - and the wall-clock assertion this replaced could
// not see one either: mutating approve to walk the whole decision log twice
// moved it from 1.7x to 2.75x the small case, inside any budget loose enough
// to survive an idle laptop's own tenfold spread.
//
// A probe that runs on its own, against a baseline recorded on the same kind
// of machine, can. Nothing here is asserted inline; check-baseline.mjs decides.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { approvePending } from "../src/approvals.ts";
import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "../tests/helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const gha = Boolean(process.env.GITHUB_ACTIONS);

/** Decisions already in the ledger when the timed work starts. */
const FILL = Number(process.env.VERAX_PROXY_PERF_FILL ?? 600);
/** Timed iterations. check-baseline wants at least 30 locally, 10 on a runner. */
const ROUNDS = Number(process.env.VERAX_PROXY_PERF_ROUNDS ?? 300);
/** Discarded before timing: the first calls pay for lazily built caches. */
const WARMUP = Number(process.env.VERAX_PROXY_PERF_WARMUP ?? 30);

function envTag(): string {
  return gha ? `gha-${process.env.RUNNER_OS ?? "unknown"}` : "local";
}

function quantile(samples: number[], q: number): number {
  const sorted = [...samples].sort((a, b) => a - b);
  const at = Math.min(sorted.length - 1, Math.ceil(sorted.length * q) - 1);
  return sorted[Math.max(0, at)] ?? 0;
}

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

async function run(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "verax-proxy-perf-"));
  const ledger = new FileLedger(dir);
  const principal = { brain: "brain-1", scopes: new Set(["verax:memory", "verax:read"]) };
  let nonce = 0;
  const proxy = createProxy({
    policy: approvePolicy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(1_000, 10),
    nonce: () => `n${++nonce}`,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  try {
    for (let i = 0; i < FILL; i += 1) {
      await proxy.call({ name: "memory.get", arguments: { id: `fill${i}` } }, principal);
    }

    // Every approve needs its own pending defer, so the queue is built before
    // the clock starts: the timed section resolves, it does not also create.
    const refs: string[] = [];
    for (let i = 0; i < ROUNDS + WARMUP; i += 1) {
      const ref = `perf-put-${i}`;
      await proxy.call(
        {
          name: "memory.put",
          arguments: { id: `p${i}`, body: "hello", source: { kind: "t" }, validUntilMs: 9_999, _ref: ref },
        },
        principal,
      );
      refs.push(ref);
    }

    const decisions = await ledger.decisions();
    const policyHashOf = (ref: string) =>
      decisions.find((d) => d.claims.ref === ref)!.claims.policyHash;

    // Processor time, not wall-clock. The gap this probe exists to close is a
    // regression that burns cycles without touching a file, and wall-clock
    // here is mostly disk: measured on 11 Sep 2026 the median wall time still
    // swung 1.4x between identical runs on an idle laptop, while the same runs
    // agreed on CPU to within a few per cent. cpuUsage() does not count the
    // waiting, which is the part the machine owns rather than the code.
    const callMs: number[] = [];
    const callCpu0 = process.cpuUsage();
    let callWarmCpu = callCpu0;
    for (let i = 0; i < ROUNDS + WARMUP; i += 1) {
      const t0 = performance.now();
      await proxy.call({ name: "memory.get", arguments: { id: `timed${i}` } }, principal);
      callMs.push(performance.now() - t0);
      if (i === WARMUP - 1) callWarmCpu = process.cpuUsage();
    }
    const callCpu = process.cpuUsage(callWarmCpu);

    const approveMs: number[] = [];
    const approveCpu0 = process.cpuUsage();
    let approveWarmCpu = approveCpu0;
    for (let i = 0; i < refs.length; i += 1) {
      const ref = refs[i]!;
      const t0 = performance.now();
      const out = await approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: tickingNow(10_000 + i * 1_000, 10),
        nonce: queuedNonce([`a${i}`]),
        ref,
        approverId: "op",
        policyHash: policyHashOf(ref),
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
      });
      approveMs.push(performance.now() - t0);
      if (!out.ok) throw new Error(`approve-failed:${ref}`);
      if (i === WARMUP - 1) approveWarmCpu = process.cpuUsage();
    }
    const approveCpu = process.cpuUsage(approveWarmCpu);

    const at = new Date().toISOString();
    for (const [name, samples, cpu] of [
      ["call", callMs, callCpu],
      ["approve", approveMs, approveCpu],
    ] as const) {
      // The warm-up rounds are dropped, not measured: the first calls pay for
      // caches the rest of the run inherits.
      const timed = samples.slice(WARMUP);
      // The median, not the 95th percentile. Measured on 11 Sep 2026, p95 over
      // 50 rounds swung 3.3x between identical runs on an idle laptop - it was
      // reporting the machine's worst moment, and a threshold over that can
      // only be loose enough to miss a real regression.
      const body = {
        key: `${process.platform}/${envTag()}/${name}@${FILL}`,
        // check-baseline reads `frames`; here a frame is one timed operation.
        frames: timed.length,
        stat: "user-cpu-us-per-op",
        // Microseconds of user processor time per operation. Kernel time is
        // reported beside it but not compared: it is the disk's share, and it
        // moves with the machine rather than with the code.
        value: Math.round(cpu.user / Math.max(1, timed.length)),
        systemUs: Math.round(cpu.system / Math.max(1, timed.length)),
        medianMs: Number(quantile(timed, 0.5).toFixed(3)),
        p95: quantile(timed, 0.95),
        at,
      };
      const out = join(here, `last-${name}.json`);
      writeFileSync(out, `${JSON.stringify(body, null, 2)}\n`, "utf8");
      process.stdout.write(`${JSON.stringify(body)}\n`);
    }
  } finally {
    ledger.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

await run();
