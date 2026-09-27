#!/usr/bin/env node
// Scale probe for the ledger read path. Builds a ledger of N decisions through
// the real proxy and the real FileLedger (signed records, chained hashes,
// inputs log, evidence copy), then starts the body on it and times what the
// panel asks for: /healthz and GET /api/ledger, whole ledger and a 24-hour
// window. Nothing here is asserted; the numbers go to a JSON file for the
// plan to quote.
//
// Generation skips fsync on append (the I/O seam in ledger.ts) so a 100k
// ledger takes minutes, not hours. The write cost per decision is measured
// elsewhere (packages/proxy/perf); this probe is about reading.
//
// VERAX_SCALE_N        decisions to generate (default 10000)
// VERAX_SCALE_AGENTS   distinct agent subjects (default 150)
// VERAX_SCALE_DIR      state directory (default <tmp>/verax-scale-<N>)
// VERAX_SCALE_REUSE=1  reuse an existing ledger in that directory
// VERAX_SCALE_ROUNDS   timed requests per endpoint (default 5)
// VERAX_SCALE_OUT      directory for last-scale-<N>.json (default the state dir)
// VERAX_SCALE_PIECE_ROWS  rows per ledger piece while generating (default: the
//                      ledger's own bound); a value above N keeps one piece

import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { loadOrCreateSigners } from "../src/keys.ts";
import { FileLedger, ledgerFs } from "../../proxy/src/ledger.ts";
import { readLedgerManifest } from "../../proxy/src/ledger-manifest.ts";
import { loadPolicy } from "../../proxy/src/policy.ts";
import { createProxy } from "../../proxy/src/proxy.ts";
import type { Principal } from "../../proxy/src/types.ts";
import { bootBody, rssMb } from "./boot.ts";

const N = Number(process.env.VERAX_SCALE_N ?? "10000");
const AGENTS = Number(process.env.VERAX_SCALE_AGENTS ?? "150");
const ROUNDS = Number(process.env.VERAX_SCALE_ROUNDS ?? "5");
const PIECE_ROWS = process.env.VERAX_SCALE_PIECE_ROWS ? Number(process.env.VERAX_SCALE_PIECE_ROWS) : undefined;
const DAYS = 30;
const dir = process.env.VERAX_SCALE_DIR ?? join(tmpdir(), `verax-scale-${N}`);
const outDir = process.env.VERAX_SCALE_OUT ?? dir;
const reuse = process.env.VERAX_SCALE_REUSE === "1" && existsSync(join(dir, "decisions.jsonl"));
// Not 8787: a live body on the same machine normally listens there.
const ISSUER_PORT = Number(process.env.VERAX_SCALE_ISSUER_PORT ?? "8796");
const BODY_PORT = Number(process.env.VERAX_SCALE_BODY_PORT ?? "8797");

// The same document the body loads, so the records' policyHash matches.
export const POLICY = {
  version: 1,
  default: "deny",
  egress: ["example.com"],
  rules: [
    { id: "memory-get", tool: "memory.get", requires: ["verax:read"], text: "Reading memory needs the read scope." },
    { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope." },
  ],
};

const log = (s: string) => process.stderr.write(`ledger-scale: ${s}\n`);

function sizeOf(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}

function dirBytes(path: string): number {
  if (!existsSync(path)) return 0;
  let total = 0;
  for (const name of readdirSync(path)) {
    const p = join(path, name);
    const st = statSync(p);
    total += st.isDirectory() ? dirBytes(p) : st.size;
  }
  return total;
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? 0 : s[Math.floor((s.length - 1) / 2)]!;
}

async function generate(): Promise<{ genMs: number; perDecisionMs: number }> {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, "policy.json"), `${JSON.stringify(POLICY, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  const { recordSigner, effectSigner } = loadOrCreateSigners(dir);

  // No fsync while generating: same bytes, same code, minus the disk wait.
  const realOpen = ledgerFs.open;
  ledgerFs.open = (async (path: string, flags: string) => {
    const fh = await open(path, flags);
    return {
      write: (data: string) => fh.write(data),
      sync: async () => undefined,
      close: () => fh.close(),
    };
  }) as unknown as typeof open;

  const ledger = new FileLedger(dir, PIECE_ROWS ? { pieceMaxRows: PIECE_ROWS } : undefined);
  ledger.effectSigner = effectSigner;
  const policy = loadPolicy(POLICY);
  const startMs = Date.now() - DAYS * 86_400_000;
  const stepMs = (DAYS * 86_400_000) / N;
  let vnow = startMs;
  let n = 0;
  const proxy = createProxy({
    policy,
    recordSigner,
    effectSigner,
    ledger,
    now: () => vnow,
    nonce: () => `s${++n}`,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  const full = new Set(["verax:read", "verax:memory"]);
  const readOnly = new Set(["verax:read"]);
  const t0 = performance.now();
  let lastPct = -1;
  try {
    for (let i = 0; i < N; i += 1) {
      vnow = Math.floor(startMs + i * stepMs);
      const agent = `agent-${i % AGENTS}`;
      // 1 in 20 is a denied write from a read-only agent; 1 in 10 a write; the rest reads.
      const deny = i % 20 === 19;
      const put = !deny && i % 10 === 0;
      const principal: Principal = { brain: agent, scopes: deny ? readOnly : full, iss: "https://issuer.example" };
      if (put || deny) {
        await proxy.call(
          {
            name: "memory.put",
            arguments: { id: `k${i}`, body: `note ${i}`, source: { kind: "probe" }, validUntilMs: vnow + 86_400_000 },
          },
          principal,
        );
      } else {
        await proxy.call({ name: "memory.get", arguments: { id: `k${i}` } }, principal);
      }
      const pct = Math.floor(((i + 1) * 10) / N);
      if (pct !== lastPct) {
        lastPct = pct;
        log(`generated ${i + 1}/${N} (${Math.round(performance.now() - t0)} ms)`);
      }
    }
  } finally {
    ledger.close();
    ledgerFs.open = realOpen;
  }
  const genMs = Math.round(performance.now() - t0);
  return { genMs, perDecisionMs: Number((genMs / N).toFixed(3)) };
}

type Timed = {
  ttfbMs: number;
  totalMs: number;
  bytes: number;
  parseMs: number | null;
  decisions: number | null;
  piecesTouched: string[] | null;
  error?: string;
};

async function timed(url: string, token: string): Promise<Timed> {
  const t0 = performance.now();
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  const ttfbMs = performance.now() - t0;
  const buf = Buffer.from(await res.arrayBuffer());
  const totalMs = performance.now() - t0;
  if (res.status !== 200) {
    return { ttfbMs, totalMs, bytes: buf.length, parseMs: null, decisions: null, piecesTouched: null, error: "http " + res.status };
  }
  let parseMs: number | null = null;
  let decisions: number | null = null;
  let piecesTouched: string[] | null = null;
  try {
    const p0 = performance.now();
    const doc = JSON.parse(buf.toString("utf8")) as { decisions?: unknown[]; piecesTouched?: unknown };
    parseMs = performance.now() - p0;
    decisions = Array.isArray(doc.decisions) ? doc.decisions.length : null;
    piecesTouched = Array.isArray(doc.piecesTouched) ? doc.piecesTouched.map((x) => String(x)) : null;
  } catch (err) {
    return { ttfbMs, totalMs, bytes: buf.length, parseMs: null, decisions: null, piecesTouched: null, error: "parse: " + (err as Error).message };
  }
  return { ttfbMs, totalMs, bytes: buf.length, parseMs, decisions, piecesTouched };
}

function summarize(rows: Timed[]) {
  const ok = rows.filter((r) => !r.error);
  return {
    rounds: rows.length,
    ok: ok.length,
    error: rows.find((r) => r.error)?.error ?? null,
    ttfbMedianMs: Math.round(median(ok.map((r) => r.ttfbMs))),
    totalMedianMs: Math.round(median(ok.map((r) => r.totalMs))),
    totalMaxMs: Math.round(Math.max(0, ...ok.map((r) => r.totalMs))),
    bytes: ok[0]?.bytes ?? rows[0]?.bytes ?? 0,
    parseMedianMs: Math.round(median(ok.map((r) => r.parseMs ?? 0))),
    decisions: ok[0]?.decisions ?? null,
    piecesTouched: ok[0]?.piecesTouched ?? null,
  };
}

async function run(): Promise<void> {
  let gen: { genMs: number; perDecisionMs: number } | null = null;
  if (reuse) {
    log(`reusing ledger in ${dir}`);
  } else {
    log(`generating ${N} decisions in ${dir}`);
    gen = await generate();
    log(`generated in ${gen.genMs} ms (${gen.perDecisionMs} ms/decision, no fsync)`);
  }
  const files = {
    decisionsBytes: sizeOf(join(dir, "decisions.jsonl")),
    effectsBytes: sizeOf(join(dir, "effects.jsonl")),
    inputsBytes: sizeOf(join(dir, "inputs.jsonl")),
    evidenceCopyBytes: dirBytes(join(dir, "evidence-copy")),
    indexBytes: sizeOf(join(dir, "index.jsonl")),
    piecesBytes: dirBytes(join(dir, "pieces")),
    stateDirBytes: dirBytes(dir),
  };
  const decisionsCount = N;

  log("starting issuer + body");
  const booted = await bootBody({
    stateDir: dir,
    policyFile: join(dir, "policy.json"),
    issuerPort: ISSUER_PORT,
    bodyPort: BODY_PORT,
    redirectUris: ["http://127.0.0.1:8791/callback"],
    quiet: true,
  });
  try {
    log(`body up in ${booted.bodyStartMs} ms; rss ${rssMb(booted.bodyPid)} MB`);
    const rssAfterStartMb = rssMb(booted.bodyPid);
    const token = await booted.mintAuditToken();
    const health: number[] = [];
    let healthDoc: unknown = null;
    for (let i = 0; i < ROUNDS; i += 1) {
      const t0 = performance.now();
      const r = await fetch(booted.bodyUrl + "/healthz", { headers: { authorization: "Bearer " + token } });
      const text = Buffer.from(await r.arrayBuffer()).toString("utf8");
      health.push(performance.now() - t0);
      if (healthDoc === null) {
        try {
          healthDoc = JSON.parse(text);
        } catch {
          healthDoc = text;
        }
      }
    }
    const all: Timed[] = [];
    for (let i = 0; i < ROUNDS; i += 1) {
      all.push(await timed(`${booted.bodyUrl}/api/ledger?from=0&to=9999999999999&limit=5000`, token));
      log(`all #${i + 1}: ${Math.round(all[i]!.totalMs)} ms, ${all[i]!.bytes} B${all[i]!.error ? ` (${all[i]!.error})` : ""}`);
    }
    const rssAfterAllMb = rssMb(booted.bodyPid);
    const from = Date.now() - 86_400_000;
    const day: Timed[] = [];
    for (let i = 0; i < ROUNDS; i += 1) {
      day.push(await timed(`${booted.bodyUrl}/api/ledger?from=${from}&to=9999999999999`, token));
      log(`24h #${i + 1}: ${Math.round(day[i]!.totalMs)} ms, ${day[i]!.bytes} B${day[i]!.error ? ` (${day[i]!.error})` : ""}`);
    }
    const last200: Timed[] = [];
    for (let i = 0; i < ROUNDS; i += 1) {
      last200.push(await timed(`${booted.bodyUrl}/api/ledger?from=0&to=9999999999999&limit=200`, token));
      log(`last200 #${i + 1}: ${Math.round(last200[i]!.totalMs)} ms, ${last200[i]!.bytes} B${last200[i]!.error ? ` (${last200[i]!.error})` : ""}`);
    }
    // F8: a 24-hour window centred on the first close, so one read crosses
    // from a closed piece into the next. Skipped when nothing has closed.
    const manifest = readLedgerManifest(dir);
    const pieces = (manifest?.pieces ?? []).map((p) => ({ id: p.id, closed: p.closed, n: p.n, firstMs: p.firstMs, lastMs: p.lastMs }));
    const firstClosed = pieces.find((p) => p.closed && p.lastMs !== null);
    const cross: Timed[] = [];
    let crossWindow: { from: number; to: number } | null = null;
    if (firstClosed && firstClosed.lastMs !== null) {
      crossWindow = { from: firstClosed.lastMs - 43_200_000, to: firstClosed.lastMs + 43_200_000 };
      for (let i = 0; i < ROUNDS; i += 1) {
        cross.push(await timed(booted.bodyUrl + "/api/ledger?from=" + crossWindow.from + "&to=" + crossWindow.to, token));
        const c = cross[i]!;
        log("cross24h #" + (i + 1) + ": " + Math.round(c.totalMs) + " ms, " + c.bytes + " B, pieces " + JSON.stringify(c.piecesTouched) + (c.error ? " (" + c.error + ")" : ""));
      }
    }
    const result = {
      probe: "ledger-scale",
      pieceRows: PIECE_ROWS ?? null,
      pieces,
      healthz: healthDoc,
      ledgerLast200: summarize(last200),
      at: new Date().toISOString(),
      platform: `${process.platform}/${process.arch}/node${process.versions.node}`,
      n: decisionsCount,
      agents: AGENTS,
      spanDays: DAYS,
      stateDir: dir,
      generation: gen,
      files,
      bytesPerDecision: Math.round(files.decisionsBytes / decisionsCount),
      body: {
        startMs: booted.bodyStartMs,
        rssAfterStartMb,
        rssAfterLedgerReadsMb: rssAfterAllMb,
        healthzMedianMs: Math.round(median(health)),
      },
      ledgerAll: summarize(all),
      ledgerLast24h: summarize(day),
      ledgerCross24h: crossWindow ? { window: crossWindow, ...summarize(cross) } : null,
    };
    mkdirSync(outDir, { recursive: true });
    const outPath = join(outDir, `last-scale-${N}.json`);
    writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
    process.stdout.write(`${JSON.stringify(result)}\n`);
    log(`wrote ${outPath}`);
  } finally {
    booted.stop();
  }
}

await run();
