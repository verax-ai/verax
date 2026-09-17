#!/usr/bin/env node
// Times GET /api/agents on a ledger that ledger-scale.ts built: the last day
// (what the panel asks every poll) and the whole ledger (the worst window).
//
// VERAX_SCALE_N, VERAX_SCALE_DIR, VERAX_SCALE_OUT as in ledger-scale.ts.

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { bootBody, rssMb } from "./boot.ts";

const N = Number(process.env.VERAX_SCALE_N ?? "10000");
const dir = process.env.VERAX_SCALE_DIR ?? join(tmpdir(), `verax-scale-${N}`);
const outDir = process.env.VERAX_SCALE_OUT ?? dir;
const ROUNDS = Number(process.env.VERAX_SCALE_ROUNDS ?? "5");
const ISSUER_PORT = Number(process.env.VERAX_SCALE_ISSUER_PORT ?? "8796");
const BODY_PORT = Number(process.env.VERAX_SCALE_BODY_PORT ?? "8797");

const log = (s: string) => process.stderr.write(`agents-scale: ${s}\n`);

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? 0 : s[Math.floor((s.length - 1) / 2)]!;
}

async function timed(url: string, token: string): Promise<{ ms: number; bytes: number; agents: number | null; status: number }> {
  const t0 = performance.now();
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  const buf = Buffer.from(await res.arrayBuffer());
  const ms = performance.now() - t0;
  let agents: number | null = null;
  try {
    const doc = JSON.parse(buf.toString("utf8")) as { agents?: unknown[] };
    agents = Array.isArray(doc.agents) ? doc.agents.length : null;
  } catch {
    agents = null;
  }
  return { ms, bytes: buf.length, agents, status: res.status };
}

async function run(): Promise<void> {
  if (!existsSync(join(dir, "decisions.jsonl"))) throw new Error(`no ledger in ${dir}; run ledger-scale.ts first`);
  const booted = await bootBody({
    stateDir: dir,
    policyFile: join(dir, "policy.json"),
    issuerPort: ISSUER_PORT,
    bodyPort: BODY_PORT,
    redirectUris: ["http://127.0.0.1:8791/callback"],
    quiet: true,
  });
  try {
    const token = await booted.mintToken();
    const day: number[] = [];
    let dayShape = { bytes: 0, agents: null as number | null, status: 0 };
    for (let i = 0; i < ROUNDS; i += 1) {
      const r = await timed(`${booted.bodyUrl}/api/agents`, token);
      day.push(r.ms);
      dayShape = { bytes: r.bytes, agents: r.agents, status: r.status };
      log(`day #${i + 1}: ${Math.round(r.ms)} ms, ${r.bytes} B, ${r.agents} agents, http ${r.status}`);
    }
    const all: number[] = [];
    let allShape = { bytes: 0, agents: null as number | null, status: 0 };
    for (let i = 0; i < Math.min(ROUNDS, 3); i += 1) {
      const r = await timed(`${booted.bodyUrl}/api/agents?from=0&to=9999999999999`, token);
      all.push(r.ms);
      allShape = { bytes: r.bytes, agents: r.agents, status: r.status };
      log(`all #${i + 1}: ${Math.round(r.ms)} ms, ${r.bytes} B, ${r.agents} agents, http ${r.status}`);
    }
    const result = {
      probe: "agents-scale",
      at: new Date().toISOString(),
      n: N,
      body: { startMs: booted.bodyStartMs, rssMb: rssMb(booted.bodyPid) },
      lastDay: { medianMs: Math.round(median(day)), maxMs: Math.round(Math.max(...day)), ...dayShape },
      whole: { medianMs: Math.round(median(all)), maxMs: Math.round(Math.max(...all)), ...allShape },
    };
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `last-agents-${N}.json`), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    booted.stop();
  }
}

await run();
