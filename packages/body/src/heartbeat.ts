import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { FileLedger } from "@verax-ai/proxy";
import { readHeartbeat } from "./health-extras.ts";

export type StartRow = {
  action: "start";
  atMs: number;
  prevBeatAtMs: number | null;
  gapMs: number | null;
  pid: number;
};

export function heartbeatEveryMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.VERAX_HEARTBEAT_EVERY_MS ?? "10000");
  return Number.isFinite(n) && n > 0 ? Math.min(2_147_483_647, Math.max(1000, Math.floor(n))) : 10_000;
}

/** Separate from halt history: starts are unsigned observations, not controls. */
export function recordBodyStart(stateDir: string, atMs: number): void {
  const prevBeatAtMs = readHeartbeat(stateDir)?.atMs ?? null;
  const row: StartRow = { action: "start", atMs, prevBeatAtMs, gapMs: prevBeatAtMs === null ? null : atMs - prevBeatAtMs, pid: process.pid };
  appendFileSync(join(stateDir, "starts.jsonl"), `${JSON.stringify(row)}\n`, { encoding: "utf8", mode: 0o600 });
}

export function startHeartbeat(ledger: FileLedger): () => void {
  ledger.pulseHeartbeat("timer");
  const timer = setInterval(() => {
    try {
      ledger.pulseHeartbeat("timer");
    } catch {
      // A failed write must leave the old timestamp for the watcher to detect.
      process.stderr.write("verax-heartbeat: pulse could not be written\n");
    }
  }, heartbeatEveryMs());
  timer.unref();
  return () => clearInterval(timer);
}

export type StartSummary = {
  count: number;
  largestGapMs: number | null;
  missingPreviousBeat: number[];
  unsigned: true;
  warnings: string[];
};

export function readStartSummary(stateDir: string): StartSummary {
  const result: StartSummary = { count: 0, largestGapMs: null, missingPreviousBeat: [], unsigned: true, warnings: [] };
  let raw: string;
  try {
    raw = readFileSync(join(stateDir, "starts.jsonl"), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") result.warnings.push("starts.jsonl could not be read");
    return result;
  }
  for (const [i, line] of raw.split("\n").entries()) {
    if (line.trim() === "") continue;
    try {
      const row = JSON.parse(line) as StartRow;
      if (!row || row.action !== "start" || !Number.isFinite(row.atMs) || !Number.isInteger(row.pid)
        || !(row.prevBeatAtMs === null || Number.isFinite(row.prevBeatAtMs))
        || !(row.gapMs === null || Number.isFinite(row.gapMs))
        || (row.prevBeatAtMs === null) !== (row.gapMs === null)) throw new Error("start row shape");
      result.count += 1;
      if (row.prevBeatAtMs === null) result.missingPreviousBeat.push(row.atMs);
      if (row.gapMs !== null) result.largestGapMs = result.largestGapMs === null ? row.gapMs : Math.max(result.largestGapMs, row.gapMs);
    } catch {
      result.warnings.push(`starts.jsonl line ${i + 1} is unreadable`);
    }
  }
  return result;
}

export function renderStarts(summary: StartSummary): string {
  return `starts        ${summary.count}; largest gap ${summary.largestGapMs === null ? "none" : `${summary.largestGapMs} ms`}; previous beat missing at ${summary.missingPreviousBeat.join(", ") || "none"}; unsigned (not verified)`
    + summary.warnings.map((warning) => `\nwarning       ${warning}`).join("");
}
