import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { FileLedger, RecordSigner } from "@verax-ai/proxy";
import { canonical } from "@cedulon/core";
import { readHeartbeat } from "./health-extras.ts";

/** v1 rows carry no `v` and no signature. */
export type StartRow = {
  action: "start";
  atMs: number;
  prevBeatAtMs: number | null;
  gapMs: number | null;
  pid: number;
};

/**
 * A v2 row is signed by the record key over its canonical form without
 * `sig`, under a domain tag, and names the SHA-256 of the line before it, so
 * a row changed or removed from the middle is named by `verify`. A row
 * removed from the end leaves nothing to compare.
 */
export type SignedStartRow = StartRow & { v: 2; prevStartHash: string | null; sig: string };

const START_DOMAIN = "verax-start-v2\n";

function startSigningBytes(row: Omit<SignedStartRow, "sig">): Buffer {
  return Buffer.from(START_DOMAIN + canonical(row), "utf8");
}

function lineHash(line: string): string {
  return createHash("sha256").update(line, "utf8").digest("hex");
}

function lastLine(path: string): string | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  return lines.length === 0 ? null : lines[lines.length - 1]!;
}

export function heartbeatEveryMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.VERAX_HEARTBEAT_EVERY_MS ?? "10000");
  return Number.isFinite(n) && n > 0 ? Math.min(2_147_483_647, Math.max(1000, Math.floor(n))) : 10_000;
}

/**
 * Separate from halt history: a start is an observation, not a control.
 * With a signer the row is v2 and signed by the record key; without one it
 * stays an unsigned v1 row.
 */
export function recordBodyStart(stateDir: string, atMs: number, signer?: RecordSigner): void {
  const path = join(stateDir, "starts.jsonl");
  const prevBeatAtMs = readHeartbeat(stateDir)?.atMs ?? null;
  const base: StartRow = {
    action: "start",
    atMs,
    prevBeatAtMs,
    gapMs: prevBeatAtMs === null ? null : atMs - prevBeatAtMs,
    pid: process.pid,
  };
  let row: StartRow | SignedStartRow = base;
  if (signer) {
    const prev = lastLine(path);
    const unsigned = { v: 2 as const, ...base, prevStartHash: prev === null ? null : lineHash(prev) };
    const sig = sign(null, startSigningBytes(unsigned), createPrivateKey(signer.privateKeyPem)).toString("base64");
    row = { ...unsigned, sig };
  }
  appendFileSync(path, `${JSON.stringify(row)}\n`, { encoding: "utf8", mode: 0o600 });
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
  /** True when any row is unsigned (v1). */
  unsigned: boolean;
  /** v2 rows, and how many of them verified under `startKey`. */
  signed: number;
  signedVerified: number;
  /** Where the key the signed rows were checked under came from. */
  startKey: "pinned" | "in-ledger" | "none";
  /** Problems that make the ledger not verify: a bad signature, a broken chain, an unsigned row after a signed one. */
  problems: string[];
  warnings: string[];
};

function isStartRow(row: StartRow): boolean {
  return (
    !!row &&
    row.action === "start" &&
    Number.isFinite(row.atMs) &&
    Number.isInteger(row.pid) &&
    (row.prevBeatAtMs === null || Number.isFinite(row.prevBeatAtMs)) &&
    (row.gapMs === null || Number.isFinite(row.gapMs)) &&
    (row.prevBeatAtMs === null) === (row.gapMs === null)
  );
}

function signedVerifies(row: SignedStartRow, publicKeyPem: string): boolean {
  try {
    const { sig, ...rest } = row;
    return verify(null, startSigningBytes(rest), createPublicKey(publicKeyPem), Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

/**
 * `publicKeyPem` is the record key the reader trusts: the one they pinned or
 * the one the records carry. Without it signed rows are counted and not
 * checked, the same as other signatures with no key.
 */
export function readStartSummary(
  stateDir: string,
  publicKeyPem: string | null = null,
  keySource: "pinned" | "in-ledger" | "none" = publicKeyPem ? "in-ledger" : "none",
): StartSummary {
  const result: StartSummary = {
    count: 0,
    largestGapMs: null,
    missingPreviousBeat: [],
    unsigned: false,
    signed: 0,
    signedVerified: 0,
    startKey: publicKeyPem ? keySource : "none",
    problems: [],
    warnings: [],
  };
  let raw: string;
  try {
    raw = readFileSync(join(stateDir, "starts.jsonl"), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") result.warnings.push("starts.jsonl could not be read");
    return result;
  }
  let prevLine: string | null = null;
  let seenSigned = false;
  for (const [i, line] of raw.split("\n").entries()) {
    if (line.trim() === "") continue;
    const n = i + 1;
    let row: StartRow | SignedStartRow;
    try {
      row = JSON.parse(line) as StartRow | SignedStartRow;
      if (!isStartRow(row)) throw new Error("start row shape");
    } catch {
      result.warnings.push(`starts.jsonl line ${n} is unreadable`);
      if (seenSigned) result.problems.push(`starts.jsonl line ${n} is unreadable after a signed start`);
      prevLine = line;
      continue;
    }
    result.count += 1;
    if (row.prevBeatAtMs === null) result.missingPreviousBeat.push(row.atMs);
    if (row.gapMs !== null) {
      result.largestGapMs = result.largestGapMs === null ? row.gapMs : Math.max(result.largestGapMs, row.gapMs);
    }
    if ((row as SignedStartRow).v === 2) {
      const signed = row as SignedStartRow;
      seenSigned = true;
      result.signed += 1;
      const expected = prevLine === null ? null : lineHash(prevLine);
      if (signed.prevStartHash !== expected) {
        result.problems.push(`start chain breaks at starts.jsonl line ${n}: the row before it is not the one it names`);
      }
      if (typeof signed.sig !== "string" || signed.sig === "") {
        result.problems.push(`start row at starts.jsonl line ${n} is v2 with no signature`);
      } else if (publicKeyPem) {
        if (signedVerifies(signed, publicKeyPem)) result.signedVerified += 1;
        else result.problems.push(`start signature does not verify: starts.jsonl line ${n}`);
      }
    } else {
      result.unsigned = true;
      if (seenSigned) result.problems.push(`unsigned start row after a signed one: starts.jsonl line ${n}`);
    }
    prevLine = line;
  }
  return result;
}

export function renderStarts(summary: StartSummary): string {
  const signedPart =
    summary.signed === 0
      ? "unsigned (not verified)"
      : summary.startKey === "none"
        ? `${summary.signed} signed, not checked (no record key)${summary.unsigned ? "; older rows unsigned" : ""}`
        : `${summary.signedVerified} of ${summary.signed} signed verify under the ${summary.startKey === "pinned" ? "pinned" : "in-ledger"} record key${summary.unsigned ? "; older rows unsigned" : ""}`;
  return `starts        ${summary.count}; largest gap ${summary.largestGapMs === null ? "none" : `${summary.largestGapMs} ms`}; previous beat missing at ${summary.missingPreviousBeat.join(", ") || "none"}; ${signedPart}`
    + summary.problems.map((p) => `\nproblem       ${p}`).join("")
    + summary.warnings.map((warning) => `\nwarning       ${warning}`).join("");
}
