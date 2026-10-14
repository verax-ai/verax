import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { appendFileSync, closeSync, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { join } from "node:path";
import type { FileLedger, RecordSigner } from "@verax-ai/proxy";
import { canonical } from "@cedulon/core";
import { readHeartbeat } from "./health-extras.ts";

/** One child named on a start: the digest of its pinned manifest, or null when it has no pins. */
export type StartDownstream = { prefix: string; manifest: string | null };

/** v1 rows carry no `v` and no signature. */
export type StartRow = {
  action: "start";
  atMs: number;
  prevBeatAtMs: number | null;
  gapMs: number | null;
  pid: number;
  /**
   * Children in force at this start. Absent when the body had none, so a row
   * written before this field still verifies.
   */
  downstream?: StartDownstream[];
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

/**
 * The last line of the file that is not blank, read from the end. The file
 * gains a row on every start and is never trimmed, so reading all of it to
 * find one line grew with the body's history and, past the longest string
 * the runtime holds, stopped the start. The window doubles until it holds a
 * whole line; a file that is one long line is read whole, as before.
 */
export function lastLine(path: string, windowBytes = 64 * 1024): string | null {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  try {
    const size = fstatSync(fd).size;
    for (let window = Math.max(1, windowBytes); ; window *= 2) {
      const start = Math.max(0, size - window);
      const buf = Buffer.alloc(size - start);
      let read = 0;
      while (read < buf.length) {
        const n = readSync(fd, buf, read, buf.length - read, start + read);
        if (n === 0) break;
        read += n;
      }
      // The bytes are cut at a newline, not at a character: a window may begin
      // inside a multi-byte character, and inside a line either way.
      const firstNewline = start === 0 ? -1 : buf.indexOf(0x0a);
      if (start > 0 && firstNewline === -1) continue;
      const text = buf.subarray(firstNewline + 1, read).toString("utf8");
      const lines = text.split("\n").filter((l) => l.trim() !== "");
      if (lines.length > 0) return lines[lines.length - 1]!;
      if (start === 0) return null;
    }
  } finally {
    closeSync(fd);
  }
}

export function heartbeatEveryMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.VERAX_HEARTBEAT_EVERY_MS ?? "10000");
  return Number.isFinite(n) && n > 0 ? Math.min(2_147_483_647, Math.max(1000, Math.floor(n))) : 10_000;
}

/**
 * Separate from halt history: a start is an observation, not a control.
 * With a signer the row is v2 and signed by the record key; without one it
 * stays an unsigned v1 row. A non-empty `downstream` list is part of the row
 * and of the bytes the record key signs. When it is absent the field is not
 * written, so older v1 and v2 rows verify unchanged.
 */
export function recordBodyStart(
  stateDir: string,
  atMs: number,
  signer?: RecordSigner,
  extra?: { downstream?: StartDownstream[] },
): void {
  const path = join(stateDir, "starts.jsonl");
  const prevBeatAtMs = readHeartbeat(stateDir)?.atMs ?? null;
  const listed = extra?.downstream;
  const base: StartRow = {
    action: "start",
    atMs,
    prevBeatAtMs,
    gapMs: prevBeatAtMs === null ? null : atMs - prevBeatAtMs,
    pid: process.pid,
    ...(listed !== undefined && listed.length > 0 ? { downstream: listed } : {}),
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
  /**
   * Children recorded on each start, in the order the rows were read. A
   * start that named none is an empty list.
   */
  downstream: StartDownstream[][];
};

const MANIFEST_RE = /^[0-9a-f]{64}$/;

function isDownstreamList(value: unknown): value is StartDownstream[] {
  if (!Array.isArray(value)) return false;
  return value.every((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) return false;
    const rec = item as Record<string, unknown>;
    if (typeof rec.prefix !== "string") return false;
    return rec.manifest === null || (typeof rec.manifest === "string" && MANIFEST_RE.test(rec.manifest));
  });
}

function isStartRow(row: StartRow): boolean {
  return (
    !!row &&
    row.action === "start" &&
    Number.isFinite(row.atMs) &&
    Number.isInteger(row.pid) &&
    (row.prevBeatAtMs === null || Number.isFinite(row.prevBeatAtMs)) &&
    (row.gapMs === null || Number.isFinite(row.gapMs)) &&
    (row.prevBeatAtMs === null) === (row.gapMs === null) &&
    ((row as { downstream?: unknown }).downstream === undefined ||
      isDownstreamList((row as { downstream?: unknown }).downstream))
  );
}

function downstreamManifestProblems(stateDir: string, row: StartRow): string[] {
  if (row.downstream === undefined) return [];
  const problems: string[] = [];
  for (const entry of row.downstream) {
    if (entry.manifest === null) continue;
    const file = join(stateDir, "definitions", `${entry.manifest}.json`);
    let bytes: Buffer;
    try {
      bytes = readFileSync(file);
    } catch (err) {
      const missing = (err as NodeJS.ErrnoException).code === "ENOENT";
      problems.push(
        `${missing ? "downstream-manifest-missing" : "downstream-manifest-invalid"}:${entry.prefix}:${entry.manifest}`,
      );
      continue;
    }
    if (createHash("sha256").update(bytes).digest("hex") !== entry.manifest) {
      problems.push(`downstream-manifest-invalid:${entry.prefix}:${entry.manifest}`);
      continue;
    }
    // The digest names these bytes. They still have to be the manifest of
    // the child this row recorded, not another prefix under the same hash.
    let recorded: unknown;
    try {
      recorded = JSON.parse(bytes.toString("utf8"));
    } catch {
      problems.push(`downstream-manifest-invalid:${entry.prefix}:${entry.manifest}`);
      continue;
    }
    const recordedPrefix =
      recorded !== null && typeof recorded === "object" && !Array.isArray(recorded)
        ? (recorded as { prefix?: unknown }).prefix
        : undefined;
    if (recordedPrefix !== entry.prefix) {
      problems.push(`downstream-manifest-mismatch:${entry.prefix}:${entry.manifest}`);
    }
  }
  return problems;
}

/**
 * Whether a line carries a field only a signed start row has. A line that no
 * longer parses is read as text, so a signed row cut short is not passed as
 * one nothing can read.
 */
function claimsSigned(parsed: unknown, line = ""): boolean {
  if (parsed === undefined) return /"(?:v|sig|prevStartHash)"\s*:/.test(line);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
  const rec = parsed as Record<string, unknown>;
  return rec.v !== undefined || rec.sig !== undefined || rec.prevStartHash !== undefined;
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
  opts: { requireSigned?: boolean } = {},
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
    downstream: [],
  };
  let raw: string;
  try {
    raw = readFileSync(join(stateDir, "starts.jsonl"), "utf8");
  } catch (err) {
    // A file that is there and cannot be read has not been checked: that is a
    // problem, not a warning. Only a file that is not there is nothing.
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") result.problems.push("starts.jsonl could not be read");
    if (opts.requireSigned) result.problems.push("start-rows-missing: no start row could be read");
    return result;
  }
  let prevLine: string | null = null;
  let seenSigned = false;
  for (const [i, line] of raw.split("\n").entries()) {
    // The empty piece after the last newline. A line of spaces is not empty:
    // the body does not write one, and it is read like any other line.
    if (line === "") continue;
    const n = i + 1;
    let row: StartRow | SignedStartRow;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
      row = parsed as StartRow | SignedStartRow;
      if (!isStartRow(row)) throw new Error("start row shape");
    } catch {
      // Every line of this file is a start row the body wrote, so a line that
      // does not read as one is a problem, whatever it still looks like.
      // Naming a tampered signed row by the fields it shows is only a better
      // message: the writer of the file can always make a row show none.
      if (claimsSigned(parsed, line)) {
        seenSigned = true;
        result.signed += 1;
        result.problems.push(`signed start row is malformed: starts.jsonl line ${n}`);
      } else if (seenSigned) {
        result.problems.push(`starts.jsonl line ${n} is unreadable after a signed start`);
      } else if (opts.requireSigned) {
        result.problems.push(`start-row-unreadable: starts.jsonl line ${n}`);
      } else {
        result.problems.push(`starts.jsonl line ${n} is not a start row`);
      }
      prevLine = line;
      continue;
    }
    result.count += 1;
    result.downstream.push(row.downstream ?? []);
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
      // A signed row is accepted in one spelling, the one the body writes. A
      // second copy of a key, padding, or an escape leaves the parsed row and
      // its signature as they were and makes the line say something else to
      // another reader.
      if (JSON.stringify(parsed) !== line) {
        result.problems.push(`signed start row is not written as the body writes it: starts.jsonl line ${n}`);
      }
      if (typeof signed.sig !== "string" || signed.sig === "") {
        result.problems.push(`start row at starts.jsonl line ${n} is v2 with no signature`);
      } else if (Buffer.from(signed.sig, "base64").toString("base64") !== signed.sig) {
        // Base64 decoding skips characters outside its alphabet, so the same
        // signature has many spellings; only the one the body writes is read.
        result.problems.push(`start signature is not canonical base64: starts.jsonl line ${n}`);
      } else if (publicKeyPem) {
        if (signedVerifies(signed, publicKeyPem)) result.signedVerified += 1;
        else result.problems.push(`start signature does not verify: starts.jsonl line ${n}`);
      }
    } else if (claimsSigned(row)) {
      // A version other than 2, or a signature with no version: a row written
      // before signing carries none of these fields.
      seenSigned = true;
      result.signed += 1;
      result.problems.push(`signed start row is malformed: starts.jsonl line ${n}`);
    } else {
      result.unsigned = true;
      if (seenSigned) result.problems.push(`unsigned start row after a signed one: starts.jsonl line ${n}`);
      // A row with its signature taken off reads as one written before signing.
      // Only a reader who knows the ledger was written signed can refuse it.
      else if (opts.requireSigned) result.problems.push(`start-row-unsigned: starts.jsonl line ${n}`);
    }
    // Each named manifest must be the file under that digest. What this shows,
    // and no more: the body that held a trusted record key recorded these
    // definitions at that start. It does not prove that a person read them or
    // that the child's code behaves as described.
    result.problems.push(...downstreamManifestProblems(stateDir, row));
    prevLine = line;
  }
  if (opts.requireSigned) {
    if (result.count === 0) result.problems.push("start-rows-missing: no start row could be read");
    if (result.signed > 0 && result.startKey === "none") {
      result.problems.push("start-rows-not-checked: signed start rows need a record key");
    }
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
  const definitions = summary.downstream.flatMap((listed) =>
    listed.map(
      (entry) =>
        `downstream    ${entry.prefix} ${entry.manifest === null ? "unpinned" : `sha256:${entry.manifest}`}`,
    ),
  );
  return `starts        ${summary.count}; largest gap ${summary.largestGapMs === null ? "none" : `${summary.largestGapMs} ms`}; previous beat missing at ${summary.missingPreviousBeat.join(", ") || "none"}; ${signedPart}`
    + definitions.map((line) => `\n${line}`).join("")
    + summary.problems.map((p) => `\nproblem       ${p}`).join("")
    + summary.warnings.map((warning) => `\nwarning       ${warning}`).join("");
}
