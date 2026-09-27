import { existsSync, readFileSync } from "node:fs";
import { join, posix, relative, resolve, win32 } from "node:path";

import { writeFileAtomic } from "./atomic-write.ts";

export const LEGACY_PIECE_ID = "legacy";
export const DEFAULT_PIECE_MAX_ROWS = 50_000;
export const DEFAULT_PIECE_MAX_BYTES = 200 * 1024 * 1024;
export const MANIFEST_NAME = "ledger-manifest.json";
export const INDEX_NAME = "index.jsonl";

export type LedgerPieceRow = {
  id: string;
  decisions: string;
  effects: string;
  inputs: string;
  n: number;
  effectN: number;
  firstMs: number | null;
  lastMs: number | null;
  lastHash: string | null;
  closed: boolean;
  closedAtMs?: number;
};

export type LedgerManifest = {
  version: 1;
  pieces: LedgerPieceRow[];
  countedAtMs: number[];
};

export type LedgerIndexLine = {
  ref: string;
  tenantRef: string;
  piece: string;
  ts: number;
  kind: string;
  requestHash: string;
  resolves: string | null;
  hasEffect: boolean;
  reasonCode: string;
  subject: string;
  policyHash: string;
};

export type PieceFiles = {
  id: string;
  decisions: string;
  effects: string;
  inputs: string;
  copyDecisions: string;
  copyEffects: string;
  closed: boolean;
  firstMs: number | null;
  lastMs: number | null;
  n: number;
  effectN: number;
};

export function manifestPath(dir: string): string {
  return join(dir, MANIFEST_NAME);
}

export function indexPath(dir: string): string {
  return join(dir, INDEX_NAME);
}

export function legacyPieceRow(): LedgerPieceRow {
  return {
    id: LEGACY_PIECE_ID,
    decisions: "decisions.jsonl",
    effects: "effects.jsonl",
    inputs: "inputs.jsonl",
    n: 0,
    effectN: 0,
    firstMs: null,
    lastMs: null,
    lastHash: null,
    closed: false,
  };
}

export function newPieceRow(id: string): LedgerPieceRow {
  return {
    id,
    decisions: `pieces/${id}/decisions.jsonl`,
    effects: `pieces/${id}/effects.jsonl`,
    inputs: `pieces/${id}/inputs.jsonl`,
    n: 0,
    effectN: 0,
    firstMs: null,
    lastMs: null,
    lastHash: null,
    closed: false,
  };
}

export function copyRel(pieceId: string, name: "decisions.jsonl" | "effects.jsonl"): string {
  if (pieceId === LEGACY_PIECE_ID) return `evidence-copy/${name}`;
  return `evidence-copy/pieces/${pieceId}/${name}`;
}

export function nextPieceId(existingIds: string[], atMs: number): string {
  const d = new Date(atMs);
  const ym = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
  const letters = "abcdefghijklmnopqrstuvwxyz";
  for (let i = 0; i < letters.length; i += 1) {
    const id = `${ym}-${letters[i]!}`;
    if (!existingIds.includes(id)) return id;
  }
  let n = letters.length;
  for (;;) {
    const id = `${ym}-z${n}`;
    if (!existingIds.includes(id)) return id;
    n += 1;
  }
}

/**
 * Null only when there is no manifest (the flat legacy layout). A manifest
 * that is there but cannot be read or parsed throws: opening as a single
 * legacy piece would chain new rows onto a closed file and hide every piece
 * the manifest named.
 */
export function readLedgerManifest(dir: string): LedgerManifest | null {
  let text: string;
  try {
    text = readFileSync(manifestPath(dir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("ledger-manifest-unreadable: " + (err as Error).message);
  }
  let raw: Partial<LedgerManifest>;
  try {
    raw = JSON.parse(text) as Partial<LedgerManifest>;
  } catch (err) {
    throw new Error("ledger-manifest-corrupt: " + (err as Error).message);
  }
  if (!raw || raw.version !== 1 || !Array.isArray(raw.pieces) || raw.pieces.length === 0) {
    throw new Error("ledger-manifest-invalid: version 1 with at least one piece expected");
  }
  const pieces = raw.pieces.map(asPieceRow);
  if (pieces.some((p) => p === null)) throw new Error("ledger-manifest-invalid: piece row missing a field");
  return {
    version: 1,
    pieces: pieces as LedgerPieceRow[],
    countedAtMs: Array.isArray(raw.countedAtMs)
      ? raw.countedAtMs.filter((n): n is number => typeof n === "number")
      : [],
  };
}

function asPieceRow(raw: unknown): LedgerPieceRow | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.id !== "string" || typeof r.decisions !== "string") return null;
  if (typeof r.effects !== "string" || typeof r.inputs !== "string") return null;
  if (typeof r.n !== "number" || typeof r.effectN !== "number") return null;
  if (typeof r.closed !== "boolean") return null;
  return {
    id: r.id,
    decisions: r.decisions,
    effects: r.effects,
    inputs: r.inputs,
    n: r.n,
    effectN: r.effectN,
    firstMs: typeof r.firstMs === "number" ? r.firstMs : null,
    lastMs: typeof r.lastMs === "number" ? r.lastMs : null,
    lastHash: typeof r.lastHash === "string" ? r.lastHash : null,
    closed: r.closed,
    ...(typeof r.closedAtMs === "number" ? { closedAtMs: r.closedAtMs } : {}),
  };
}

export function writeLedgerManifest(dir: string, manifest: LedgerManifest): void {
  writeFileAtomic(manifestPath(dir), `${JSON.stringify(manifest)}\n`);
}

const PIECE_SEP = /[/\\]/;

function piecePathRefusal(rel: string): string {
  return `manifest piece path leaves the ledger directory: ${rel}`;
}

function looksUnc(rel: string): boolean {
  return rel.startsWith("\\\\") || rel.startsWith("//") || rel.startsWith("\\/") || rel.startsWith("/\\");
}

function looksDrive(rel: string): boolean {
  return /^[A-Za-z]:/.test(rel);
}

function hasDotDot(rel: string): boolean {
  return rel.split(PIECE_SEP).some((part) => part === "..");
}

/**
 * A manifest piece path is usable only when it stays inside `dir` after
 * normalization. Absolute paths, drive letters, UNC (`\\host\share`,
 * `//host/share`) and `..` are refused here, before any filesystem call.
 * Null means the path is confined; the string is the problem to report.
 */
export function ledgerPiecePathProblem(dir: string, rel: string): string | null {
  if (typeof rel !== "string" || rel === "" || rel.includes("\0")) return piecePathRefusal(String(rel));
  if (looksUnc(rel) || looksDrive(rel) || hasDotDot(rel) || win32.isAbsolute(rel) || posix.isAbsolute(rel)) {
    return piecePathRefusal(rel);
  }
  const root = resolve(dir);
  const target = resolve(dir, rel);
  const fromRoot = relative(root, target);
  if (
    fromRoot === "" ||
    win32.isAbsolute(fromRoot) ||
    posix.isAbsolute(fromRoot) ||
    fromRoot.split(PIECE_SEP).some((part) => part === "..")
  ) {
    return piecePathRefusal(rel);
  }
  return null;
}

/** Confined absolute path, or a thrown error. Does not touch the filesystem. */
export function requireLedgerPiecePath(dir: string, rel: string): string {
  const problem = ledgerPiecePathProblem(dir, rel);
  if (problem !== null) throw new Error(problem);
  return resolve(dir, rel);
}

export function listPieceFiles(dir: string): PieceFiles[] {
  const manifest = readLedgerManifest(dir);
  const pieces = manifest?.pieces ?? [legacyPieceRow()];
  return pieces.map((p) => ({
    id: p.id,
    decisions: requireLedgerPiecePath(dir, p.decisions),
    effects: requireLedgerPiecePath(dir, p.effects),
    inputs: requireLedgerPiecePath(dir, p.inputs),
    copyDecisions: requireLedgerPiecePath(dir, copyRel(p.id, "decisions.jsonl")),
    copyEffects: requireLedgerPiecePath(dir, copyRel(p.id, "effects.jsonl")),
    closed: p.closed,
    firstMs: p.firstMs,
    lastMs: p.lastMs,
    n: p.n,
    effectN: p.effectN,
  }));
}

export function pieceOverlaps(
  piece: { firstMs: number | null; lastMs: number | null; n: number; closed: boolean },
  fromMs: number,
  toMs: number,
): boolean {
  if (piece.firstMs === null || piece.lastMs === null) return piece.n > 0 || !piece.closed;
  return piece.lastMs >= fromMs && piece.firstMs < toMs;
}

export function parseIndexText(text: string): LedgerIndexLine[] {
  const rows: LedgerIndexLine[] = [];
  for (const line of text.split("\n")) {
    if (line === "") continue;
    // The index is appended without fsync, so a crash can leave its last
    // line half written. Such a line is skipped; the ref count below then
    // falls short of the ledger's and the index is rebuilt from the pieces.
    let raw: Partial<LedgerIndexLine>;
    try {
      raw = JSON.parse(line) as Partial<LedgerIndexLine>;
    } catch {
      continue;
    }
    if (typeof raw.ref !== "string" || typeof raw.piece !== "string") continue;
    rows.push({
      ref: raw.ref,
      tenantRef: typeof raw.tenantRef === "string" ? raw.tenantRef : "",
      piece: raw.piece,
      ts: typeof raw.ts === "number" ? raw.ts : 0,
      kind: typeof raw.kind === "string" ? raw.kind : "",
      requestHash: typeof raw.requestHash === "string" ? raw.requestHash : "",
      resolves: typeof raw.resolves === "string" ? raw.resolves : null,
      hasEffect: raw.hasEffect === true,
      reasonCode: typeof raw.reasonCode === "string" ? raw.reasonCode : "",
      subject: typeof raw.subject === "string" ? raw.subject : "",
      policyHash: typeof raw.policyHash === "string" ? raw.policyHash : "",
    });
  }
  return rows;
}

export function readLedgerIndex(dir: string): LedgerIndexLine[] {
  try {
    return parseIndexText(readFileSync(indexPath(dir), "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

/**
 * Decisions the index knows, by distinct ref. An effect adds a second line
 * for its decision's ref, so a line total would overstate what the index
 * holds and let a short index pass as complete.
 */
export function decisionIndexCount(lines: readonly LedgerIndexLine[]): number {
  const refs = new Set<string>();
  for (const l of lines) {
    if (l.kind === "allow" || l.kind === "deny" || l.kind === "defer") refs.add(l.ref);
  }
  return refs.size;
}

/**
 * What the on-disk index names, or null when the file is missing. Doctor
 * compares this to the pieces; a short index is rebuilt on the next open
 * but a running body does not see the missing refs until then.
 */
export function indexCoverage(dir: string): { refs: number; pieces: Set<string> } | null {
  if (!existsSync(indexPath(dir))) return null;
  const lines = readLedgerIndex(dir);
  const pieces = new Set<string>();
  for (const line of lines) pieces.add(line.piece);
  return { refs: decisionIndexCount(lines), pieces };
}

export function manifestExists(dir: string): boolean {
  return existsSync(manifestPath(dir));
}
