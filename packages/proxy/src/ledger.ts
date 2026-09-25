import { randomBytes } from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";

/** I/O seam so append-cost tests can count rereads without mocking node:fs. */
export const ledgerFs = {
  readFile,
  readFileSync,
  open,
};
import { dirname, join } from "node:path";
import { writeFileAtomic } from "./atomic-write.ts";
import { canonical, decisionRecordHash } from "@cedulon/core";
import { coseToHex, signCoseSign1 } from "@cedulon/cose";
import {
  signEffectExtract,
  type EffectRow,
  type SignedEffectExtract,
} from "@cedulon/effect-extract";
import { readJsonlTail, seekOffsetByTimestamp, type TailVisit } from "./jsonl-tail.ts";
import {
  copyRel,
  decisionIndexCount,
  DEFAULT_PIECE_MAX_BYTES,
  DEFAULT_PIECE_MAX_ROWS,
  indexPath,
  LEGACY_PIECE_ID,
  legacyPieceRow,
  newPieceRow,
  nextPieceId,
  pieceOverlaps,
  readLedgerIndex,
  readLedgerManifest,
  writeLedgerManifest,
  type LedgerIndexLine,
  type LedgerManifest,
  type LedgerPieceRow,
} from "./ledger-manifest.ts";
import { tenantKey } from "./tenant.ts";
import type {
  DecisionInputs,
  EffectSigner,
  ExtractWindow,
  Ledger,
  LedgerEffect,
  WitnessClass,
} from "./types.ts";
import type { DecisionKind, SignedDecisionRecord } from "@cedulon/core";
import { sha256Canonical } from "./hash.ts";
import { SerialQueue } from "./serial-queue.ts";

export type PermissionCheck = "owner-only" | "not checked on this platform";

const DEFAULT_WITNESS: WitnessClass = "self";

function lineOf(value: unknown): string {
  return `${canonical(value)}\n`;
}

function parseJsonl<T>(text: string): T[] {
  const rows: T[] = [];
  for (const line of text.split("\n")) {
    if (line === "") continue;
    rows.push(JSON.parse(line) as T);
  }
  return rows;
}

async function readJsonl<T>(path: string): Promise<T[]> {
  try {
    return parseJsonl<T>(await ledgerFs.readFile(path, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

function readJsonlSync<T>(path: string): T[] {
  try {
    return parseJsonl<T>(ledgerFs.readFileSync(path, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

/**
 * A ledger file read from its end through the same seam the reads above use,
 * so a test can count what a window costs.
 */
export function readLedgerTail<T>(
  path: string,
  visit: (row: T) => TailVisit,
  chunkBytesOrOpts?: number | { chunkBytes?: number; endOffset?: number },
): Promise<T[]> {
  const opts =
    chunkBytesOrOpts === undefined
      ? {}
      : typeof chunkBytesOrOpts === "number"
        ? { chunkBytes: chunkBytesOrOpts }
        : chunkBytesOrOpts;
  return readJsonlTail<T>(path, visit, { open: ledgerFs.open, ...opts });
}

async function readPieceWindow<T>(
  dir: string,
  piece: LedgerPieceRow,
  fileRel: string,
  toMs: number,
  tsOf: (row: T) => number,
  visit: (row: T) => TailVisit,
): Promise<T[]> {
  const path = join(dir, fileRel);
  const seekTarget = toMs + WINDOW_SLACK_MS;
  if (piece.lastMs !== null && seekTarget < piece.lastMs) {
    const endOffset = await seekOffsetByTimestamp(path, seekTarget, tsOf, { open: ledgerFs.open });
    return readLedgerTail(path, visit, { endOffset });
  }
  return readLedgerTail(path, visit);
}

/**
 * How far past a window's lower edge the tail reader keeps looking before it
 * stops. Rows are in file order; their stamps are the clock's, and a clock
 * can be set back. A row stamped a minute before its neighbour is still seen.
 */
export const WINDOW_SLACK_MS = 60_000;

/**
 * Write without fsync. For the ref index only: it is derived from the
 * pieces, a tail lost to a crash is rebuilt on the next open, and the
 * decision's own fsync stays the one per append.
 */
async function appendPlain(path: string, line: string): Promise<void> {
  const fh = await ledgerFs.open(path, "a");
  try {
    await fh.write(line);
  } finally {
    await fh.close();
  }
}

/** Write then fsync so a crash cannot drop a committed line. */
export async function appendDurable(path: string, line: string): Promise<void> {
  const fh = await ledgerFs.open(path, "a");
  try {
    await fh.write(line);
    await fh.sync();
  } finally {
    await fh.close();
  }
}

function assertDirPrivate(dir: string): PermissionCheck {
  if (process.platform === "win32") {
    // Stated, not a silent pass: Windows ACL is not measured here.
    return "not checked on this platform";
  }
  const mode = statSync(dir).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(`ledger-dir-not-private:${mode.toString(8)}`);
  }
  return "owner-only";
}

function ensureLedgerDir(dir: string): PermissionCheck {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return assertDirPrivate(dir);
}

export type RemoteWitnessSign = (
  row: EffectRow,
  resultHash: string | undefined,
) => Promise<Pick<LedgerEffect, "receipt" | "attestation" | "witnessClass"> | null>;

export function signEffectAttestation(
  row: EffectRow,
  witnessClass: WitnessClass,
  resultHash: string | undefined,
  signer: EffectSigner,
): Pick<LedgerEffect, "receipt" | "attestation"> {
  return signedEffectFields(row, witnessClass, resultHash, signer);
}

function signedEffectFields(
  row: EffectRow,
  witnessClass: WitnessClass,
  resultHash: string | undefined,
  signer: EffectSigner | undefined,
): Pick<LedgerEffect, "receipt" | "attestation"> {
  if (!signer) return {};
  const clean = asEffectRow(row);
  const receipt = signEffectExtract(
    {
      deciderId: "verax-proxy",
      channelId: "verax-body",
      windowStartMs: clean.timestampMs,
      windowEndMs: clean.timestampMs + 1,
      effects: [clean],
    },
    signer.privateKeyPem,
    signer.publicKeyPem,
  );
  const payload = Buffer.from(
    canonical({
      ref: clean.ref,
      effectHash: clean.effectHash,
      witnessClass,
      resultHash: resultHash ?? null,
    }),
    "utf8",
  );
  const attestation = {
    coseHex: coseToHex(signCoseSign1(payload, signer.privateKeyPem, "application/json")),
  };
  return { receipt, attestation };
}

function asEffectRow(row: EffectRow): EffectRow {
  return {
    ref: row.ref,
    effectHash: row.effectHash,
    effectClass: row.effectClass,
    timestampMs: row.timestampMs,
    ...(row.actor !== undefined ? { actor: row.actor } : {}),
  };
}

function asStoredEffect(
  row: EffectRow,
  witnessClass: WitnessClass,
  resultHash: string | undefined,
  signer: EffectSigner | undefined,
): LedgerEffect {
  const stored: LedgerEffect = {
    row: asEffectRow(row),
    witnessClass,
    ...signedEffectFields(row, witnessClass, resultHash, signer),
  };
  if (resultHash !== undefined) stored.resultHash = resultHash;
  return stored;
}

/** Slim index row. The Ledger interface stays closed. */
export type DecisionIndexRow = {
  ref: string;
  requestHash: string;
  decision: DecisionKind;
  reasonCode: string;
  subject: string;
  policyHash: string;
  timestampMs: number;
};

export type ResolutionHit = { ref: string; kind: "allow" | "expired" };

function indexRowOf(signed: SignedDecisionRecord): DecisionIndexRow | null {
  if (typeof signed.claims.ref !== "string") return null;
  return {
    ref: signed.claims.ref,
    requestHash: signed.claims.requestHash,
    decision: signed.claims.decision,
    reasonCode: signed.claims.reasonCode,
    subject: signed.claims.subject,
    policyHash: signed.claims.policyHash,
    timestampMs: signed.claims.timestampMs,
  };
}

function resolutionKindOf(row: DecisionIndexRow): ResolutionHit["kind"] | null {
  if (row.decision === "allow") return "allow";
  if (row.reasonCode === "expired") return "expired";
  return null;
}

function noteReauth(map: Map<string, string>, row: DecisionIndexRow): void {
  if (row.reasonCode !== "spend-reauth-required") return;
  if (!map.has(row.requestHash)) map.set(row.requestHash, row.ref);
}

function noteCounted(times: number[], row: DecisionIndexRow): void {
  if (row.decision === "allow" || row.decision === "defer") times.push(row.timestampMs);
}

export class MemoryLedger implements Ledger {
  readonly permissionCheck: PermissionCheck = "owner-only";
  effectSigner?: EffectSigner;
  private readonly _decisions: SignedDecisionRecord[] = [];
  private readonly _effects: LedgerEffect[] = [];
  private readonly byRef = new Map<string, DecisionIndexRow>();
  private readonly resolvedBy = new Map<string, ResolutionHit>();
  private readonly reauthByHash = new Map<string, string>();
  private readonly countedAt: number[] = [];
  countsReadable = true;
  private readonly q = new SerialQueue();

  lookupByRef(ref: string): DecisionIndexRow | null {
    return this.byRef.get(ref) ?? null;
  }

  noteTenantRef(key: string, ref: string): void {
    const row = this.byRef.get(ref);
    if (row) this.byRef.set(`${key}:${ref}`, row);
  }

  lookupResolvedBy(deferRef: string): ResolutionHit | null {
    return this.resolvedBy.get(deferRef) ?? null;
  }

  noteResolution(deferRef: string, hit: ResolutionHit): void {
    this.resolvedBy.set(deferRef, hit);
  }

  lookupReauthByHash(requestHash: string): string | null {
    return this.reauthByHash.get(requestHash) ?? null;
  }

  countedTimes(): number[] {
    return this.countedAt;
  }

  hasPrimaryEffect(ref: string): boolean {
    return this._effects.some((e) => e.row.ref === ref && e.row.effectClass !== "duplicate-effect");
  }

  async appendDecision(signed: SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      this._decisions.push(signed);
      const row = indexRowOf(signed);
      if (row) {
        this.byRef.set(row.ref, row);
        noteReauth(this.reauthByHash, row);
        noteCounted(this.countedAt, row);
      }
    });
  }

  async appendDecisionChained(build: (prevRecordHash: string | null) => SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      const last = this._decisions[this._decisions.length - 1];
      const signed = build(last ? decisionRecordHash(last) : null);
      this._decisions.push(signed);
      const row = indexRowOf(signed);
      if (row) {
        this.byRef.set(row.ref, row);
        noteReauth(this.reauthByHash, row);
        noteCounted(this.countedAt, row);
      }
    });
  }

  async appendEffect(row: EffectRow, witnessClass: WitnessClass = DEFAULT_WITNESS, resultHash?: string): Promise<void> {
    return this.q.enqueue(async () => this.appendEffectUnlocked(row, witnessClass, resultHash));
  }

  private async appendEffectUnlocked(
    row: EffectRow,
    witnessClass: WitnessClass,
    resultHash?: string,
  ): Promise<void> {
    const existing = this._effects.find((e) => e.row.ref === row.ref && e.row.effectClass !== "duplicate-effect");
    if (existing && row.effectClass !== "duplicate-effect") {
      this._effects.push(
        asStoredEffect(
          {
            ref: row.ref,
            effectHash: sha256Canonical({ refused: "duplicate-effect", ref: row.ref }),
            effectClass: "duplicate-effect",
            timestampMs: row.timestampMs,
            actor: row.actor,
          },
          DEFAULT_WITNESS,
          resultHash,
          this.effectSigner,
        ),
      );
      throw new Error(`duplicate-effect:${row.ref}`);
    }
    this._effects.push(asStoredEffect(row, witnessClass, resultHash, this.effectSigner));
  }

  async decisions(): Promise<SignedDecisionRecord[]> {
    return [...this._decisions];
  }

  async effects(): Promise<LedgerEffect[]> {
    return [...this._effects];
  }

  async lastDecisionHash(): Promise<string | null> {
    const last = this._decisions[this._decisions.length - 1];
    return last ? decisionRecordHash(last) : null;
  }

  async exportExtract(window: ExtractWindow, signer: EffectSigner): Promise<SignedEffectExtract> {
    return signWindow(this._effects, window, signer);
  }
}

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readLock(path: string): { pid: number; startedAt: number; token?: string } | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      pid?: unknown;
      startedAt?: unknown;
      token?: unknown;
    };
    if (typeof raw.pid !== "number" || typeof raw.startedAt !== "number") return null;
    return {
      pid: raw.pid,
      startedAt: raw.startedAt,
      ...(typeof raw.token === "string" ? { token: raw.token } : {}),
    };
  } catch {
    return null;
  }
}

export type FileLedgerOpts = {
  pieceMaxRows?: number;
  pieceMaxBytes?: number;
  onPieceClose?: (window: { startMs: number; endMs: number; pieceId: string }) => Promise<void>;
};

export type LedgerCounts = {
  decisions: number;
  effects: number;
  lastDecisionMs: number | null;
  activeDecisions: number;
  pieces: number;
};

export class FileLedger implements Ledger {
  readonly permissionCheck: PermissionCheck;
  readonly dir: string;
  effectSigner?: EffectSigner;
  /** Optional signer in another process. Null means stay `self`. */
  remoteWitness?: RemoteWitnessSign;
  /** Asked after a piece closes. A missing or failing hook does not block the close. */
  onPieceClose?: FileLedgerOpts["onPieceClose"];
  pieceMaxRows: number;
  pieceMaxBytes: number;
  private decisionsPath: string;
  private effectsPath: string;
  private inputsPath: string;
  private copyDecisionsPath: string;
  private copyEffectsPath: string;
  private readonly lockPath: string;
  private readonly q = new SerialQueue();
  private readonly token = randomBytes(16).toString("hex");
  private closed = false;
  private lost = false;
  private tailHash: string | null = null;
  private readonly effectRefs = new Set<string>();
  private readonly byRef = new Map<string, DecisionIndexRow>();
  private readonly resolvedBy = new Map<string, ResolutionHit>();
  private readonly reauthByHash = new Map<string, string>();
  private readonly countedAt: number[] = [];
  countsReadable = true;
  private readonly heartbeatPath: string;
  private decisionCount = 0;
  private effectCount = 0;
  private lastDecisionMs: number | null = null;
  private pieces: LedgerPieceRow[] = [];
  /** Inputs rows appended through this instance, until their decision lands. */
  private readonly recentInputs = new Map<string, DecisionInputs>();
  private activeId = LEGACY_PIECE_ID;
  private activeDecisionN = 0;
  private activeEffectN = 0;

  constructor(dir: string, opts?: FileLedgerOpts) {
    this.dir = dir;
    this.permissionCheck = ensureLedgerDir(dir);
    this.pieceMaxRows = opts?.pieceMaxRows ?? DEFAULT_PIECE_MAX_ROWS;
    this.pieceMaxBytes = opts?.pieceMaxBytes ?? DEFAULT_PIECE_MAX_BYTES;
    this.onPieceClose = opts?.onPieceClose;
    this.decisionsPath = join(dir, "decisions.jsonl");
    this.effectsPath = join(dir, "effects.jsonl");
    this.inputsPath = join(dir, "inputs.jsonl");
    this.copyDecisionsPath = join(dir, "evidence-copy", "decisions.jsonl");
    this.copyEffectsPath = join(dir, "evidence-copy", "effects.jsonl");
    this.lockPath = join(dir, "ledger.lock");
    this.heartbeatPath = join(dir, "heartbeat.json");
    this.acquireLock();
    try {
      this.loadCaches();
    } catch (err) {
      // A ledger that cannot be read is not held: the lock goes back so the
      // operator's next attempt is not refused as "locked" by a dead open.
      this.close();
      throw err;
    }
  }

  noteInputs(ref: string, inputs: DecisionInputs): void {
    this.recentInputs.set(ref, inputs);
    if (this.recentInputs.size > RECENT_INPUTS_MAX) {
      const oldest = this.recentInputs.keys().next().value;
      if (oldest !== undefined) this.recentInputs.delete(oldest);
    }
  }

  inputsPaths(): { active: string; all: string[] } {
    return {
      active: this.inputsPath,
      all: this.pieces.map((p) => join(this.dir, p.inputs)),
    };
  }

  /** After lock handoff a new instance reloads; the lost owner cannot append. */
  private loadCaches(): void {
    this.effectRefs.clear();
    this.byRef.clear();
    this.resolvedBy.clear();
    this.reauthByHash.clear();
    this.countedAt.length = 0;
    this.countsReadable = true;
    const stored = readLedgerManifest(this.dir);
    this.pieces = stored ? stored.pieces.map((p) => ({ ...p })) : [legacyPieceRow()];
    const open = [...this.pieces].reverse().find((p) => !p.closed) ?? this.pieces[this.pieces.length - 1]!;
    this.activeId = open.id;
    this.applyActivePaths();
    let activeDecisions: SignedDecisionRecord[] = [];
    try {
      activeDecisions = readJsonlSync<SignedDecisionRecord>(this.decisionsPath);
    } catch {
      this.countsReadable = false;
    }
    const closedN = this.pieces.filter((p) => p.closed).reduce((s, p) => s + p.n, 0);
    let indexLines = readLedgerIndex(this.dir);
    if (decisionIndexCount(indexLines) < closedN + activeDecisions.length) {
      indexLines = this.rebuildIndex(activeDecisions);
    }
    for (const line of indexLines) this.applyIndexLine(line);
    for (const line of indexLines) {
      if (line.kind === "allow" || line.kind === "defer") {
        noteCounted(this.countedAt, {
          ref: line.ref,
          requestHash: line.requestHash,
          decision: line.kind,
          reasonCode: line.reasonCode,
          subject: line.subject,
          policyHash: line.policyHash,
          timestampMs: line.ts,
        });
      }
    }
    this.pruneCounted(Date.now());
    const last = activeDecisions[activeDecisions.length - 1];
    if (last) {
      this.tailHash = decisionRecordHash(last);
      this.lastDecisionMs = last.claims.timestampMs;
    } else {
      const prev = [...this.pieces].reverse().find((p) => p.closed);
      this.tailHash = prev?.lastHash ?? null;
      this.lastDecisionMs = prev?.lastMs ?? null;
    }
    this.activeDecisionN = activeDecisions.length;
    this.decisionCount = closedN + activeDecisions.length;
    if (open.firstMs === null && activeDecisions[0]) open.firstMs = activeDecisions[0].claims.timestampMs;
    if (activeDecisions.length > 0) open.lastMs = activeDecisions[activeDecisions.length - 1]!.claims.timestampMs;
    open.n = activeDecisions.length;
    this.effectCount = 0;
    const activeEffects = readJsonlSync<LedgerEffect>(this.effectsPath);
    for (const effect of activeEffects) {
      this.effectCount += 1;
      if (effect.row.effectClass !== "duplicate-effect") this.effectRefs.add(effect.row.ref);
    }
    this.activeEffectN = activeEffects.length;
    const closedEffects = this.pieces.filter((p) => p.closed).reduce((s, p) => s + p.effectN, 0);
    this.effectCount = closedEffects + activeEffects.length;
    open.effectN = activeEffects.length;
  }

  private applyActivePaths(): void {
    const piece = this.pieces.find((p) => p.id === this.activeId) ?? this.pieces[this.pieces.length - 1]!;
    this.activeId = piece.id;
    this.decisionsPath = join(this.dir, piece.decisions);
    this.effectsPath = join(this.dir, piece.effects);
    this.inputsPath = join(this.dir, piece.inputs);
    this.copyDecisionsPath = join(this.dir, copyRel(piece.id, "decisions.jsonl"));
    this.copyEffectsPath = join(this.dir, copyRel(piece.id, "effects.jsonl"));
  }

  private activePiece(): LedgerPieceRow {
    return this.pieces.find((p) => p.id === this.activeId) ?? this.pieces[this.pieces.length - 1]!;
  }

  private applyIndexLine(line: LedgerIndexLine): void {
    // An effect marker names its decision's ref and nothing else: the
    // decision's own line already carries the row, and counting the marker
    // as a decision doubled the rate-limit work after a restart.
    if (line.kind === "effect") {
      this.effectRefs.add(line.ref);
      return;
    }
    const row: DecisionIndexRow = {
      ref: line.ref,
      requestHash: line.requestHash,
      decision: line.kind as DecisionKind,
      reasonCode: line.reasonCode,
      subject: line.subject,
      policyHash: line.policyHash,
      timestampMs: line.ts,
    };
    this.byRef.set(line.ref, row);
    if (line.tenantRef !== "") this.byRef.set(`${line.tenantRef}:${line.ref}`, row);
    noteReauth(this.reauthByHash, row);
    if (line.resolves) {
      const kind = resolutionKindOf(row);
      if (kind) this.resolvedBy.set(line.resolves, { ref: line.ref, kind });
    }
    if (line.hasEffect) this.effectRefs.add(line.ref);
  }

  private pruneCounted(nowMs: number): void {
    const day = new Date(nowMs);
    const keepFrom = Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate()) - 60_000;
    let w = 0;
    for (const t of this.countedAt) {
      if (t >= keepFrom) {
        this.countedAt[w] = t;
        w += 1;
      }
    }
    this.countedAt.length = w;
  }

  private rebuildIndex(activeDecisions: SignedDecisionRecord[]): LedgerIndexLine[] {
    const lines: LedgerIndexLine[] = [];
    for (const piece of this.pieces) {
      const path = join(this.dir, piece.decisions);
      const recs =
        piece.id === this.activeId ? activeDecisions : readJsonlSync<SignedDecisionRecord>(path);
      const inputLists = inputsByRef(join(this.dir, piece.inputs));
      const effectSet = primaryEffectRefs(join(this.dir, piece.effects));
      const seen = new Map<string, number>();
      for (const rec of recs) {
        const row = indexRowOf(rec);
        if (!row) continue;
        const idx = seen.get(row.ref) ?? 0;
        seen.set(row.ref, idx + 1);
        const inputs = inputLists.get(row.ref)?.[idx];
        const principal = inputs?.principal;
        const tenantRef =
          principal && typeof principal.brain === "string"
            ? tenantKey({
                brain: principal.brain,
                iss: principal.iss,
                tenant: principal.tenant,
                org: principal.org,
              })
            : "";
        lines.push({
          ref: row.ref,
          tenantRef,
          piece: piece.id,
          ts: row.timestampMs,
          kind: row.decision,
          requestHash: row.requestHash,
          resolves: inputs?.approver?.resolves ?? null,
          hasEffect: effectSet.has(row.ref),
          reasonCode: row.reasonCode,
          subject: row.subject,
          policyHash: row.policyHash,
        });
      }
    }
    const text = lines.map((l) => lineOf(l)).join("");
    writeFileAtomic(indexPath(this.dir), text);
    return lines;
  }

  private async writeIndexForDecision(signed: SignedDecisionRecord): Promise<void> {
    const row = indexRowOf(signed);
    if (!row) return;
    // The inputs row was handed over in memory when it was appended (the
    // proxy writes it just before the decision). The tail read is for a row
    // this instance did not write, and it is bounded: an append never reads
    // a piece back.
    let inputs = this.recentInputs.get(row.ref) ?? null;
    if (inputs) this.recentInputs.delete(row.ref);
    else inputs = await peekInputsTail(this.inputsPath, row.ref);
    const principal = inputs?.principal;
    const tenantRef =
      principal && typeof principal.brain === "string"
        ? tenantKey({
            brain: principal.brain,
            iss: principal.iss,
            tenant: principal.tenant,
            org: principal.org,
          })
        : "";
    const line: LedgerIndexLine = {
      ref: row.ref,
      tenantRef,
      piece: this.activeId,
      ts: row.timestampMs,
      kind: row.decision,
      requestHash: row.requestHash,
      resolves: inputs?.approver?.resolves ?? null,
      hasEffect: this.effectRefs.has(row.ref),
      reasonCode: row.reasonCode,
      subject: row.subject,
      policyHash: row.policyHash,
    };
    await appendPlain(indexPath(this.dir), lineOf(line));
    this.applyIndexLine(line);
  }

  private async writeIndexHasEffect(ref: string): Promise<void> {
    const existing = this.byRef.get(ref);
    if (!existing) return;
    const line: LedgerIndexLine = {
      ref,
      tenantRef: "",
      piece: this.activeId,
      ts: existing.timestampMs,
      kind: "effect",
      requestHash: "",
      resolves: null,
      hasEffect: true,
      reasonCode: "",
      subject: "",
      policyHash: "",
    };
    await appendPlain(indexPath(this.dir), lineOf(line));
    this.effectRefs.add(ref);
  }

  private noteActiveStamp(ts: number): void {
    const piece = this.activePiece();
    if (piece.firstMs === null) piece.firstMs = ts;
    piece.lastMs = ts;
  }

  private persistManifest(): void {
    const manifest: LedgerManifest = {
      version: 1,
      pieces: this.pieces,
      countedAtMs: [...this.countedAt],
    };
    writeLedgerManifest(this.dir, manifest);
  }

  private async fsyncPath(path: string): Promise<void> {
    try {
      const fh = await ledgerFs.open(path, "r+");
      try {
        await fh.sync();
      } finally {
        await fh.close();
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
  }

  private ensurePieceFiles(piece: LedgerPieceRow): void {
    mkdirSync(join(this.dir, dirname(piece.decisions)), { recursive: true, mode: 0o700 });
    mkdirSync(join(this.dir, dirname(copyRel(piece.id, "decisions.jsonl"))), { recursive: true, mode: 0o700 });
    for (const rel of [piece.decisions, piece.effects, piece.inputs, copyRel(piece.id, "decisions.jsonl"), copyRel(piece.id, "effects.jsonl")]) {
      const path = join(this.dir, rel);
      if (!existsSync(path)) writeFileSync(path, "", { encoding: "utf8", mode: 0o600 });
    }
  }

  private async closeActivePiece(): Promise<void> {
    this.assertOwned();
    const closing = this.activePiece();
    await this.fsyncPath(this.decisionsPath);
    await this.fsyncPath(this.effectsPath);
    await this.fsyncPath(this.inputsPath);
    closing.closed = true;
    closing.closedAtMs = Date.now();
    closing.n = this.activeDecisionN;
    closing.effectN = this.activeEffectN;
    closing.lastHash = this.tailHash;
    const nextId = nextPieceId(
      this.pieces.map((p) => p.id),
      closing.lastMs ?? Date.now(),
    );
    const next = newPieceRow(nextId);
    this.pieces.push(next);
    this.pruneCounted(Date.now());
    this.persistManifest();
    this.activeId = nextId;
    this.applyActivePaths();
    this.ensurePieceFiles(next);
    this.activeDecisionN = 0;
    this.activeEffectN = 0;
    try {
      await this.onPieceClose?.({
        startMs: closing.firstMs ?? 0,
        endMs: (closing.lastMs ?? 0) + 1,
        pieceId: closing.id,
      });
    } catch {
      // witness down: the piece stays closed
    }
  }

  private async maybeRotate(): Promise<void> {
    if (this.activeDecisionN >= this.pieceMaxRows) {
      await this.closeActivePiece();
      return;
    }
    let bytes = 0;
    try {
      bytes = statSync(this.decisionsPath).size;
    } catch {
      bytes = 0;
    }
    if (bytes >= this.pieceMaxBytes) await this.closeActivePiece();
  }

  private lockBody(): string {
    return `${JSON.stringify({ pid: process.pid, startedAt: Date.now(), token: this.token })}\n`;
  }

  private ownsLock(): boolean {
    const existing = readLock(this.lockPath);
    return existing?.token === this.token;
  }

  /** Lock file on disk, not a process counter. */
  lockStatus(): "held" | "free" {
    return this.ownsLock() ? "held" : "free";
  }

  private markLost(): void {
    this.lost = true;
  }

  private assertOwned(): void {
    if (this.lost || !this.ownsLock()) {
      this.markLost();
      throw new Error("ledger-lost-lock");
    }
  }

  private lockedError(): Error {
    const existing = readLock(this.lockPath);
    const pid = existing?.pid ?? "unknown";
    if (typeof existing?.pid === "number" && !pidAlive(existing.pid)) {
      return new Error(`ledger-locked-stale:${pid}\nrun: verax unlock ${this.dir}`);
    }
    return new Error(`ledger-locked:${pid}`);
  }

  private acquireLock(): void {
    const body = this.lockBody();
    try {
      writeFileSync(this.lockPath, body, { encoding: "utf8", flag: "wx", mode: 0o600 });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") throw this.lockedError();
      throw err;
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (!this.ownsLock()) {
      this.lost = true;
      return;
    }
    try {
      unlinkSync(this.lockPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }

  async appendDecision(signed: SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      this.assertOwned();
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      const line = lineOf(signed);
      await appendDurable(this.decisionsPath, line);
      await this.pulse("decisions.jsonl", line, "decision");
      this.tailHash = decisionRecordHash(signed);
      this.lastDecisionMs = signed.claims.timestampMs;
      this.noteActiveStamp(signed.claims.timestampMs);
      this.activeDecisionN += 1;
      const row = indexRowOf(signed);
      if (row) {
        this.byRef.set(row.ref, row);
        noteReauth(this.reauthByHash, row);
        noteCounted(this.countedAt, row);
      }
      await this.writeIndexForDecision(signed);
      await this.maybeRotate();
    });
  }

  async appendDecisionChained(build: (prevRecordHash: string | null) => SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      this.assertOwned();
      const prev = await this.lastDecisionHashUnlocked();
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      const signed = build(prev);
      const line = lineOf(signed);
      await appendDurable(this.decisionsPath, line);
      await this.pulse("decisions.jsonl", line, "decision");
      this.tailHash = decisionRecordHash(signed);
      this.lastDecisionMs = signed.claims.timestampMs;
      this.noteActiveStamp(signed.claims.timestampMs);
      this.activeDecisionN += 1;
      const row = indexRowOf(signed);
      if (row) {
        this.byRef.set(row.ref, row);
        noteReauth(this.reauthByHash, row);
        noteCounted(this.countedAt, row);
      }
      await this.writeIndexForDecision(signed);
      await this.maybeRotate();
    });
  }

  /**
   * What /healthz reports, from memory: the counts are kept on load and on
   * every append. Rereading both files to count lines cost a second per call
   * on a 100k-decision ledger (measured 17 Sep 2026), and the panel asks
   * every five seconds. Null when the decision file could not be parsed on
   * load; then the caller reads for itself and fails the way it always did.
   */
  counts(): LedgerCounts | null {
    if (!this.countsReadable) return null;
    return {
      decisions: this.decisionCount,
      effects: this.effectCount,
      lastDecisionMs: this.lastDecisionMs,
      activeDecisions: this.activeDecisionN,
      pieces: this.pieces.length,
    };
  }

  /**
   * Decisions stamped in [fromMs, toMs), read from the end of each overlapping
   * piece so the cost is the window's, not the ledger's. With a limit, the
   * newest rows of the window come back and `more` says the window went on,
   * including in a closed piece.
   */
  async decisionsWindow(
    fromMs: number,
    toMs: number,
    limit?: number,
  ): Promise<{ rows: SignedDecisionRecord[]; more: boolean; piecesTouched: string[] }> {
    const max = limit === undefined ? Number.POSITIVE_INFINITY : Math.max(0, Math.floor(limit));
    const overlapping = this.pieces.filter((p) => pieceOverlaps(p, fromMs, toMs));
    const piecesTouched = overlapping.map((p) => p.id);
    let taken = 0;
    let more = false;
    let stopOld = false;
    const newestFirst = [...overlapping].reverse();
    const collected: SignedDecisionRecord[] = [];
    for (let i = 0; i < newestFirst.length; i += 1) {
      const piece = newestFirst[i]!;
      if (stopOld) break;
      const part = await readPieceWindow<SignedDecisionRecord>(
        this.dir,
        piece,
        piece.decisions,
        toMs,
        (row) => row.claims.timestampMs,
        (row) => {
          const ts = row.claims.timestampMs;
          if (ts >= toMs) return "skip";
          if (ts < fromMs) {
            if (ts < fromMs - WINDOW_SLACK_MS) {
              stopOld = true;
              return "stop";
            }
            return "skip";
          }
          if (taken >= max) {
            more = true;
            return "stop";
          }
          taken += 1;
          return "take";
        },
      );
      collected.unshift(...part);
      if (more || stopOld) break;
      if (taken >= max && i + 1 < newestFirst.length) {
        more = true;
        break;
      }
    }
    return { rows: collected, more, piecesTouched };
  }

  /** Effects stamped in [fromMs, toMs), read from the end of each overlapping piece. */
  async effectsWindow(fromMs: number, toMs: number): Promise<LedgerEffect[]> {
    const overlapping = this.pieces.filter((p) => pieceOverlaps(p, fromMs, toMs));
    const newestFirst = [...overlapping].reverse();
    const collected: LedgerEffect[] = [];
    let stopOld = false;
    for (const piece of newestFirst) {
      if (stopOld) break;
      const part = await readPieceWindow<LedgerEffect>(
        this.dir,
        piece,
        piece.effects,
        toMs,
        (effect) => effect.row.timestampMs,
        (effect) => {
          const ts = effect.row.timestampMs;
          if (ts >= toMs) return "skip";
          if (ts < fromMs) {
            if (ts < fromMs - WINDOW_SLACK_MS) {
              stopOld = true;
              return "stop";
            }
            return "skip";
          }
          return "take";
        },
      );
      collected.unshift(...part);
    }
    return collected;
  }

  async appendEffect(row: EffectRow, witnessClass: WitnessClass = DEFAULT_WITNESS, resultHash?: string): Promise<void> {
    return this.q.enqueue(async () => {
      this.assertOwned();
      return this.appendEffectUnlocked(row, witnessClass, resultHash);
    });
  }

  private async appendEffectUnlocked(
    row: EffectRow,
    witnessClass: WitnessClass = DEFAULT_WITNESS,
    resultHash?: string,
  ): Promise<void> {
    if (row.effectClass !== "duplicate-effect" && this.effectRefs.has(row.ref)) {
      const dup = lineOf(
        asStoredEffect(
          {
            ref: row.ref,
            effectHash: sha256Canonical({ refused: "duplicate-effect", ref: row.ref }),
            effectClass: "duplicate-effect",
            timestampMs: row.timestampMs,
            actor: row.actor,
          },
          DEFAULT_WITNESS,
          resultHash,
          this.effectSigner,
        ),
      );
      await appendDurable(this.effectsPath, dup);
      await this.pulse("effects.jsonl", dup, "effect");
      this.activeEffectN += 1;
      throw new Error(`duplicate-effect:${row.ref}`);
    }
    const line = lineOf(await this.storeEffect(row, witnessClass, resultHash));
    await appendDurable(this.effectsPath, line);
    await this.pulse("effects.jsonl", line, "effect");
    this.activeEffectN += 1;
    if (row.effectClass !== "duplicate-effect") {
      this.effectRefs.add(row.ref);
      await this.writeIndexHasEffect(row.ref);
    }
  }

  async decisions(): Promise<SignedDecisionRecord[]> {
    const out: SignedDecisionRecord[] = [];
    for (const piece of this.pieces) {
      out.push(...(await readJsonl<SignedDecisionRecord>(join(this.dir, piece.decisions))));
    }
    return out;
  }

  async effects(): Promise<LedgerEffect[]> {
    const out: LedgerEffect[] = [];
    for (const piece of this.pieces) {
      out.push(...(await readJsonl<LedgerEffect>(join(this.dir, piece.effects))));
    }
    return out;
  }

  async lastDecisionHash(): Promise<string | null> {
    return this.lastDecisionHashUnlocked();
  }

  private async lastDecisionHashUnlocked(): Promise<string | null> {
    return this.tailHash;
  }

  async exportExtract(window: ExtractWindow, signer: EffectSigner): Promise<SignedEffectExtract> {
    return signWindow(await this.effects(), window, signer);
  }

  lookupByRef(ref: string): DecisionIndexRow | null {
    return this.byRef.get(ref) ?? null;
  }

  noteTenantRef(key: string, ref: string): void {
    const row = this.byRef.get(ref);
    if (row) this.byRef.set(`${key}:${ref}`, row);
  }

  lookupResolvedBy(deferRef: string): ResolutionHit | null {
    return this.resolvedBy.get(deferRef) ?? null;
  }

  noteResolution(deferRef: string, hit: ResolutionHit): void {
    this.resolvedBy.set(deferRef, hit);
  }

  lookupReauthByHash(requestHash: string): string | null {
    return this.reauthByHash.get(requestHash) ?? null;
  }

  countedTimes(): number[] {
    return this.countedAt;
  }

  hasPrimaryEffect(ref: string): boolean {
    return this.effectRefs.has(ref);
  }

  private async pulse(
    name: "decisions.jsonl" | "effects.jsonl",
    line: string,
    kind: "decision" | "effect",
  ): Promise<void> {
    const dest = name === "decisions.jsonl" ? this.copyDecisionsPath : this.copyEffectsPath;
    mkdirSync(dirname(dest), { recursive: true, mode: 0o700 });
    appendFileSync(dest, line, { encoding: "utf8" });
    if (kind === "decision") this.decisionCount += 1;
    else this.effectCount += 1;
    writeFileSync(
      this.heartbeatPath,
      `${JSON.stringify({
        atMs: Date.now(),
        pid: process.pid,
        lastDecisionN: this.decisionCount,
        lastEffectN: this.effectCount,
      })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  }

  private async storeEffect(
    row: EffectRow,
    witnessClass: WitnessClass,
    resultHash: string | undefined,
  ): Promise<LedgerEffect> {
    if (this.remoteWitness && row.effectClass !== "duplicate-effect") {
      const remote = await this.remoteWitness(row, resultHash);
      if (remote?.attestation && remote.receipt && remote.witnessClass && remote.witnessClass !== "self") {
        const stored: LedgerEffect = {
          row: asEffectRow(row),
          witnessClass: remote.witnessClass,
          receipt: remote.receipt,
          attestation: remote.attestation,
        };
        if (resultHash !== undefined) stored.resultHash = resultHash;
        return stored;
      }
      return asStoredEffect(row, DEFAULT_WITNESS, resultHash, this.effectSigner);
    }
    return asStoredEffect(row, witnessClass, resultHash, this.effectSigner);
  }
}

const RECENT_INPUTS_MAX = 4096;
const PEEK_INPUTS_ROWS = 256;

/** The newest rows of inputs.jsonl, from the end, for a ref this instance did not append. */
async function peekInputsTail(path: string, ref: string): Promise<DecisionInputs | null> {
  let visited = 0;
  let found = false;
  let rows: { ref?: unknown; inputs?: DecisionInputs }[];
  try {
    rows = await readLedgerTail<{ ref?: unknown; inputs?: DecisionInputs }>(path, (row) => {
      if (found) return "stop";
      visited += 1;
      if (row.ref === ref) {
        found = true;
        return "take";
      }
      return visited >= PEEK_INPUTS_ROWS ? "stop" : "skip";
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  return rows[0]?.inputs ?? null;
}

function inputsByRef(path: string): Map<string, DecisionInputs[]> {
  const out = new Map<string, DecisionInputs[]>();
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return out;
    throw err;
  }
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: unknown; inputs?: DecisionInputs };
    if (typeof row.ref !== "string" || !row.inputs) continue;
    const list = out.get(row.ref) ?? [];
    list.push(row.inputs);
    out.set(row.ref, list);
  }
  return out;
}

function primaryEffectRefs(path: string): Set<string> {
  const refs = new Set<string>();
  for (const effect of readJsonlSync<LedgerEffect>(path)) {
    if (effect.row.effectClass !== "duplicate-effect") refs.add(effect.row.ref);
  }
  return refs;
}

function signWindow(
  effects: LedgerEffect[],
  window: ExtractWindow,
  signer: EffectSigner,
): SignedEffectExtract {
  const rows = effects
    .filter((e) => e.row.timestampMs >= window.startMs && e.row.timestampMs < window.endMs)
    .map((e) => asEffectRow(e.row));
  return signEffectExtract(
    {
      deciderId: "verax-proxy",
      channelId: "verax-body",
      windowStartMs: window.startMs,
      windowEndMs: window.endMs,
      effects: rows,
    },
    signer.privateKeyPem,
    signer.publicKeyPem,
  );
}

/** Extra methods on FileLedger / MemoryLedger. The Ledger interface stays closed. */
type LedgerIndex = {
  lookupByRef?: (ref: string) => DecisionIndexRow | null;
  noteTenantRef?: (key: string, ref: string) => void;
  hasPrimaryEffect?: (ref: string) => boolean;
  lookupResolvedBy?: (deferRef: string) => ResolutionHit | null;
  noteResolution?: (deferRef: string, hit: ResolutionHit) => void;
  lookupReauthByHash?: (requestHash: string) => string | null;
  countedTimes?: () => number[];
  countsReadable?: boolean;
};

export async function lookupDecisionByRef(
  ledger: Ledger,
  ref: string,
  key?: string,
): Promise<DecisionIndexRow | null> {
  const extra = ledger as Ledger & LedgerIndex;
  if (typeof extra.lookupByRef === "function") {
    if (key) return extra.lookupByRef(`${key}:${ref}`);
    return extra.lookupByRef(ref);
  }
  const found = (await ledger.decisions()).find((d) => d.claims.ref === ref);
  return found ? indexRowOf(found) : null;
}

export function noteTenantRef(ledger: Ledger, key: string, ref: string): void {
  const extra = ledger as Ledger & LedgerIndex;
  if (typeof extra.noteTenantRef === "function") extra.noteTenantRef(key, ref);
}

export function lookupResolvedBy(ledger: Ledger, deferRef: string): ResolutionHit | null {
  const extra = ledger as Ledger & LedgerIndex;
  if (typeof extra.lookupResolvedBy === "function") return extra.lookupResolvedBy(deferRef);
  return null;
}

export function noteResolution(ledger: Ledger, deferRef: string, hit: ResolutionHit): void {
  const extra = ledger as Ledger & LedgerIndex;
  if (typeof extra.noteResolution === "function") extra.noteResolution(deferRef, hit);
}

export function countedWork(
  ledger: Ledger,
  nowMs: number,
): { ok: true; minute: number; day: number } | { ok: false } {
  const extra = ledger as Ledger & LedgerIndex;
  if (extra.countsReadable === false) return { ok: false };
  if (typeof extra.countedTimes !== "function") return { ok: false };
  const times = extra.countedTimes();
  const minuteStart = nowMs - 60_000;
  const day = new Date(nowMs);
  const dayStart = Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate());
  let minute = 0;
  let dayCount = 0;
  for (const t of times) {
    if (t >= minuteStart && t <= nowMs) minute += 1;
    if (t >= dayStart && t <= nowMs) dayCount += 1;
  }
  return { ok: true, minute, day: dayCount };
}

export async function lookupReauthByHash(ledger: Ledger, requestHash: string): Promise<string | null> {
  const extra = ledger as Ledger & LedgerIndex;
  if (typeof extra.lookupReauthByHash === "function") return extra.lookupReauthByHash(requestHash);
  for (const d of await ledger.decisions()) {
    if (d.claims.reasonCode === "spend-reauth-required" && d.claims.requestHash === requestHash && d.claims.ref) {
      return d.claims.ref;
    }
  }
  return null;
}

export async function hasPrimaryEffect(ledger: Ledger, ref: string): Promise<boolean> {
  const extra = ledger as Ledger & LedgerIndex;
  if (typeof extra.hasPrimaryEffect === "function") return extra.hasPrimaryEffect(ref);
  return (await ledger.effects()).some((e) => e.row.ref === ref && e.row.effectClass !== "duplicate-effect");
}

export function witnessClassSummary(effects: readonly LedgerEffect[]): Record<WitnessClass, number> {
  const out: Record<WitnessClass, number> = {
    self: 0,
    "same-org": 0,
    "third-party": 0,
    regulated: 0,
  };
  for (const e of effects) {
    out[e.witnessClass] += 1;
  }
  return out;
}
