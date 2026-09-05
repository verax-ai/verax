import { randomBytes } from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import { existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";

/** I/O seam so append-cost tests can count rereads without mocking node:fs. */
export const ledgerFs = {
  readFile,
  readFileSync,
  open,
};
import { join } from "node:path";
import { canonical, decisionRecordHash } from "@cedulon/core";
import { coseToHex, signCoseSign1 } from "@cedulon/cose";
import {
  signEffectExtract,
  type EffectRow,
  type SignedEffectExtract,
} from "@cedulon/effect-extract";
import type {
  EffectSigner,
  ExtractWindow,
  Ledger,
  LedgerEffect,
  WitnessClass,
} from "./types.ts";
import type { SignedDecisionRecord } from "@cedulon/core";
import { sha256Canonical } from "./hash.ts";

export type PermissionCheck = "owner-only" | "not checked on this platform";

const DEFAULT_WITNESS: WitnessClass = "self";

/** One async tail so read-then-append cannot fork the chain. */
class SerialQueue {
  private tail: Promise<void> = Promise.resolve();

  enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.tail.then(fn, fn);
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

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

/** Write then fsync so a crash cannot drop a committed line. */
async function appendDurable(path: string, line: string): Promise<void> {
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

export class MemoryLedger implements Ledger {
  readonly permissionCheck: PermissionCheck = "owner-only";
  effectSigner?: EffectSigner;
  private readonly _decisions: SignedDecisionRecord[] = [];
  private readonly _effects: LedgerEffect[] = [];
  private readonly q = new SerialQueue();

  async appendDecision(signed: SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      this._decisions.push(signed);
    });
  }

  async appendDecisionChained(build: (prevRecordHash: string | null) => SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      const last = this._decisions[this._decisions.length - 1];
      this._decisions.push(build(last ? decisionRecordHash(last) : null));
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
      this._effects.push({
        row: {
          ref: row.ref,
          effectHash: sha256Canonical({ refused: "duplicate-effect", ref: row.ref }),
          effectClass: "duplicate-effect",
          timestampMs: row.timestampMs,
          actor: row.actor,
        },
        witnessClass: DEFAULT_WITNESS,
        resultHash,
      });
      throw new Error(`duplicate-effect:${row.ref}`);
    }
    this._effects.push({
      row: asEffectRow(row),
      witnessClass,
      resultHash,
      ...signedEffectFields(row, witnessClass, resultHash, this.effectSigner),
    });
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

export class FileLedger implements Ledger {
  readonly permissionCheck: PermissionCheck;
  readonly dir: string;
  effectSigner?: EffectSigner;
  private readonly decisionsPath: string;
  private readonly effectsPath: string;
  private readonly lockPath: string;
  private readonly q = new SerialQueue();
  private readonly token = randomBytes(16).toString("hex");
  private closed = false;
  private lost = false;
  private tailHash: string | null = null;
  private readonly effectRefs = new Set<string>();

  constructor(dir: string) {
    this.dir = dir;
    this.permissionCheck = ensureLedgerDir(dir);
    this.decisionsPath = join(dir, "decisions.jsonl");
    this.effectsPath = join(dir, "effects.jsonl");
    this.lockPath = join(dir, "ledger.lock");
    this.acquireLock();
    this.loadCaches();
  }

  /** After lock handoff a new instance reloads; the lost owner cannot append. */
  private loadCaches(): void {
    this.effectRefs.clear();
    const decisions = readJsonlSync<SignedDecisionRecord>(this.decisionsPath);
    const last = decisions[decisions.length - 1];
    this.tailHash = last ? decisionRecordHash(last) : null;
    for (const effect of readJsonlSync<LedgerEffect>(this.effectsPath)) {
      if (effect.row.effectClass !== "duplicate-effect") this.effectRefs.add(effect.row.ref);
    }
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
      await appendDurable(this.decisionsPath, lineOf(signed));
      this.tailHash = decisionRecordHash(signed);
    });
  }

  async appendDecisionChained(build: (prevRecordHash: string | null) => SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      this.assertOwned();
      const prev = await this.lastDecisionHashUnlocked();
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      const signed = build(prev);
      await appendDurable(this.decisionsPath, lineOf(signed));
      this.tailHash = decisionRecordHash(signed);
    });
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
      const marker: LedgerEffect = {
        row: {
          ref: row.ref,
          effectHash: sha256Canonical({ refused: "duplicate-effect", ref: row.ref }),
          effectClass: "duplicate-effect",
          timestampMs: row.timestampMs,
          actor: row.actor,
        },
        witnessClass: DEFAULT_WITNESS,
        resultHash,
      };
      await appendDurable(this.effectsPath, lineOf(marker));
      throw new Error(`duplicate-effect:${row.ref}`);
    }
    await appendDurable(
      this.effectsPath,
      lineOf({
        row: asEffectRow(row),
        witnessClass,
        resultHash,
        ...signedEffectFields(row, witnessClass, resultHash, this.effectSigner),
      }),
    );
    if (row.effectClass !== "duplicate-effect") this.effectRefs.add(row.ref);
  }

  async decisions(): Promise<SignedDecisionRecord[]> {
    return readJsonl<SignedDecisionRecord>(this.decisionsPath);
  }

  async effects(): Promise<LedgerEffect[]> {
    return readJsonl<LedgerEffect>(this.effectsPath);
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
