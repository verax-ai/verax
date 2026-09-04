import { appendFile, mkdir, readFile } from "node:fs/promises";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { canonical, decisionRecordHash } from "@cedulon/core";
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
    return parseJsonl<T>(await readFile(path, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
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

  async appendEffect(row: EffectRow, witnessClass: WitnessClass = DEFAULT_WITNESS): Promise<void> {
    return this.q.enqueue(async () => this.appendEffectUnlocked(row, witnessClass));
  }

  private async appendEffectUnlocked(row: EffectRow, witnessClass: WitnessClass): Promise<void> {
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
      });
      throw new Error(`duplicate-effect:${row.ref}`);
    }
    this._effects.push({ row: asEffectRow(row), witnessClass });
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

export class FileLedger implements Ledger {
  readonly permissionCheck: PermissionCheck;
  readonly dir: string;
  private readonly decisionsPath: string;
  private readonly effectsPath: string;
  private readonly q = new SerialQueue();

  constructor(dir: string) {
    this.dir = dir;
    this.permissionCheck = ensureLedgerDir(dir);
    this.decisionsPath = join(dir, "decisions.jsonl");
    this.effectsPath = join(dir, "effects.jsonl");
  }

  async appendDecision(signed: SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      await appendFile(this.decisionsPath, lineOf(signed), { encoding: "utf8" });
    });
  }

  async appendDecisionChained(build: (prevRecordHash: string | null) => SignedDecisionRecord): Promise<void> {
    return this.q.enqueue(async () => {
      const prev = await this.lastDecisionHashUnlocked();
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      await appendFile(this.decisionsPath, lineOf(build(prev)), { encoding: "utf8" });
    });
  }

  async appendEffect(row: EffectRow, witnessClass: WitnessClass = DEFAULT_WITNESS): Promise<void> {
    return this.q.enqueue(async () => this.appendEffectUnlocked(row, witnessClass));
  }

  private async appendEffectUnlocked(row: EffectRow, witnessClass: WitnessClass = DEFAULT_WITNESS): Promise<void> {
    const current = await this.effects();
    const existing = current.find((e) => e.row.ref === row.ref && e.row.effectClass !== "duplicate-effect");
    if (existing && row.effectClass !== "duplicate-effect") {
      const marker: LedgerEffect = {
        row: {
          ref: row.ref,
          effectHash: sha256Canonical({ refused: "duplicate-effect", ref: row.ref }),
          effectClass: "duplicate-effect",
          timestampMs: row.timestampMs,
          actor: row.actor,
        },
        witnessClass: DEFAULT_WITNESS,
      };
      await appendFile(this.effectsPath, lineOf(marker), { encoding: "utf8" });
      throw new Error(`duplicate-effect:${row.ref}`);
    }
    await appendFile(this.effectsPath, lineOf({ row: asEffectRow(row), witnessClass }), {
      encoding: "utf8",
    });
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
    const all = await this.decisions();
    const last = all[all.length - 1];
    return last ? decisionRecordHash(last) : null;
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
