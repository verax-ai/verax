import { appendFileSync, existsSync, readdirSync, readFileSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { signDecisionRecord } from "@cedulon/core";
import { appendDurable, lookupDecisionByRef, lookupResolvedBy, noteResolution } from "./ledger.ts";
import { effectDescriptor, sha256Canonical } from "./hash.ts";
import { inputsLogFor } from "./inputs.ts";
import type { DecisionInputs, InputsLog, Ledger, RecordSigner } from "./types.ts";

export type ApprovalRow = {
  ref: string;
  requestHash: string;
  subject: string;
  args: Record<string, unknown>;
  ruleId: string | null;
  ruleText: string | null;
  inputsSummary: { count: number; ids: string[] };
  amount?: unknown;
  payee?: unknown;
  currency?: unknown;
  createdAtMs?: number;
  expiresAtMs: number;
  status: "pending" | "approved" | "expired";
  brain: string;
  allowRef?: string;
};

export type ApprovalsLog = {
  append(row: ApprovalRow): Promise<void>;
  get(ref: string): Promise<ApprovalRow | null>;
  listPending(): Promise<ApprovalRow[]>;
  listAll(): Promise<ApprovalRow[]>;
  updateStatus(ref: string, status: "approved" | "expired", extra?: { allowRef?: string }): Promise<void>;
};

function lastByRef(rows: ApprovalRow[]): Map<string, ApprovalRow> {
  const map = new Map<string, ApprovalRow>();
  for (const row of rows) map.set(row.ref, row);
  return map;
}

function parseLines(text: string): ApprovalRow[] {
  const rows: ApprovalRow[] = [];
  for (const line of text.split("\n")) {
    if (line === "") continue;
    rows.push(JSON.parse(line) as ApprovalRow);
  }
  return rows;
}

export class MemoryApprovalsLog implements ApprovalsLog {
  private readonly rows: ApprovalRow[] = [];
  private readonly byRef = new Map<string, ApprovalRow>();

  async append(row: ApprovalRow): Promise<void> {
    this.rows.push(row);
    this.byRef.set(row.ref, row);
  }

  async get(ref: string): Promise<ApprovalRow | null> {
    return this.byRef.get(ref) ?? null;
  }

  async listPending(): Promise<ApprovalRow[]> {
    return [...this.byRef.values()].filter((r) => r.status === "pending");
  }

  async listAll(): Promise<ApprovalRow[]> {
    return [...this.byRef.values()];
  }

  async updateStatus(ref: string, status: "approved" | "expired", extra?: { allowRef?: string }): Promise<void> {
    const cur = this.byRef.get(ref);
    if (!cur) return;
    await this.append({ ...cur, status, ...(extra?.allowRef !== undefined ? { allowRef: extra.allowRef } : {}) });
  }
}

export class FileApprovalsLog implements ApprovalsLog {
  private readonly path: string;
  private readonly byRef = new Map<string, ApprovalRow>();

  constructor(dir: string) {
    this.path = join(dir, "approvals.jsonl");
    for (const row of this.read()) this.byRef.set(row.ref, row);
  }

  async append(row: ApprovalRow): Promise<void> {
    await appendDurable(this.path, `${JSON.stringify(row)}\n`);
    this.byRef.set(row.ref, row);
  }

  async get(ref: string): Promise<ApprovalRow | null> {
    return this.byRef.get(ref) ?? null;
  }

  async listPending(): Promise<ApprovalRow[]> {
    return [...this.byRef.values()].filter((r) => r.status === "pending");
  }

  async listAll(): Promise<ApprovalRow[]> {
    return [...this.byRef.values()];
  }

  async updateStatus(ref: string, status: "approved" | "expired", extra?: { allowRef?: string }): Promise<void> {
    const cur = this.byRef.get(ref);
    if (!cur) return;
    await this.append({ ...cur, status, ...(extra?.allowRef !== undefined ? { allowRef: extra.allowRef } : {}) });
  }

  private read(): ApprovalRow[] {
    try {
      return parseLines(readFileSync(this.path, "utf8"));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }
}

const STASH = Symbol.for("verax.approvalsLog");

export function approvalsLogFor(ledger: object): ApprovalsLog {
  const bag = ledger as { dir?: unknown; [STASH]?: ApprovalsLog };
  if (bag[STASH]) return bag[STASH];
  const log = typeof bag.dir === "string" ? new FileApprovalsLog(bag.dir) : new MemoryApprovalsLog();
  bag[STASH] = log;
  return log;
}

export function loadApprovalsFromDir(dir: string): ApprovalRow[] {
  const path = join(dir, "approvals.jsonl");
  try {
    return [...lastByRef(parseLines(readFileSync(path, "utf8"))).values()];
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

export type ApproveResult = { ok: true; allowRef: string } | { ok: false; reason: string };

async function hasResolves(inputsLog: InputsLog, ledger: Ledger, deferRef: string): Promise<boolean> {
  const indexed = ledger as Ledger & { lookupResolvedBy?: (ref: string) => unknown };
  if (typeof indexed.lookupResolvedBy === "function") {
    return indexed.lookupResolvedBy(deferRef) != null;
  }
  for (const d of await ledger.decisions()) {
    if (!d.claims.ref || d.claims.ref === deferRef) continue;
    const inp = await inputsLog.get(d.claims.ref);
    if (inp?.approver?.resolves === deferRef) return true;
  }
  return false;
}

export async function approvePending(opts: {
  ledger: Ledger;
  recordSigner: RecordSigner;
  now: () => number;
  nonce: () => string;
  ref: string;
  approverId: string;
  policyHash: string;
  approvals: ApprovalsLog;
  inputsLog?: InputsLog;
}): Promise<ApproveResult> {
  const inputsLog = opts.inputsLog ?? inputsLogFor(opts.ledger);
  const defer = await lookupDecisionByRef(opts.ledger, opts.ref);
  if (!defer || defer.decision !== "defer") return { ok: false, reason: "unknown-ref" };
  const snap = await opts.approvals.get(opts.ref);
  if (snap && snap.status !== "pending") return { ok: false, reason: "already-resolved" };
  const resolved = lookupResolvedBy(opts.ledger, opts.ref);
  if (resolved || (await hasResolves(inputsLog, opts.ledger, opts.ref))) {
    const hit = resolved ?? lookupResolvedBy(opts.ledger, opts.ref);
    if (snap?.status === "pending" && hit) {
      await opts.approvals.updateStatus(
        opts.ref,
        hit.kind === "allow" ? "approved" : "expired",
        hit.kind === "allow" ? { allowRef: hit.ref } : undefined,
      );
    }
    return { ok: false, reason: "already-resolved" };
  }
  if (!snap) return { ok: false, reason: "snapshot-missing" };
  const requestHash = sha256Canonical({ name: snap.subject, arguments: snap.args });
  if (requestHash !== defer.requestHash || requestHash !== snap.requestHash) {
    return { ok: false, reason: "hash-mismatch" };
  }
  if (opts.now() > snap.expiresAtMs) {
    const expireRef = opts.nonce();
    const prior = await inputsLog.get(opts.ref);
    const inputs: DecisionInputs = {
      principal: prior?.principal ?? { brain: snap.brain, scopes: [] },
      inputs: prior?.inputs ?? [],
      approver: { id: opts.approverId, via: "cli", resolves: opts.ref },
    };
    const inputsHash = sha256Canonical(inputs);
    await inputsLog.append(expireRef, inputs);
    await opts.ledger.appendDecisionChained((prevRecordHash) =>
      signDecisionRecord(
        {
          decider: "verax-operator",
          subject: defer.subject,
          requestHash: defer.requestHash,
          policyHash: opts.policyHash,
          inputsHash,
          decision: "deny",
          reasonCode: "expired",
          ref: expireRef,
          effectHash: null,
          timestampMs: opts.now(),
          nonce: expireRef,
          prevRecordHash,
        },
        opts.recordSigner.privateKeyPem,
        opts.recordSigner.publicKeyPem,
      ),
    );
    noteResolution(opts.ledger, opts.ref, { ref: expireRef, kind: "expired" });
    await opts.approvals.updateStatus(opts.ref, "expired");
    return { ok: false, reason: "expired" };
  }
  const allowRef = opts.nonce();
  const prior = await inputsLog.get(opts.ref);
  const inputs: DecisionInputs = {
    principal: prior?.principal ?? { brain: snap.brain, scopes: [] },
    inputs: prior?.inputs ?? [],
    approver: { id: opts.approverId, via: "cli", resolves: opts.ref },
  };
  const inputsHash = sha256Canonical(inputs);
  const effectHash = sha256Canonical(effectDescriptor(snap.subject, snap.args));
  await inputsLog.append(allowRef, inputs);
  await opts.ledger.appendDecisionChained((prevRecordHash) =>
    signDecisionRecord(
      {
        decider: "verax-operator",
        subject: defer.subject,
        requestHash: defer.requestHash,
        policyHash: opts.policyHash,
        inputsHash,
        decision: "allow",
        reasonCode: "approved-by-operator",
        ref: allowRef,
        effectHash,
        timestampMs: opts.now(),
        nonce: allowRef,
        prevRecordHash,
      },
      opts.recordSigner.privateKeyPem,
      opts.recordSigner.publicKeyPem,
    ),
  );
  noteResolution(opts.ledger, opts.ref, { ref: allowRef, kind: "allow" });
  if (snap.subject === "spend") {
    await opts.ledger.appendEffect({
      ref: allowRef,
      effectHash,
      effectClass: "spend",
      timestampMs: opts.now(),
      actor: snap.brain,
    });
  }
  await opts.approvals.updateStatus(opts.ref, "approved", { allowRef });
  return { ok: true, allowRef };
}

export type ApprovalCommand = { ref: string; approverId: string; atMs: number };

export function enqueueApprovalCommand(dir: string, cmd: ApprovalCommand): void {
  appendFileSync(join(dir, "approval-commands.jsonl"), `${JSON.stringify(cmd)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

export async function drainApprovalCommands(
  dir: string,
  apply: (cmd: ApprovalCommand) => Promise<void>,
): Promise<void> {
  const live = join(dir, "approval-commands.jsonl");
  if (existsSync(live)) {
    const processing = join(dir, `approval-commands.processing-${Date.now()}-${process.pid}`);
    try {
      renameSync(live, processing);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EPERM" || code === "EBUSY") return;
      if (code !== "ENOENT") throw err;
    }
  }
  let names: string[];
  try {
    names = readdirSync(dir)
      .filter((n) => n.startsWith("approval-commands.processing-"))
      .sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  const donePath = join(dir, "approval-commands.applied.jsonl");
  const poisonPath = join(dir, "approval-commands.poison.jsonl");
  for (const name of names) {
    const file = join(dir, name);
    try {
      const text = readFileSync(file, "utf8");
      for (const line of text.split("\n")) {
        if (line === "") continue;
        try {
          const cmd = JSON.parse(line) as ApprovalCommand;
          await apply(cmd);
          appendFileSync(donePath, `${line}\n`, { encoding: "utf8", mode: 0o600 });
        } catch (err) {
          const error = err instanceof Error ? err.message : String(err);
          appendFileSync(
            poisonPath,
            `${JSON.stringify({ line, error, atMs: Date.now() })}\n`,
            { encoding: "utf8", mode: 0o600 },
          );
        }
      }
    } finally {
      unlinkSync(file);
    }
  }
}
