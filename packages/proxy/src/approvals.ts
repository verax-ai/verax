import { appendFileSync, existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { signDecisionRecord, decisionRecordHash } from "@cedulon/core";
import { appendDurable } from "./ledger.ts";
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
  expiresAtMs: number;
  status: "pending" | "approved" | "expired";
  brain: string;
};

export type ApprovalsLog = {
  append(row: ApprovalRow): Promise<void>;
  get(ref: string): Promise<ApprovalRow | null>;
  listPending(): Promise<ApprovalRow[]>;
  updateStatus(ref: string, status: "approved" | "expired"): Promise<void>;
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

  async append(row: ApprovalRow): Promise<void> {
    this.rows.push(row);
  }

  async get(ref: string): Promise<ApprovalRow | null> {
    return lastByRef(this.rows).get(ref) ?? null;
  }

  async listPending(): Promise<ApprovalRow[]> {
    return [...lastByRef(this.rows).values()].filter((r) => r.status === "pending");
  }

  async updateStatus(ref: string, status: "approved" | "expired"): Promise<void> {
    const cur = await this.get(ref);
    if (!cur) return;
    this.rows.push({ ...cur, status });
  }
}

export class FileApprovalsLog implements ApprovalsLog {
  private readonly path: string;

  constructor(dir: string) {
    this.path = join(dir, "approvals.jsonl");
  }

  async append(row: ApprovalRow): Promise<void> {
    await appendDurable(this.path, `${JSON.stringify(row)}\n`);
  }

  async get(ref: string): Promise<ApprovalRow | null> {
    return lastByRef(this.read()).get(ref) ?? null;
  }

  async listPending(): Promise<ApprovalRow[]> {
    return [...lastByRef(this.read()).values()].filter((r) => r.status === "pending");
  }

  async updateStatus(ref: string, status: "approved" | "expired"): Promise<void> {
    const cur = await this.get(ref);
    if (!cur) return;
    await this.append({ ...cur, status });
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
  const decisions = await opts.ledger.decisions();
  const defer = decisions.find((d) => d.claims.ref === opts.ref && d.claims.decision === "defer");
  if (!defer) return { ok: false, reason: "unknown-ref" };
  const already = decisions.find(
    (d) =>
      d.claims.requestHash === defer.claims.requestHash &&
      d.claims.prevRecordHash === decisionRecordHash(defer) &&
      (d.claims.decision === "allow" || d.claims.reasonCode === "expired"),
  );
  if (already) return { ok: false, reason: "already-resolved" };
  const snap = await opts.approvals.get(opts.ref);
  if (!snap) return { ok: false, reason: "snapshot-missing" };
  const requestHash = sha256Canonical({ name: snap.subject, arguments: snap.args });
  if (requestHash !== defer.claims.requestHash || requestHash !== snap.requestHash) {
    return { ok: false, reason: "hash-mismatch" };
  }
  if (opts.now() > snap.expiresAtMs) {
    const expireRef = opts.nonce();
    const prior = await inputsLog.get(opts.ref);
    const inputs: DecisionInputs = {
      principal: prior?.principal ?? { brain: snap.brain, scopes: [] },
      inputs: prior?.inputs ?? [],
    };
    const inputsHash = sha256Canonical(inputs);
    await inputsLog.append(expireRef, inputs);
    await opts.ledger.appendDecisionChained((prevRecordHash) =>
      signDecisionRecord(
        {
          decider: "verax-operator",
          subject: defer.claims.subject,
          requestHash: defer.claims.requestHash,
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
    await opts.approvals.updateStatus(opts.ref, "expired");
    return { ok: false, reason: "expired" };
  }
  const allowRef = opts.nonce();
  const prior = await inputsLog.get(opts.ref);
  const inputs: DecisionInputs = {
    principal: prior?.principal ?? { brain: snap.brain, scopes: [] },
    inputs: prior?.inputs ?? [],
    approver: { id: opts.approverId, via: "cli" },
  };
  const inputsHash = sha256Canonical(inputs);
  const effectHash = sha256Canonical(effectDescriptor(snap.subject, snap.args));
  await inputsLog.append(allowRef, inputs);
  await opts.ledger.appendDecisionChained((prevRecordHash) =>
    signDecisionRecord(
      {
        decider: "verax-operator",
        subject: defer.claims.subject,
        requestHash: defer.claims.requestHash,
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
  await opts.approvals.updateStatus(opts.ref, "approved");
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
  const path = join(dir, "approval-commands.jsonl");
  if (!existsSync(path)) return;
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  const donePath = join(dir, "approval-commands.applied.jsonl");
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const cmd = JSON.parse(line) as ApprovalCommand;
    await apply(cmd);
    appendFileSync(donePath, `${line}\n`, { encoding: "utf8", mode: 0o600 });
  }
  writeFileSync(path, "", { encoding: "utf8", mode: 0o600 });
  unlinkSync(path);
}
