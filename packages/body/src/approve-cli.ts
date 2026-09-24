import { existsSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import {
  approvePending,
  approvalsLogFor,
  createApprovalBudgetGuard,
  enqueueApprovalCommand,
  FileLedger,
  loadApprovalsFromDir,
  loadPolicy,
  type ApprovalRow,
  type Policy,
} from "@verax-ai/proxy";
import { directoryAccess, stateDirFor, unreadableSentence } from "./install.ts";
import { loadOrCreateSigners } from "./keys.ts";

function policyForApprove(stateDir: string, policyHash: string): Policy | null {
  const fromEnv = process.env.VERAX_POLICY_FILE?.trim();
  if (fromEnv) {
    try {
      return loadPolicy(readFileSync(fromEnv, "utf8"));
    } catch {
      // Fall through to the snapshot the body wrote for this hash.
    }
  }
  const snap = join(stateDir, "policies", `${policyHash}.json`);
  if (!existsSync(snap)) return null;
  try {
    return loadPolicy(JSON.parse(readFileSync(snap, "utf8")) as unknown);
  } catch {
    return null;
  }
}

function operatorName(): string {
  try {
    const name = userInfo().username;
    return name.length > 0 ? name : "unknown";
  } catch {
    return "unknown";
  }
}

export function resolveApproveRef(
  pending: { ref: string; status?: string }[],
  given: string,
):
  | { ok: true; ref: string }
  | { ok: false; reason: "unknown-ref" | "ambiguous-ref"; candidates: string[] } {
  const open = pending.filter((r) => r.status === "pending" || r.status === undefined);
  const exact = open.find((r) => r.ref === given);
  if (exact) return { ok: true, ref: exact.ref };
  const suffix = `:${given}`;
  const hits = open.filter((r) => r.ref.endsWith(suffix)).map((r) => r.ref);
  const unique = [...new Set(hits)].sort();
  if (unique.length === 1) return { ok: true, ref: unique[0]! };
  if (unique.length > 1) return { ok: false, reason: "ambiguous-ref", candidates: unique };
  return { ok: false, reason: "unknown-ref", candidates: [] };
}

const NEEDS_TERMINAL =
  "verax approve needs a terminal: it shows what is waiting and asks you to type the amount back\n";

function minorUnits(row: ApprovalRow): number | null {
  if (typeof row.amount === "number") return row.amount;
  const fromArgs = row.args.amountMinor;
  return typeof fromArgs === "number" ? fromArgs : null;
}

function heldLine(row: ApprovalRow): string {
  const payee = typeof row.payee === "string" ? row.payee : String(row.args.payee ?? "");
  const currency = typeof row.currency === "string" ? row.currency : String(row.args.currency ?? "");
  const reference = typeof row.args.reference === "string" ? row.args.reference : "";
  const amount = minorUnits(row);
  const prefix = row.requestHash.slice(0, 12);
  return `held tool=${row.subject} payee=${payee} amount=${amount === null ? "" : String(amount)} currency=${currency} reference=${reference} requestHash=${prefix}\n`;
}

function readTypedAmount(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.once("line", (line) => {
      rl.close();
      resolve(line);
    });
  });
}

export type ApproveIo = {
  isTTY: boolean;
  ask: (prompt: string) => Promise<string>;
};

function defaultApproveIo(): ApproveIo {
  return {
    isTTY: Boolean(process.stdin.isTTY),
    ask: () => readTypedAmount(),
  };
}

export async function runApprove(
  argv: string[],
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  writeOut: (s: string) => void = (s) => process.stdout.write(s),
  io?: ApproveIo,
): Promise<number> {
  const terminal = io ?? defaultApproveIo();
  const rest = argv.slice(1).filter((a) => a !== "--from-script");
  const fromScript = argv.includes("--from-script");
  let stateDir = rest[0];
  let given = rest[1];
  if (rest.length === 1 && stateDir) {
    const installed = stateDirFor(process.platform);
    const access = directoryAccess(installed);
    if (access === "unreadable") {
      writeErr(`${unreadableSentence(installed)}\n`);
      return 77;
    }
    if (access === "ok") {
      given = stateDir;
      stateDir = installed;
    }
  }
  if (!stateDir || !given || (rest.length !== 2 && !(rest.length === 1 && stateDir && given))) {
    writeErr("verax approve <stateDir> <ref>\n");
    return 78;
  }
  if (directoryAccess(stateDir) === "unreadable") {
    writeErr(`${unreadableSentence(stateDir)}\n`);
    return 77;
  }
  // A non-interactive shell can read the state directory. Without a person
  // at a terminal, or an explicit --from-script, nothing is approved.
  if (!fromScript && !terminal.isTTY) {
    writeErr(NEEDS_TERMINAL);
    return 78;
  }
  const rows = loadApprovalsFromDir(stateDir);
  const resolved = resolveApproveRef(rows, given);
  if (!resolved.ok) {
    if (resolved.reason === "ambiguous-ref") {
      writeErr(`ambiguous-ref\n${resolved.candidates.join("\n")}\n`);
      return 78;
    }
    writeErr("approve-unknown-ref\n");
    return 78;
  }
  const ref = resolved.ref;
  const via = fromScript ? "cli-script" : "cli";
  // The amount is checked before the ledger is opened. A running body holds
  // the lock, and queueing first would approve without the person ever typing it.
  if (!fromScript) {
    const waiting = rows.find((row) => row.ref === ref);
    if (!waiting) {
      writeErr("approve-unknown-ref\n");
      return 78;
    }
    const expected = minorUnits(waiting);
    const shown = expected === null ? "" : String(expected);
    writeOut(heldLine(waiting));
    writeOut("Type the amount in minor units:\n");
    const typed = (await terminal.ask("Type the amount in minor units:\n")).trim();
    if (typed !== shown) {
      writeErr("approve-amount-mismatch\n");
      return 1;
    }
  }
  let ledger: FileLedger;
  try {
    ledger = new FileLedger(stateDir);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "";
    if (msg.startsWith("ledger-locked")) {
      enqueueApprovalCommand(stateDir, { ref, approverId: operatorName(), atMs: Date.now(), via });
      writeOut("approve-queued\n");
      return 0;
    }
    writeErr(`approve-failed:${msg.split("\n")[0] ?? "unknown"}\n`);
    return 1;
  }
  try {
    const signers = loadOrCreateSigners(stateDir);
    const approvals = approvalsLogFor(ledger);
    const decisions = await ledger.decisions();
    const defer = decisions.find((d) => d.claims.ref === ref && d.claims.decision === "defer");
    if (!defer) {
      writeErr("approve-unknown-ref\n");
      return 78;
    }
    const policy = policyForApprove(stateDir, defer.claims.policyHash);
    const result = await approvePending({
      ledger,
      recordSigner: signers.recordSigner,
      now: () => Date.now(),
      nonce: () => crypto.randomUUID(),
      ref,
      approverId: operatorName(),
      via,
      policyHash: defer.claims.policyHash,
      approvals,
      ...(policy
        ? { budgetGuard: createApprovalBudgetGuard({ policy, approvals, now: () => Date.now() }) }
        : {}),
    });
    if (!result.ok) {
      writeErr(`approve-${result.reason}\n`);
      return result.reason === "expired" ? 2 : 1;
    }
    writeOut(`approved:${result.allowRef}\n`);
    return 0;
  } catch (err) {
    writeErr(`approve-failed:${err instanceof Error ? err.message : "unknown"}\n`);
    return 1;
  } finally {
    ledger.close();
  }
}
