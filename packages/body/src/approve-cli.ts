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
  TERMINAL_CONTROL_CLASS,
  type ApprovalRow,
  type Policy,
} from "@verax-ai/proxy";
import { EX_CONFIG } from "./config.ts";
import { cliCodeCheckPassedAlready, defaultElevated, directoryAccess, elevatedCommandCodeRefusal, stateDirFor, SystemToolError, unreadableSentence, windowsProgramDataRefusal } from "./install.ts";
import { loadOrCreateSigners } from "./keys.ts";

function policyFromSnapshot(stateDir: string, policyHash: string): Policy | null {
  const snap = join(stateDir, "policies", `${policyHash}.json`);
  if (!existsSync(snap)) return null;
  try {
    return loadPolicy(JSON.parse(readFileSync(snap, "utf8")) as unknown);
  } catch {
    return null;
  }
}

function policyForApprove(stateDir: string, policyHash: string, env: NodeJS.ProcessEnv, elevated: boolean): Policy | null {
  // An elevated approve inherits the user's environment. The snapshot the body
  // wrote is the policy that held the call. The environment is not.
  // When not elevated, the environment file is that policy only when its
  // canonical hash is the defer's policyHash. Any other file falls through
  // to the snapshot.
  if (!elevated) {
    const fromEnv = env.VERAX_POLICY_FILE?.trim();
    if (fromEnv) {
      try {
        const loaded = loadPolicy(readFileSync(fromEnv, "utf8"));
        if (loaded.hash === policyHash) return loaded;
      } catch {
        // Fall through to the snapshot the body wrote for this hash.
      }
    }
  }
  return policyFromSnapshot(stateDir, policyHash);
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

function integerMinor(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

/** An integer minor-unit amount, or null when the stored amount cannot be read as one. */
function minorUnits(row: ApprovalRow): number | null {
  if (typeof row.amount === "number") return integerMinor(row.amount);
  return integerMinor(row.args.amountMinor);
}

const HELD_CONTROL = new RegExp(`[${TERMINAL_CONTROL_CLASS}]`, "gu");

/**
 * One argument per line, JSON-quoted, so a value cannot look like another field. JSON leaves
 * U+0085, U+FEFF, U+2028 and U+2029 as they are, so every terminal-control code point is
 * written as a \u escape as well.
 */
function quotedField(name: string, value: unknown): string {
  const text = typeof value === "string" ? value : value === undefined || value === null ? "" : JSON.stringify(value);
  const quoted = JSON.stringify(text).replace(
    HELD_CONTROL,
    (ch) => `\\u${ch.codePointAt(0)!.toString(16).padStart(4, "0")}`,
  );
  return `${name}: ${quoted}\n`;
}

function spendPrompt(row: ApprovalRow, amount: number): string {
  const payee = typeof row.payee === "string" ? row.payee : String(row.args.payee ?? "");
  const currency = typeof row.currency === "string" ? row.currency : String(row.args.currency ?? "");
  const reference = typeof row.args.reference === "string" ? row.args.reference : "";
  return [
    quotedField("tool", row.subject),
    quotedField("payee", payee),
    quotedField("amount", String(amount)),
    quotedField("currency", currency),
    quotedField("reference", reference),
    quotedField("requestHash", row.requestHash.slice(0, 12)),
  ].join("");
}

function argumentPrompt(row: ApprovalRow): string {
  const lines = [quotedField("tool", row.subject)];
  for (const key of Object.keys(row.args).sort()) lines.push(quotedField(key, row.args[key]));
  return lines.join("");
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

export type ApproveHooks = {
  elevated?: () => boolean;
  codeProbe?: (dir: string) => boolean;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
};

export async function runApprove(
  argv: string[],
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  writeOut: (s: string) => void = (s) => process.stdout.write(s),
  io?: ApproveIo,
  hooks?: ApproveHooks,
): Promise<number> {
  const platform = hooks?.platform ?? process.platform;
  const env = hooks?.env ?? process.env;
  let isElevated = false;
  try {
    isElevated = hooks?.elevated ? hooks.elevated() : defaultElevated(platform);
  } catch (err) {
    if (err instanceof SystemToolError) {
      writeErr(`${err.message}\n`);
      return EX_CONFIG;
    }
    throw err;
  }
  if (isElevated && !cliCodeCheckPassedAlready()) {
    const refusal = elevatedCommandCodeRefusal(platform, env, hooks?.codeProbe);
    if (refusal) {
      writeErr(refusal.endsWith("\n") ? refusal : `${refusal}\n`);
      return EX_CONFIG;
    }
  }
  const terminal = io ?? defaultApproveIo();
  const rest = argv.slice(1).filter((a) => a !== "--from-script");
  const fromScript = argv.includes("--from-script");
  let stateDir = rest[0];
  let given = rest[1];
  if (rest.length === 1 && stateDir) {
    let installed: string;
    try {
      if (platform === "win32") {
        const rootRefusal = windowsProgramDataRefusal(env);
        if (rootRefusal) {
          writeErr(`${rootRefusal}\n`);
          return 78;
        }
      }
      installed = stateDirFor(platform, env);
    } catch (err) {
      writeErr(`${err instanceof SystemToolError ? err.message : "refusing install root"}\n`);
      return 78;
    }
    const access = directoryAccess(installed);
    if (access === "unreadable") {
      writeErr(`${unreadableSentence(installed, "approve")}\n`);
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
    writeErr(`${unreadableSentence(stateDir, "approve")}\n`);
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
    if (waiting.subject === "spend") {
      const expected = minorUnits(waiting);
      if (expected === null) {
        writeErr("approve-amount-unreadable\n");
        return 1;
      }
      writeOut(spendPrompt(waiting, expected));
      writeOut("Type the amount in minor units:\n");
      const typed = (await terminal.ask("Type the amount in minor units:\n")).trim();
      if (typed !== String(expected)) {
        writeErr("approve-amount-mismatch\n");
        return 1;
      }
    } else {
      writeOut(argumentPrompt(waiting));
      writeOut("Type yes:\n");
      const typed = (await terminal.ask("Type yes:\n")).trim();
      if (typed !== "yes") {
        writeErr("approve-confirm-mismatch\n");
        return 1;
      }
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
    const policy = policyForApprove(stateDir, defer.claims.policyHash, env, isElevated);
    const waitingSubject = rows.find((row) => row.ref === ref)?.subject;
    if (!policy && waitingSubject === "spend") {
      writeErr("approve-policy-missing\n");
      return 1;
    }
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
        ? { budgetGuard: createApprovalBudgetGuard({ policy, approvals, now: () => Date.now(), ledger }) }
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
