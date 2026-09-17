import { existsSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import {
  approvePending,
  approvalsLogFor,
  createApprovalBudgetGuard,
  enqueueApprovalCommand,
  FileLedger,
  loadApprovalsFromDir,
  loadPolicy,
  type Policy,
} from "@verax-ai/proxy";
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

export async function runApprove(
  argv: string[],
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  writeOut: (s: string) => void = (s) => process.stdout.write(s),
): Promise<number> {
  const rest = argv.slice(1);
  const stateDir = rest[0];
  const given = rest[1];
  if (!stateDir || !given || rest.length !== 2) {
    writeErr("verax approve <stateDir> <ref>\n");
    return 78;
  }
  const resolved = resolveApproveRef(loadApprovalsFromDir(stateDir), given);
  if (!resolved.ok) {
    if (resolved.reason === "ambiguous-ref") {
      writeErr(`ambiguous-ref\n${resolved.candidates.join("\n")}\n`);
      return 78;
    }
    writeErr("approve-unknown-ref\n");
    return 78;
  }
  const ref = resolved.ref;
  let ledger: FileLedger;
  try {
    ledger = new FileLedger(stateDir);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "";
    if (msg.startsWith("ledger-locked")) {
      enqueueApprovalCommand(stateDir, { ref, approverId: operatorName(), atMs: Date.now() });
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
      via: "cli",
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
