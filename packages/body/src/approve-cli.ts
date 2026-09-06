import { userInfo } from "node:os";
import { approvePending, approvalsLogFor, enqueueApprovalCommand, FileLedger, loadApprovalsFromDir } from "@verax-ai/proxy";
import { loadOrCreateSigners } from "./keys.ts";

function operatorName(): string {
  try {
    const name = userInfo().username;
    return name.length > 0 ? name : "unknown";
  } catch {
    return "unknown";
  }
}

export async function runApprove(
  argv: string[],
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  writeOut: (s: string) => void = (s) => process.stdout.write(s),
): Promise<number> {
  const rest = argv.slice(1);
  const stateDir = rest[0];
  const ref = rest[1];
  if (!stateDir || !ref || rest.length !== 2) {
    writeErr("verax approve <stateDir> <ref>\n");
    return 78;
  }
  const pending = loadApprovalsFromDir(stateDir).find((r) => r.ref === ref);
  if (!pending) {
    writeErr("approve-unknown-ref\n");
    return 78;
  }
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
    const result = await approvePending({
      ledger,
      recordSigner: signers.recordSigner,
      now: () => Date.now(),
      nonce: () => crypto.randomUUID(),
      ref,
      approverId: operatorName(),
      policyHash: defer.claims.policyHash,
      approvals,
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
