/**
 * The approvals row on disk is not signed. The terminal, the operator door and
 * the ledger API show it, while a running body approves its own copy. Each of
 * them holds the row to the hashes the signed defer names, here, so a row
 * edited on disk is never what an operator is asked to approve.
 */
import {
  approvalArgsBound,
  loadDecisionRequestHashesFromDir,
  loadSignedForwardedHashesFromDir,
  type ApprovalRow,
} from "@verax-ai/proxy";

/** Reads the decision and inputs files once; the returned check is per row. */
export function boundOnDisk(stateDir: string): (row: ApprovalRow) => boolean {
  const requestHashes = loadDecisionRequestHashesFromDir(stateDir);
  const forwardedHashes = loadSignedForwardedHashesFromDir(stateDir);
  return (row) => {
    const signed = requestHashes.get(row.ref);
    return typeof signed === "string" && signed !== "" && approvalArgsBound(row, signed, forwardedHashes.get(row.ref));
  };
}
