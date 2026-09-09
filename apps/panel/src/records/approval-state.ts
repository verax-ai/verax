import type { PendingApproval, RailAction } from "../rail/types.ts";

export type ApprovalResolution = "waiting" | "resolved" | "expired" | "not-deferred";

/** Last ledger row for each approval request. A later row overwrites an earlier one. */
export function lastApprovalByRef(rows: readonly PendingApproval[]): Map<string, PendingApproval> {
  const map = new Map<string, PendingApproval>();
  for (const row of rows) map.set(row.ref, row);
  return map;
}

/**
 * The approval row that answers a decision's ref.
 * Prefer a row whose allowRef is the decision, then a row whose own ref is.
 * The last match of that preferred kind wins.
 */
export function approvalForRef(
  rows: readonly PendingApproval[],
  ref: string | null,
): PendingApproval | undefined {
  if (ref === null || ref === "") return undefined;
  let byAllow: PendingApproval | undefined;
  let byRef: PendingApproval | undefined;
  for (const row of rows) {
    if (row.allowRef && row.allowRef === ref) byAllow = row;
    if (row.ref === ref) byRef = row;
  }
  return byAllow ?? byRef;
}

export function resolutionOf(
  action: RailAction,
  approvals: readonly PendingApproval[],
): ApprovalResolution {
  if (action.record.claims.decision !== "defer") return "not-deferred";
  const snap = approvalForRef(approvals, action.record.claims.ref);
  if (!snap) return "waiting";
  if (snap.status === "pending") return "waiting";
  if (snap.status === "approved") return "resolved";
  return "expired";
}
