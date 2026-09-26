export type PinnedApproval = { ref: string; requestHash: string };

/**
 * Yes may send only the row Approve was pressed on. A different ref or
 * requestHash is not a target.
 */
export function pinnedApproveTarget(
  captured: PinnedApproval | null,
  row: PinnedApproval,
): PinnedApproval | null {
  if (!captured) return null;
  if (captured.ref !== row.ref || captured.requestHash !== row.requestHash) return null;
  return { ref: captured.ref, requestHash: captured.requestHash };
}
