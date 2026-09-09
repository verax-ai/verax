import type { PendingApproval, RailAction } from "../rail/types.ts";

export type DecisionPair = {
  defer: RailAction | null;
  resolution: RailAction | null;
};

function byRef(actions: readonly RailAction[], ref: string | null | undefined): RailAction | null {
  if (!ref) return null;
  return actions.find((a) => a.record.claims.ref === ref) ?? null;
}

/**
 * Pair a defer with its operator resolution from the ledger itself:
 * approval.allowRef, inputs.approver.resolves, or a shared requestHash.
 * Contest can refine this; it is not required to see both records.
 */
export function pairFromLedger(
  actions: readonly RailAction[],
  selected: RailAction | null,
  approvals: readonly PendingApproval[] = [],
): DecisionPair {
  if (!selected) return { defer: null, resolution: null };
  const ref = selected.record.claims.ref;
  const requestHash = selected.record.claims.requestHash;
  const ownResolves = selected.inputs?.approver?.resolves;

  if (selected.record.claims.decision === "defer" && ref) {
    const snap = [...approvals].reverse().find((p) => p.ref === ref);
    const resolution =
      byRef(actions, snap?.allowRef) ??
      actions.find((a) => a.inputs?.approver?.resolves === ref) ??
      (typeof requestHash === "string"
        ? actions.find((a) => a.record.claims.ref !== ref && a.record.claims.requestHash === requestHash)
        : null) ??
      null;
    return { defer: selected, resolution };
  }

  const fromApprover = byRef(actions, ownResolves);
  if (fromApprover) return { defer: fromApprover, resolution: selected };

  const snap = approvals.find((p) => p.allowRef && p.allowRef === ref);
  if (snap) return { defer: byRef(actions, snap.ref), resolution: selected };

  if (typeof requestHash === "string") {
    const defer = actions.find(
      (a) => a.record.claims.decision === "defer" && a.record.claims.requestHash === requestHash,
    );
    if (defer) return { defer, resolution: selected };
  }

  return { defer: null, resolution: null };
}
