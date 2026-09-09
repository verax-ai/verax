import { fillCopy } from "../galaxy/coverage-line.ts";
import type { Copy } from "../copy.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { lastApprovalByRef } from "./approval-state.ts";

export type RecordCounts = {
  decisions: number;
  denied: number;
  pending: number;
  unmatched: number | null;
};

function matchedRefs(report: ReconcileCardReport): Set<string> {
  const out = new Set<string>();
  for (const row of report.matched ?? []) {
    const ref = row.effect?.ref;
    if (typeof ref === "string" && ref !== "") out.add(ref);
  }
  return out;
}

export function countRecords(
  actions: readonly RailAction[],
  pending: readonly PendingApproval[],
  reconcile: ReconcileCardReport | null,
): RecordCounts {
  const decisions = actions.length;
  const denied = actions.filter((a) => a.record.claims.decision === "deny").length;
  const open = [...lastApprovalByRef(pending).values()].filter((p) => p.status === "pending").length;
  if (reconcile === null) {
    return { decisions, denied, pending: open, unmatched: null };
  }
  const matched = matchedRefs(reconcile);
  const unmatched = actions.filter((a) => {
    if (a.effect?.row.effectClass !== "spend") return false;
    const ref = a.effect.row.ref;
    return typeof ref === "string" && ref !== "" && !matched.has(ref);
  }).length;
  return { decisions, denied, pending: open, unmatched };
}

export function summarySentence(copy: Copy, counts: RecordCounts): string {
  if (counts.decisions === 0) return copy["summary.empty"];
  const vars = {
    decisions: counts.decisions,
    denied: counts.denied,
    pending: counts.pending,
  };
  if (counts.unmatched === null) {
    return fillCopy(copy["summary.line.noStatement"], vars);
  }
  return fillCopy(copy["summary.line"], { ...vars, unmatched: counts.unmatched });
}
