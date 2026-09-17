import type { PendingApproval, RailAction } from "../rail/types.ts";
import { kindOf, type RecordKind } from "./line.ts";

/**
 * How the records list is narrowed. Every field is optional; an empty
 * string is the same as absent, which is what a select's "all" option and
 * an emptied search box hand over.
 */
export type RecordFilter = {
  agent?: string;
  tool?: string;
  kind?: RecordKind | "";
  ref?: string;
};

export function filterActive(filter: RecordFilter): boolean {
  return Boolean(filter.agent || filter.tool || filter.kind || (filter.ref ?? "").trim());
}

/**
 * The rows on screen that match the filter, in the order they came. The
 * outcome is read through kindOf, the same source as the status column, so
 * a row filed under "waiting" is the row the column calls waiting.
 */
export function filterActions(
  actions: readonly RailAction[],
  pending: readonly PendingApproval[],
  filter: RecordFilter,
): RailAction[] {
  const ref = (filter.ref ?? "").trim().toLowerCase();
  return actions.filter((action) => {
    if (filter.agent && action.inputs?.principal.brain !== filter.agent) return false;
    if (filter.tool && action.record.claims.subject !== filter.tool) return false;
    if (filter.kind && kindOf(action, pending) !== filter.kind) return false;
    if (ref !== "" && !(action.record.claims.ref ?? "").toLowerCase().includes(ref)) return false;
    return true;
  });
}
