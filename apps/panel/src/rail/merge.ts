import type { RailAction } from "./types.ts";

/**
 * The rows the screen holds, with a fresh batch folded in: one row per ref,
 * the incoming one when both have it (its effect may have landed since),
 * newest first. A poll asks the body for what is new since the newest row
 * held, so the batch overlaps the top of the list and this is where the
 * overlap goes.
 */
export function mergeActions(held: RailAction[], incoming: RailAction[]): RailAction[] {
  const byRef = new Map<string, RailAction>();
  const rows: RailAction[] = [];
  const keyOf = (action: RailAction) => action.record.claims.ref ?? `at:${action.record.claims.timestampMs}`;
  for (const action of incoming) byRef.set(keyOf(action), action);
  for (const action of held) {
    const key = keyOf(action);
    if (!byRef.has(key)) byRef.set(key, action);
  }
  for (const action of byRef.values()) rows.push(action);
  rows.sort((a, b) => b.record.claims.timestampMs - a.record.claims.timestampMs);
  return rows;
}
