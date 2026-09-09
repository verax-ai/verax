import type { RailAction } from "../rail/types.ts";

/**
 * Subjects the panel produces by asking the ledger about itself. Opening on
 * one shows a visitor the screen inspecting itself instead of an account of
 * something that happened, and the panel writes one on every visit, so it is
 * reliably the newest record in the ledger.
 */
const SELF_INSPECTION = /^audit\./;

/**
 * The record the screen opens on: the newest outward record that carries an
 * effect row, which is also the only kind that can show evidence. Falling
 * back through the newest outward record to the newest record of all, so a
 * ledger holding nothing but reads still opens on something.
 */
export function exhibitAction(actions: readonly RailAction[]): RailAction | null {
  const outward = actions.filter((a) => !SELF_INSPECTION.test(a.record.claims.subject));
  return outward.find((a) => a.effect != null) ?? outward[0] ?? actions[0] ?? null;
}

export function exhibitRef(actions: readonly RailAction[]): string | null {
  return exhibitAction(actions)?.record.claims.ref ?? null;
}
