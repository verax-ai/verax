import type { RailAction } from "../rail/types.ts";

/**
 * The record the screen opens on.
 *
 * Records arrive newest first, and the newest one is often the panel's own
 * read of the ledger. Opening there shows a visitor the screen inspecting
 * itself. The exhibit is the newest record that actually did something --
 * the one carrying an effect row, which is also the only kind that can show
 * evidence. When no record has an effect the newest one stands, because an
 * empty exhibit is still the honest one.
 */
export function exhibitAction(actions: readonly RailAction[]): RailAction | null {
  return actions.find((a) => a.effect != null) ?? actions[0] ?? null;
}

export function exhibitRef(actions: readonly RailAction[]): string | null {
  return exhibitAction(actions)?.record.claims.ref ?? null;
}
