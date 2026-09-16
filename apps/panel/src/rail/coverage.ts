import type { Inventory } from "@verax-ai/inventory";
import type { Copy } from "../copy.ts";
import { fillCopy } from "../fill.ts";

export const INVENTORY_STALE_MS = 24 * 60 * 60 * 1000;

export function formatAge(ageMs: number, copy: Copy): string {
  const sec = Math.max(0, Math.floor(ageMs / 1000));
  if (sec < 60) return fillCopy(copy["time.secondsAgo"], { n: sec });
  const min = Math.floor(sec / 60);
  if (min < 60) return fillCopy(copy["time.minutesAgo"], { n: min });
  const hr = Math.floor(min / 60);
  if (hr < 24) return fillCopy(copy["time.hoursAgo"], { n: hr });
  return fillCopy(copy["time.daysAgo"], { n: Math.floor(hr / 24) });
}

/**
 * One sentence about the roster the body serves: how many of the agents it
 * declares have a decision in this ledger, whose roster it is, and how old the
 * snapshot is. "Accountable" is the intersection of the roster's agent ids and
 * the brains the ledger names; nothing is counted that neither document
 * states, and an agent counts once however many decisions name it.
 */
export function coverageLine(
  inventory: Inventory | null,
  brains: readonly string[],
  nowMs: number,
  copy: Copy,
  demo = false,
): { text: string; stale: boolean; bound: boolean } {
  if (demo) {
    // Demo mode never reads /api/inventory, so "not bound" would be a claim
    // about the body that the panel did not check - and one that is false
    // whenever the body is serving a roster.
    return { text: copy["inventory.sample"], stale: false, bound: false };
  }
  if (!inventory) {
    return { text: copy["inventory.unbound"], stale: false, bound: false };
  }
  const named = new Set(brains);
  const accountable = inventory.agents.filter((a) => named.has(a.id)).length;
  const ageMs = nowMs - inventory.takenAtMs;
  const stale = ageMs > INVENTORY_STALE_MS;
  const key = stale ? "inventory.coverage.stale" : "inventory.coverage";
  return {
    text: fillCopy(copy[key], {
      accountable,
      total: inventory.agents.length,
      source: inventory.source,
      ago: formatAge(ageMs, copy),
    }),
    stale,
    bound: true,
  };
}
