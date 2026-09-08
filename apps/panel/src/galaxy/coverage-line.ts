import {
  coverage,
  inventoryToGalaxy,
  type GalaxyModel,
  type Inventory,
} from "@verax-ai/galaxy";
import type { Copy } from "../copy.ts";

export const INVENTORY_STALE_MS = 24 * 60 * 60 * 1000;

export function fillCopy(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{([a-zA-Z]+)\}/g, (_, key: string) => String(vars[key] ?? ""));
}

export function formatAge(ageMs: number, copy: Copy): string {
  const sec = Math.max(0, Math.floor(ageMs / 1000));
  if (sec < 60) return fillCopy(copy["time.secondsAgo"], { n: sec });
  const min = Math.floor(sec / 60);
  if (min < 60) return fillCopy(copy["time.minutesAgo"], { n: min });
  const hr = Math.floor(min / 60);
  if (hr < 24) return fillCopy(copy["time.hoursAgo"], { n: hr });
  return fillCopy(copy["time.daysAgo"], { n: Math.floor(hr / 24) });
}

export function coverageLine(
  inventory: Inventory | null,
  ledger: GalaxyModel,
  nowMs: number,
  copy: Copy,
  demo = false,
): { text: string; stale: boolean; bound: boolean } {
  if (demo) {
    // Demo mode never reads /api/inventory, so "not bound" would be a claim
    // about the body that the panel did not check - and one that is false
    // whenever the body is serving a roster.
    return { text: copy["galaxy.inventory.sample"], stale: false, bound: false };
  }
  if (!inventory) {
    return { text: copy["galaxy.inventory.unbound"], stale: false, bound: false };
  }
  const invModel = inventoryToGalaxy(inventory);
  const counted = coverage(ledger, invModel);
  const ageMs = nowMs - inventory.takenAtMs;
  const stale = ageMs > INVENTORY_STALE_MS;
  const ago = formatAge(ageMs, copy);
  const key = stale ? "galaxy.coverage.stale" : "galaxy.coverage";
  return {
    text: fillCopy(copy[key], {
      accountable: counted.accountable,
      total: counted.total,
      source: inventory.source,
      ago,
    }),
    stale,
    bound: true,
  };
}
