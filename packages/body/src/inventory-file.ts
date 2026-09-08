import { existsSync, readFileSync } from "node:fs";
import { parseInventory, type Inventory } from "../../galaxy/src/inventory.ts";

export type InventoryDoor =
  | { inventory: Inventory }
  | { inventory: null; reason?: string };

export type InventoryHealth = { source: string; takenAtMs: number; agents: number };

/**
 * Read the declared roster. A missing path or missing file is absence.
 * A broken document is still absence, with a reason; no half-filled model.
 */
export function readInventoryFile(path: string | null | undefined): InventoryDoor {
  if (path === undefined || path === null || path.trim() === "") {
    return { inventory: null };
  }
  if (!existsSync(path)) {
    return { inventory: null };
  }
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { inventory: null, reason: "unreadable" };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    return { inventory: null, reason: "invalid-json" };
  }
  const parsed = parseInventory(raw);
  if (!parsed.ok) return { inventory: null, reason: parsed.reason };
  return { inventory: parsed.value };
}

export function inventoryHealth(door: InventoryDoor): InventoryHealth | null {
  if (!door.inventory) return null;
  return {
    source: door.inventory.source,
    takenAtMs: door.inventory.takenAtMs,
    agents: door.inventory.agents.length,
  };
}
