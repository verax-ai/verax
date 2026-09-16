import { measured, unmeasured, type Measured } from "./measured.ts";
import type { GalaxyAgent, GalaxyModel, GalaxyPlanet, GalaxyStar } from "./model.ts";
import type { Inventory, InventoryAgent, InventoryState } from "@verax-ai/inventory";

// The document itself is read in @verax-ai/inventory; this file turns it into
// a galaxy. Re-exported so every caller keeps one import.
export {
  parseInventory,
  type Inventory,
  type InventoryAgent,
  type InventoryGroup,
  type InventoryOrphan,
  type InventoryParse,
  type InventoryState,
} from "@verax-ai/inventory";

export type Coverage = { total: number; accountable: number };

const NO_FRESHNESS = new Set<InventoryState>(["unmonitored", "unknown"]);

function agentLastAct(agent: InventoryAgent, source: string): Measured<number> {
  if (NO_FRESHNESS.has(agent.state) || agent.lastRunMs === null) {
    return unmeasured(agent.state);
  }
  return measured(agent.lastRunMs, `inventory:${source}.lastRun`);
}

/** Declaration only. takenAtMs does not enter the model. No witness is attached. */
export function inventoryToGalaxy(inventory: Inventory): GalaxyModel {
  const tag = inventory.source;
  const planets: GalaxyPlanet[] = inventory.groups.map((group) => {
    const members = inventory.agents.filter((a) => a.groupId === group.id);
    const runs = members
      .map((a) => a.lastRunMs)
      .filter((ms): ms is number => ms !== null);
    return {
      id: group.id,
      label: group.label,
      size: measured(members.length, `inventory:${tag}.agents`),
      freshness:
        runs.length > 0 ? measured(Math.max(...runs), `inventory:${tag}.lastRun`) : unmeasured("no lastRun"),
    };
  });

  const agents: GalaxyAgent[] = inventory.agents.map((agent) => ({
    id: agent.id,
    label: agent.label,
    planetId: agent.groupId,
    lastActMs: agentLastAct(agent, tag),
  }));

  const stars: GalaxyStar[] = inventory.orphans.map((orphan) => ({
    id: orphan.id,
    planetId: null,
    at: orphan.lastRunMs ?? 0,
    kind: orphan.why,
    flag: "ghost",
  }));

  return {
    core: { pulse: unmeasured("inventory"), label: tag },
    planets,
    stars,
    agents,
    edges: [],
  };
}

/**
 * Ledger measurements win. Planet membership may come from the inventory.
 * Inventory-only agents stay unmeasured. Ledger-only agents are unchanged.
 */
export function mergeGalaxy(fromLedger: GalaxyModel, fromInventory: GalaxyModel): GalaxyModel {
  const planets: GalaxyPlanet[] = [];
  const planetSeen = new Set<string>();
  for (const planet of fromLedger.planets) {
    planetSeen.add(planet.id);
    planets.push(planet);
  }
  for (const planet of fromInventory.planets) {
    if (planetSeen.has(planet.id)) continue;
    planets.push(planet);
  }

  const invAgents = new Map(fromInventory.agents.map((a) => [a.id, a]));
  const agents: GalaxyAgent[] = [];
  const agentSeen = new Set<string>();
  for (const agent of fromLedger.agents) {
    agentSeen.add(agent.id);
    const inv = invAgents.get(agent.id);
    agents.push(inv && inv.planetId ? { ...agent, planetId: inv.planetId } : agent);
  }
  for (const agent of fromInventory.agents) {
    if (agentSeen.has(agent.id)) continue;
    agents.push(agent);
  }

  const stars: GalaxyStar[] = [];
  const starSeen = new Set<string>();
  for (const star of fromLedger.stars) {
    starSeen.add(star.id);
    stars.push(star);
  }
  for (const star of fromInventory.stars) {
    if (starSeen.has(star.id)) continue;
    stars.push(star);
  }

  return {
    core: fromLedger.core,
    planets,
    stars,
    agents,
    edges: fromLedger.edges,
  };
}

/** Intersection of the two agent id sets. Do not call when there is no inventory. */
export function coverage(fromLedger: GalaxyModel, fromInventory: GalaxyModel): Coverage {
  const ledgerIds = new Set(fromLedger.agents.map((a) => a.id));
  let accountable = 0;
  for (const agent of fromInventory.agents) {
    if (ledgerIds.has(agent.id)) accountable += 1;
  }
  return { total: fromInventory.agents.length, accountable };
}

export function emptyGalaxy(label = "body"): GalaxyModel {
  return {
    core: { pulse: unmeasured("no heartbeat"), label },
    planets: [],
    stars: [],
    agents: [],
    edges: [],
  };
}
