import { measured, unmeasured, type Measured } from "./measured.ts";
import type { GalaxyAgent, GalaxyModel, GalaxyPlanet, GalaxyStar } from "./model.ts";

export type InventoryState = "live" | "stale" | "failed" | "unmonitored" | "retired" | "unknown";

export type InventoryAgent = {
  id: string;
  label: string;
  groupId: string | null;
  kind: string;
  /** null = the source does not know when this agent last ran */
  lastRunMs: number | null;
  state: InventoryState;
  note?: string;
};

export type InventoryGroup = { id: string; label: string };

/** A pulse the roster does not name: the record and the fact have come apart. */
export type InventoryOrphan = { id: string; lastRunMs: number | null; why: string };

export type Inventory = {
  takenAtMs: number;
  /** Name of whoever produced the inventory. Measured.source carries this. */
  source: string;
  groups: InventoryGroup[];
  agents: InventoryAgent[];
  orphans: InventoryOrphan[];
};

export type InventoryParse =
  | { ok: true; value: Inventory }
  | { ok: false; reason: string };

export type Coverage = { total: number; accountable: number };

const STATES: ReadonlySet<string> = new Set([
  "live",
  "stale",
  "failed",
  "unmonitored",
  "retired",
  "unknown",
]);

const NO_FRESHNESS = new Set<InventoryState>(["unmonitored", "unknown"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function finiteMs(value: unknown, path: string): { ok: true; value: number } | { ok: false; reason: string } {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return { ok: false, reason: `invalid:${path}` };
  }
  return { ok: true, value };
}

function optionalMs(
  value: unknown,
  path: string,
): { ok: true; value: number | null } | { ok: false; reason: string } {
  if (value === null) return { ok: true, value: null };
  return finiteMs(value, path);
}

function nonEmptyString(value: unknown, path: string): { ok: true; value: string } | { ok: false; reason: string } {
  if (typeof value !== "string" || value === "") {
    return { ok: false, reason: `invalid:${path}` };
  }
  return { ok: true, value };
}

function parseGroup(value: unknown, path: string): { ok: true; value: InventoryGroup } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: `invalid:${path}` };
  const id = nonEmptyString(value.id, `${path}.id`);
  if (!id.ok) return id;
  const label = nonEmptyString(value.label, `${path}.label`);
  if (!label.ok) return label;
  return { ok: true, value: { id: id.value, label: label.value } };
}

function parseAgent(value: unknown, path: string): { ok: true; value: InventoryAgent } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: `invalid:${path}` };
  const id = nonEmptyString(value.id, `${path}.id`);
  if (!id.ok) return id;
  const label = nonEmptyString(value.label, `${path}.label`);
  if (!label.ok) return label;
  if (value.groupId !== null && (typeof value.groupId !== "string" || value.groupId === "")) {
    return { ok: false, reason: `invalid:${path}.groupId` };
  }
  const kind = nonEmptyString(value.kind, `${path}.kind`);
  if (!kind.ok) return kind;
  const lastRunMs = optionalMs(value.lastRunMs, `${path}.lastRunMs`);
  if (!lastRunMs.ok) return lastRunMs;
  if (typeof value.state !== "string" || !STATES.has(value.state)) {
    return { ok: false, reason: `invalid:${path}.state` };
  }
  const agent: InventoryAgent = {
    id: id.value,
    label: label.value,
    groupId: value.groupId as string | null,
    kind: kind.value,
    lastRunMs: lastRunMs.value,
    state: value.state as InventoryState,
  };
  if (value.note !== undefined) {
    if (typeof value.note !== "string") return { ok: false, reason: `invalid:${path}.note` };
    agent.note = value.note;
  }
  return { ok: true, value: agent };
}

function parseOrphan(
  value: unknown,
  path: string,
): { ok: true; value: InventoryOrphan } | { ok: false; reason: string } {
  if (!isRecord(value)) return { ok: false, reason: `invalid:${path}` };
  const id = nonEmptyString(value.id, `${path}.id`);
  if (!id.ok) return id;
  const lastRunMs = optionalMs(value.lastRunMs, `${path}.lastRunMs`);
  if (!lastRunMs.ok) return lastRunMs;
  const why = nonEmptyString(value.why, `${path}.why`);
  if (!why.ok) return why;
  return { ok: true, value: { id: id.value, lastRunMs: lastRunMs.value, why: why.value } };
}

/**
 * Strict parse. A single broken field fails the whole document; nothing
 * half-filled is returned.
 */
export function parseInventory(raw: unknown): InventoryParse {
  if (!isRecord(raw)) return { ok: false, reason: "invalid:root" };
  const takenAtMs = finiteMs(raw.takenAtMs, "takenAtMs");
  if (!takenAtMs.ok) return takenAtMs;
  const source = nonEmptyString(raw.source, "source");
  if (!source.ok) return source;
  if (!Array.isArray(raw.groups)) return { ok: false, reason: "invalid:groups" };
  if (!Array.isArray(raw.agents)) return { ok: false, reason: "invalid:agents" };
  if (!Array.isArray(raw.orphans)) return { ok: false, reason: "invalid:orphans" };

  const groups: InventoryGroup[] = [];
  const groupIds = new Set<string>();
  for (let i = 0; i < raw.groups.length; i += 1) {
    const row = parseGroup(raw.groups[i], `groups[${i}]`);
    if (!row.ok) return row;
    if (groupIds.has(row.value.id)) return { ok: false, reason: `invalid:groups[${i}].id` };
    groupIds.add(row.value.id);
    groups.push(row.value);
  }

  const agents: InventoryAgent[] = [];
  const agentIds = new Set<string>();
  for (let i = 0; i < raw.agents.length; i += 1) {
    const row = parseAgent(raw.agents[i], `agents[${i}]`);
    if (!row.ok) return row;
    if (agentIds.has(row.value.id)) return { ok: false, reason: `invalid:agents[${i}].id` };
    agentIds.add(row.value.id);
    agents.push(row.value);
  }

  const orphans: InventoryOrphan[] = [];
  const orphanIds = new Set<string>();
  for (let i = 0; i < raw.orphans.length; i += 1) {
    const row = parseOrphan(raw.orphans[i], `orphans[${i}]`);
    if (!row.ok) return row;
    if (orphanIds.has(row.value.id)) return { ok: false, reason: `invalid:orphans[${i}].id` };
    orphanIds.add(row.value.id);
    orphans.push(row.value);
  }

  return {
    ok: true,
    value: { takenAtMs: takenAtMs.value, source: source.value, groups, agents, orphans },
  };
}

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
