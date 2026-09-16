/**
 * The declared roster document: what it says, and how to read it.
 *
 * It lives in its own package because two very different readers need it:
 * the body, which serves roster health from a file on disk, and the galaxy,
 * which draws it. The galaxy carries three.js and React; the body must not.
 */
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
