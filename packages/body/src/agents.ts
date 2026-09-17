// One row per agent for the panel's status tab: what each did in a window
// of the ledger, what is waiting on an operator for it, when it last acted,
// and what the roster says about it. A company runs hundreds of agents; the
// operator reads this list, not the records. The window is read from the
// end of the ledger, so the answer costs the window and not the ledger.

import { parseInventory } from "@verax-ai/inventory";
import { loadApprovalsFromDir, type FileLedger } from "@verax-ai/proxy";

import { matchingInputs } from "./inputs-read.ts";
import { readInventoryFile } from "./inventory-file.ts";

export type AgentRow = {
  brain: string;
  decisions: number;
  allowed: number;
  denied: number;
  deferred: number;
  /** Approvals waiting on an operator now, whatever the window. */
  pending: number;
  /** The newest decision in the window, or null when there was none. */
  lastMs: number | null;
  /** What the roster declares; null for an agent the roster does not name. */
  roster: { state: string; label: string; group: string | null } | null;
};

export type AgentsAnswer = {
  fromMs: number;
  toMs: number;
  /** Pending first, then the most recently active; ties by name. */
  agents: AgentRow[];
  /** Decisions in the window whose inputs document was not found or did not match its hash. */
  unattributed: number;
};

export async function agentsWindow(opts: {
  ledger: FileLedger;
  stateDir: string;
  inventoryFile: string | null | undefined;
  fromMs: number;
  toMs: number;
}): Promise<AgentsAnswer> {
  const { rows } = await opts.ledger.decisionsWindow(opts.fromMs, opts.toMs);
  const inputs = (await matchingInputs(opts.stateDir, rows)) as Record<string, { principal?: { brain?: unknown } } | undefined>;
  const byBrain = new Map<string, AgentRow>();
  const rowFor = (brain: string): AgentRow => {
    let row = byBrain.get(brain);
    if (!row) {
      row = { brain, decisions: 0, allowed: 0, denied: 0, deferred: 0, pending: 0, lastMs: null, roster: null };
      byBrain.set(brain, row);
    }
    return row;
  };
  let unattributed = 0;
  for (const d of rows) {
    const ref = d.claims.ref;
    const brain = typeof ref === "string" ? inputs[ref]?.principal?.brain : undefined;
    if (typeof brain !== "string" || brain === "") {
      unattributed += 1;
      continue;
    }
    const row = rowFor(brain);
    row.decisions += 1;
    if (d.claims.decision === "allow") row.allowed += 1;
    else if (d.claims.decision === "deny") row.denied += 1;
    else if (d.claims.decision === "defer") row.deferred += 1;
    if (row.lastMs === null || d.claims.timestampMs > row.lastMs) row.lastMs = d.claims.timestampMs;
  }
  for (const approval of loadApprovalsFromDir(opts.stateDir)) {
    if (approval.status === "pending") rowFor(approval.brain).pending += 1;
  }
  const door = readInventoryFile(opts.inventoryFile);
  const parsed = door.inventory == null ? null : parseInventory(door.inventory);
  if (parsed && parsed.ok) {
    const groups = new Map(parsed.value.groups.map((g) => [g.id, g.label]));
    for (const agent of parsed.value.agents) {
      rowFor(agent.id).roster = {
        state: agent.state,
        label: agent.label,
        group: agent.groupId === null ? null : (groups.get(agent.groupId) ?? agent.groupId),
      };
    }
  }
  const agents = [...byBrain.values()].sort(
    (a, b) => b.pending - a.pending || (b.lastMs ?? -1) - (a.lastMs ?? -1) || a.brain.localeCompare(b.brain),
  );
  return { fromMs: opts.fromMs, toMs: opts.toMs, agents, unattributed };
}
