import { measured, unmeasured, type GalaxyModel, type StarFlag, type WitnessMark } from "@verax-ai/galaxy";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { RailAction } from "../rail/types.ts";

export type GalaxyHealth = {
  heartbeat?: { atMs: number; lastDecisionN?: number; lastEffectN?: number } | null;
  lastDecisionMs?: number | null;
} | null;

/**
 * Same material as `tenantKey`: iss + sub (brain). Hex digest stays on the body.
 *
 * A token with no `iss` names no tenant. Grouping those records by brain would
 * draw a planet for something nobody measured - and give it the brain's own
 * name, so one word labelled two different bodies on one screen. With no
 * issuer there is no planet: the records sit in the unassigned cloud and the
 * agent is still there to be seen.
 */
export function tenantGroup(principal: { brain?: string; iss?: string } | null | undefined): string | null {
  if (!principal || typeof principal.brain !== "string" || principal.brain === "") return null;
  if (typeof principal.iss !== "string" || principal.iss === "") return null;
  return `${principal.iss}\u001f${principal.brain}`;
}

function ghostRefs(report: ReconcileCardReport | null): Set<string> {
  const out = new Set<string>();
  if (!report) return out;
  for (const row of report.ghost) {
    if (typeof row === "string" && row !== "") out.add(row);
    else if (row && typeof row === "object" && "ref" in row && typeof (row as { ref: unknown }).ref === "string") {
      out.add((row as { ref: string }).ref);
    }
  }
  return out;
}

function starFlag(action: RailAction, ghosts: Set<string>): StarFlag | undefined {
  const ref = action.record.claims.ref;
  const reason = action.record.claims.reasonCode;
  if (ref && ghosts.has(ref)) return "ghost";
  if (reason === "spend-reauth-required") return "reauth";
  if (action.record.claims.decision === "deny") return "deny";
  return undefined;
}

function corePulse(health: GalaxyHealth): GalaxyModel["core"]["pulse"] {
  const at = health?.heartbeat?.atMs;
  if (typeof at === "number" && Number.isFinite(at)) {
    return measured(1, "healthz.heartbeat.atMs");
  }
  const last = health?.lastDecisionMs;
  if (typeof last === "number" && Number.isFinite(last)) {
    return measured(1, "healthz.lastDecisionMs");
  }
  return unmeasured("no heartbeat");
}

function witnessOf(actions: RailAction[]): WitnessMark | undefined {
  const marks = actions.map((a) => a.witnessClass ?? a.effect?.witnessClass ?? null);
  if (marks.some((m) => m === "same-org")) return "same-org";
  if (marks.some((m) => m === "self")) return "self";
  return undefined;
}

/**
 * Signed ledger → galaxy model. A missing tenant does not invent a planet;
 * those stars sit in the unassigned cloud (`planetId: null`).
 */
export function ledgerToGalaxy(
  actions: readonly RailAction[],
  health: GalaxyHealth,
  reconcile: ReconcileCardReport | null = null,
): GalaxyModel {
  const ghosts = ghostRefs(reconcile);
  const planets = new Map<string, { label: string; n: number; last: number }>();
  const agents = new Map<string, { last: number; rows: RailAction[] }>();
  const stars: GalaxyModel["stars"] = [];
  const edges: GalaxyModel["edges"] = [];

  for (const a of actions) {
    const ref = a.record.claims.ref;
    const at = a.record.claims.timestampMs;
    const group = tenantGroup(a.inputs?.principal ?? null);
    const brain = a.inputs?.principal.brain ?? null;

    if (ref) {
      stars.push({
        id: ref,
        planetId: group,
        at,
        kind: a.record.claims.decision,
        flag: starFlag(a, ghosts),
      });
    }

    if (group) {
      const prev = planets.get(group);
      const label = a.inputs?.principal.iss
        ? `${a.inputs.principal.iss} / ${a.inputs.principal.brain}`
        : a.inputs?.principal.brain ?? group;
      planets.set(group, {
        label,
        n: (prev?.n ?? 0) + 1,
        last: Math.max(prev?.last ?? 0, at),
      });
    }

    if (brain) {
      const prev = agents.get(brain);
      agents.set(brain, {
        last: Math.max(prev?.last ?? 0, at),
        rows: [...(prev?.rows ?? []), a],
      });
      if (ref) edges.push({ fromId: `agent:${brain}`, toId: ref, kind: "acted" });
    }
  }

  return {
    core: { pulse: corePulse(health), label: "body" },
    planets: [...planets.entries()].map(([id, p]) => ({
      id,
      label: p.label,
      size: measured(p.n, "ledger.decisions"),
      freshness: measured(p.last, "ledger.timestampMs"),
    })),
    stars: stars.map((s) => (s.planetId ? s : { ...s, planetId: null })),
    agents: [...agents.entries()].map(([id, a]) => ({
      id,
      label: id,
      planetId: tenantGroup(a.rows[0]?.inputs?.principal ?? null),
      lastActMs: measured(a.last, "ledger.timestampMs"),
      witness: witnessOf(a.rows),
    })),
    edges,
  };
}
