import type { PendingApproval, RailAction } from "../rail/types.ts";
import { approvalForRef } from "../records/approval-state.ts";

/**
 * The black box reads the ledger the way a flight recorder is read after an
 * incident: every decision on one tape, one lane per agent, in the order the
 * body wrote them; the chain of one decision from request to receipt; and what
 * the record can and cannot vouch for. Nothing here is drawn that the ledger
 * did not give.
 */

/** A quiet stretch longer than this is drawn as a break with its length, not to scale. */
export const BREAK_MS = 30 * 60 * 1000;

export type Decision = "allow" | "deny" | "defer";

export type TapeMark = {
  key: string;
  lane: number;
  /** Position along the tape, 0-100. */
  x: number;
  decision: Decision;
  subject: string;
  timestampMs: number;
  ref: string | null;
  hasEffect: boolean;
  action: RailAction;
};

export type TapeBreak = { x: number; ms: number };

export type Tape = {
  lanes: string[];
  marks: TapeMark[];
  breaks: TapeBreak[];
  firstMs: number | null;
  lastMs: number | null;
};

export function brainOf(action: RailAction): string {
  const brain = action.inputs?.principal.brain;
  return typeof brain === "string" && brain !== "" ? brain : "?";
}

/**
 * Lays the decisions out left to right in time. Short gaps keep their order
 * and a spacing that grows with the gap (log of seconds), so a burst of calls
 * stays readable next to a slow hour. A gap longer than BREAK_MS becomes a
 * break of fixed width that carries its real length. The axis is not to
 * scale; the screen says so.
 */
export function layTape(actions: readonly RailAction[]): Tape {
  const sorted = actions
    .map((action, i) => ({ action, i, t: action.record.claims.timestampMs }))
    .filter((e) => Number.isFinite(e.t))
    .sort((a, b) => a.t - b.t || a.i - b.i);
  const lanes: string[] = [];
  const laneOf = (brain: string) => {
    let at = lanes.indexOf(brain);
    if (at === -1) at = lanes.push(brain) - 1;
    return at;
  };
  if (sorted.length === 0) return { lanes, marks: [], breaks: [], firstMs: null, lastMs: null };

  const BREAK_UNITS = 5;
  const units: number[] = [0];
  const breakAt: { units: number; ms: number }[] = [];
  let total = 0;
  for (let k = 1; k < sorted.length; k++) {
    const delta = sorted[k]!.t - sorted[k - 1]!.t;
    if (delta > BREAK_MS) {
      breakAt.push({ units: total + BREAK_UNITS / 2, ms: delta });
      total += BREAK_UNITS;
    } else {
      total += 1 + Math.log10(1 + Math.max(0, delta) / 1000);
    }
    units.push(total);
  }
  const PAD = 3;
  const place = (u: number) => (total === 0 ? 50 : PAD + (u / total) * (100 - 2 * PAD));
  const marks = sorted.map((e, k) => {
    const c = e.action.record.claims;
    return {
      key: `${c.ref ?? "no-ref"}:${e.i}`,
      lane: laneOf(brainOf(e.action)),
      x: place(units[k]!),
      decision: c.decision,
      subject: c.subject,
      timestampMs: c.timestampMs,
      ref: c.ref,
      hasEffect: e.action.effect !== null,
      action: e.action,
    };
  });
  return {
    lanes,
    marks,
    breaks: breakAt.map((b) => ({ x: place(b.units), ms: b.ms })),
    firstMs: sorted[0]!.t,
    lastMs: sorted[sorted.length - 1]!.t,
  };
}

/** A gap in words a person reads: the largest unit that fits, rounded down. */
export function gapWords(ms: number, lang: "tr" | "en"): string {
  const steps: [number, string, string][] = [
    [365 * 24 * 3600e3, "yıl", "yr"],
    [24 * 3600e3, "gün", "d"],
    [3600e3, "sa", "h"],
    [60e3, "dk", "min"],
  ];
  for (const [size, tr, en] of steps) {
    if (ms >= size) return `${Math.floor(ms / size)} ${lang === "tr" ? tr : en}`;
  }
  return lang === "tr" ? "<1 dk" : "<1 min";
}

export type LinkState = "done" | "stopped" | "waiting" | "missing";

export type ChainLink = {
  id: "request" | "rule" | "decision" | "approval" | "effect" | "receipt";
  state: LinkState;
  /** Copy key suffix for the line under the step's name. */
  say: string;
  detail: string | null;
  code: string | null;
};

const short = (hash: string | null | undefined) => (typeof hash === "string" && hash !== "" ? `${hash.slice(0, 12)}…` : null);

/**
 * The chain of one decision, from the request to the receipt. A link the
 * ledger does not hold is drawn as missing and says which; a refusal stops the
 * chain at the decision, because the tool never ran.
 */
export function chainFor(
  action: RailAction,
  actions: readonly RailAction[],
  pending: readonly PendingApproval[],
): ChainLink[] {
  const c = action.record.claims;
  const links: ChainLink[] = [
    { id: "request", state: "done", say: "request", detail: `${c.subject} / ${brainOf(action)}`, code: short(c.requestHash) },
  ];

  if (action.rule === null) links.push({ id: "rule", state: "missing", say: "rule.none", detail: null, code: short(c.policyHash) });
  else if (action.rule.text === null) links.push({ id: "rule", state: "missing", say: "rule.gone", detail: null, code: short(c.policyHash) });
  else links.push({ id: "rule", state: "done", say: "rule", detail: action.rule.text, code: short(c.policyHash) });

  const decisionState: LinkState = c.decision === "allow" ? "done" : c.decision === "deny" ? "stopped" : "waiting";
  links.push({ id: "decision", state: decisionState, say: `decision.${c.decision}`, detail: `${c.reasonCode} / ${c.decider}`, code: null });

  const approver = action.inputs?.approver;
  if (c.decision === "defer") {
    const row = approvalForRef(pending, c.ref);
    const answer = row?.allowRef ? actions.find((a) => a.record.claims.ref === row.allowRef) : undefined;
    const by = answer?.inputs?.approver;
    if (row?.status === "approved") {
      links.push({ id: "approval", state: "done", say: "approval.done", detail: by ? who(by) : null, code: row.allowRef ?? null });
    } else if (row?.status === "expired") {
      links.push({ id: "approval", state: "stopped", say: "approval.expired", detail: null, code: null });
    } else {
      links.push({ id: "approval", state: "waiting", say: "approval.waiting", detail: null, code: null });
    }
  } else if (approver) {
    links.push({ id: "approval", state: "done", say: "approval.done", detail: who(approver), code: approver.resolves ?? null });
  }

  if (c.decision === "deny") {
    links.push({ id: "effect", state: "stopped", say: "effect.refused", detail: null, code: null });
  } else if (c.decision === "defer") {
    links.push({ id: "effect", state: "waiting", say: "effect.held", detail: null, code: null });
  } else if (action.effect) {
    const witness = action.effect.witnessClass ?? action.witnessClass ?? null;
    links.push({
      id: "effect",
      state: "done",
      say: "effect",
      detail: witness ? `${action.effect.row.effectClass} / ${witness}` : action.effect.row.effectClass,
      code: short(action.effect.row.effectHash),
    });
    const receipt = action.effect.receipt !== undefined && action.effect.receipt !== null;
    links.push({ id: "receipt", state: receipt ? "done" : "missing", say: receipt ? "receipt" : "receipt.none", detail: null, code: null });
  } else {
    links.push({ id: "effect", state: "missing", say: "effect.none", detail: null, code: null });
  }
  return links;
}

function who(approver: { id: string; via?: string }): string {
  return approver.via ? `${approver.id} / ${approver.via}` : approver.id;
}

export type RecordHealth = {
  decisions: number;
  agents: number;
  denied: number;
  waiting: number;
  /** Effect rows by witness class, as the ledger names them. */
  witness: Record<string, number>;
  /** Decisions whose inputs document is bound into the signed record. */
  inputsBound: number;
  /** null when no record carries a trust-root reading. */
  trustPinned: boolean | null;
};

export function recordHealth(
  actions: readonly RailAction[],
  pending: readonly PendingApproval[],
  decisions: number | undefined,
): RecordHealth {
  const witness: Record<string, number> = {};
  let trustPinned: boolean | null = null;
  for (const a of actions) {
    if (a.effect) {
      const w = a.effect.witnessClass ?? a.witnessClass ?? "self";
      witness[w] = (witness[w] ?? 0) + 1;
    }
    if (a.trustRoot) trustPinned = (trustPinned ?? true) && a.trustRoot.pinned;
  }
  const latest = new Map<string, PendingApproval>();
  for (const row of pending) latest.set(row.ref, row);
  return {
    decisions: decisions ?? actions.length,
    agents: new Set(actions.map(brainOf)).size,
    denied: actions.filter((a) => a.record.claims.decision === "deny").length,
    waiting: [...latest.values()].filter((r) => r.status === "pending").length,
    witness,
    inputsBound: actions.filter((a) => a.inputsBound === true).length,
    trustPinned,
  };
}
