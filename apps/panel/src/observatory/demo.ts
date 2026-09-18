import { parseLedger } from "../rail/parse.ts";
import type { PolicyStore } from "../rail/parse.ts";
import type { AgentRow, AgentsAnswer, PendingApproval, RailAction, RailInputs } from "../rail/types.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import decisionsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/decisions.jsonl?raw";
import effectsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/effects.jsonl?raw";
import inputsText from "../../../../packages/proxy/tests/fixtures/ledger-golden/inputs.jsonl?raw";
import policyStore from "../../../../packages/proxy/tests/fixtures/ledger-golden/policy-store.json";

const DEMO_REQUEST_HASH =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DEMO_WAIT_HASH =
  "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DEMO_DEFER_REF = "demo-spend-defer";
const DEMO_WAIT_REF = "demo-spend-open";
const DEMO_ALLOW_REF = "demo-spend-allow";
const DEMO_POLICY_HASH =
  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const DEMO_EFFECT_HASH =
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DEMO_DEFER_MS = 1_788_800_000_000;
const DEMO_WAIT_MS = 1_788_800_000_500;
const DEMO_ALLOW_MS = 1_788_800_001_100;

const demoRule = {
  id: "spend-sample",
  tool: "spend",
  text: "Sample spend needs operator approval.",
} as const;

function parseInputsJsonl(text: string): Record<string, RailInputs> {
  const out: Record<string, RailInputs> = {};
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref: string; inputs: RailInputs };
    if (typeof row.ref !== "string" || row.ref === "") continue;
    out[row.ref] = row.inputs;
  }
  return out;
}

function demoDefer(): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: "defer",
        reasonCode: "approval-required",
        timestampMs: DEMO_DEFER_MS,
        decider: "verax-proxy",
        ref: DEMO_DEFER_REF,
        requestHash: DEMO_REQUEST_HASH,
        policyHash: DEMO_POLICY_HASH,
        effectHash: null,
      },
    },
    effect: null,
    rule: demoRule,
    finding: null,
    inputs: { principal: { brain: "sample-brain", scopes: ["verax:pay"] }, inputs: [] },
    inputsBound: true,
  };
}

function demoAllow(): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: "allow",
        reasonCode: "approved-by-operator",
        timestampMs: DEMO_ALLOW_MS,
        decider: "verax-operator",
        ref: DEMO_ALLOW_REF,
        requestHash: DEMO_REQUEST_HASH,
        policyHash: DEMO_POLICY_HASH,
        effectHash: DEMO_EFFECT_HASH,
      },
    },
    effect: {
      row: {
        ref: DEMO_ALLOW_REF,
        effectClass: "spend",
        effectHash: DEMO_EFFECT_HASH,
        timestampMs: DEMO_ALLOW_MS,
        actor: "operator-1",
      },
      witnessClass: "self",
      receipt: { present: true },
      attestation: { present: true },
    },
    rule: demoRule,
    finding: null,
    inputs: {
      principal: { brain: "sample-brain", scopes: ["verax:pay"] },
      inputs: [],
      approver: { id: "operator-1", via: "cli", resolves: DEMO_DEFER_REF },
    },
    inputsBound: true,
    witnessClass: "self",
  };
}

function demoWaiting(): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: "defer",
        reasonCode: "approval-required",
        timestampMs: DEMO_WAIT_MS,
        decider: "verax-proxy",
        ref: DEMO_WAIT_REF,
        requestHash: DEMO_WAIT_HASH,
        policyHash: DEMO_POLICY_HASH,
        effectHash: null,
      },
    },
    effect: null,
    rule: demoRule,
    finding: null,
    inputs: { principal: { brain: "sample-brain", scopes: ["verax:pay"] }, inputs: [] },
    inputsBound: true,
  };
}

export function loadDemoActions(): RailAction[] {
  const golden = parseLedger(
    decisionsText,
    effectsText,
    policyStore as PolicyStore,
    parseInputsJsonl(inputsText),
  );
  // parseLedger is newest-first. These two are the newest outward records so
  // the screen opens on the resolved spend. Appending them would leave the
  // exhibit on golden message.read and the gate would keep measuring a thin pane.
  // The waiting spend sits after the resolved pair so the exhibit stays the
  // allow; the operator still has a pending row to tap on the records tab.
  return [demoAllow(), demoDefer(), demoWaiting(), ...golden];
}

export function loadDemoApprovals(): PendingApproval[] {
  return [
    {
      ref: DEMO_DEFER_REF,
      requestHash: DEMO_REQUEST_HASH,
      subject: "spend",
      ruleText: demoRule.text,
      inputsSummary: { count: 0, ids: [] },
      amount: 1000,
      currency: "TRY",
      payee: "example-payee",
      expiresAtMs: DEMO_ALLOW_MS + 86_400_000,
      status: "approved",
      brain: "sample-brain",
      allowRef: DEMO_ALLOW_REF,
    },
    {
      ref: DEMO_WAIT_REF,
      requestHash: DEMO_WAIT_HASH,
      subject: "spend",
      ruleText: demoRule.text,
      inputsSummary: { count: 0, ids: [] },
      amount: 1000,
      currency: "TRY",
      payee: "example-payee",
      expiresAtMs: DEMO_ALLOW_MS + 86_400_000,
      status: "pending",
      brain: "sample-brain",
    },
  ];
}

/**
 * The agents table for the sample, counted off the sample itself.
 *
 * A body answers /api/agents by reading its ledger and its roster. The sample
 * has no body, so the table was simply absent and the published screen showed
 * less than the product does. These rows are the same arithmetic as
 * `agentsWindow` in the body, applied to the rows already on screen: the brain
 * comes from the decision's inputs document, a decision with none is
 * unattributed rather than filed under a guessed name, and an approval that is
 * still pending counts against its brain. Nothing here is a number the sample
 * does not already state.
 *
 * `roster` stays null on every row, because the sample reads no inventory. The
 * table then files them under its off-roster group, which is what the status
 * rail already says in words: the sample scenario shows no inventory.
 */
export function demoAgents(
  actions: readonly RailAction[],
  pending: readonly PendingApproval[],
): AgentsAnswer {
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
  let fromMs: number | null = null;
  let toMs: number | null = null;
  for (const action of actions) {
    const brain = action.inputs?.principal.brain;
    if (typeof brain !== "string" || brain === "") {
      unattributed += 1;
      continue;
    }
    const row = rowFor(brain);
    const { decision, timestampMs } = action.record.claims;
    row.decisions += 1;
    if (decision === "allow") row.allowed += 1;
    else if (decision === "deny") row.denied += 1;
    else if (decision === "defer") row.deferred += 1;
    if (row.lastMs === null || timestampMs > row.lastMs) row.lastMs = timestampMs;
    if (fromMs === null || timestampMs < fromMs) fromMs = timestampMs;
    if (toMs === null || timestampMs > toMs) toMs = timestampMs;
  }
  for (const approval of pending) {
    if (approval.status === "pending") rowFor(approval.brain).pending += 1;
  }

  const agents = [...byBrain.values()].sort(
    (a, b) => b.pending - a.pending || (b.lastMs ?? -1) - (a.lastMs ?? -1) || a.brain.localeCompare(b.brain),
  );
  return { fromMs: fromMs ?? 0, toMs: toMs ?? 0, agents, unattributed };
}

export function loadDemoAgents(): AgentsAnswer {
  return demoAgents(loadDemoActions(), loadDemoApprovals());
}

export function loadDemoReconcile(): ReconcileCardReport {
  return {
    scope: {
      channel: "card",
      windowStartMs: DEMO_DEFER_MS,
      windowEndMs: DEMO_ALLOW_MS,
      rowCount: 1,
    },
    ghost: [],
    matched: [{ effect: { ref: DEMO_ALLOW_REF } }],
    authorizedUnpaid: [],
  };
}
