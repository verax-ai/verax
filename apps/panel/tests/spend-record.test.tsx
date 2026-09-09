import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Observatory } from "../src/observatory/Observatory.tsx";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";
import type { ReconcileCardReport } from "../src/ReconcileCard.tsx";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

afterEach(() => {
  cleanup();
});

const defer: RailAction = {
  record: {
    claims: {
      subject: "spend",
      decision: "defer",
      reasonCode: "approval-required",
      timestampMs: 1788714790230,
      decider: "verax-proxy",
      ref: "kart-test-2",
      requestHash: "2f67e3d762c48ebd699170e1f815dcaa882a83b210dbab9d4c01c826172d5dc0",
      policyHash: "f7963a24b19e982a3e9826feab098bbbdced10b7b036d4426966d309417e452f",
      effectHash: null,
    },
  },
  effect: null,
  rule: { id: "spend-meta-ads", tool: "spend", text: "Payments to the Meta ads account need operator approval." },
  finding: null,
  inputs: { principal: { brain: "dev-brain", scopes: ["verax:pay"] }, inputs: [] },
  inputsBound: true,
};

const allow: RailAction = {
  record: {
    claims: {
      subject: "spend",
      decision: "allow",
      reasonCode: "approved-by-operator",
      timestampMs: 1788714791356,
      decider: "verax-operator",
      ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      requestHash: "2f67e3d762c48ebd699170e1f815dcaa882a83b210dbab9d4c01c826172d5dc0",
      policyHash: "f7963a24b19e982a3e9826feab098bbbdced10b7b036d4426966d309417e452f",
      effectHash: "ed26dba0e503304a4d14c045f0ddd54f53fd04c20222603659c4c935fcbefe0a",
    },
  },
  effect: {
    row: {
      ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      effectClass: "spend",
      effectHash: "ed26dba0e503304a4d14c045f0ddd54f53fd04c20222603659c4c935fcbefe0a",
      timestampMs: 1788714791359,
      actor: "operator-1",
    },
    witnessClass: "self",
    receipt: { present: true },
    attestation: { present: true },
  },
  rule: { id: "spend-meta-ads", tool: "spend", text: "Payments to the Meta ads account need operator approval." },
  finding: null,
  inputs: {
    principal: { brain: "dev-brain", scopes: ["verax:pay"] },
    inputs: [],
    approver: { id: "operator-1", via: "cli", resolves: "kart-test-2" },
  },
  inputsBound: true,
  witnessClass: "self",
};

const approvals: PendingApproval[] = [
  {
    ref: "kart-test-2",
    requestHash: "2f67e3d762c48ebd699170e1f815dcaa882a83b210dbab9d4c01c826172d5dc0",
    subject: "spend",
    ruleText: "Payments to the Meta ads account need operator approval.",
    inputsSummary: { count: 0, ids: [] },
    amount: 1000,
    currency: "TRY",
    payee: "meta-ads",
    expiresAtMs: 1788801190230,
    status: "approved",
    brain: "dev-brain",
    allowRef: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
  },
];

const reconcile: ReconcileCardReport = {
  scope: { channel: "card", windowStartMs: 1788696000000, windowEndMs: 1788696000000, rowCount: 1 },
  ghost: [],
  matched: [{ effect: { ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d" } }],
  authorizedUnpaid: [],
};

describe("10 TRY spend record", () => {
  it("shows amount, payee, approver, statement match, witness self, and the defer-approve chain", () => {
    render(
      <Observatory
        actions={[allow, defer]}
        status="ok"
        demo={false}
        pending={approvals}
        reconcile={reconcile}
      />,
    );
    const spend = screen.getByTestId("spend-fields").textContent ?? "";
    // The ledger stores 1000 minor units. The screen must say ten lira, not a thousand.
    expect(spend).toMatch(/10[.,]00/);
    expect(spend).not.toMatch(/(^|[^.,\d])1000([^.,\d]|$)/);
    expect(spend).not.toMatch(/amountMinor/);
    expect(spend).toMatch(/meta-ads/);
    expect(spend).toMatch(/operator-1/);
    expect(spend).toMatch(/eşleşti|matched/i);
    expect(screen.getByTestId("scope-witness").textContent).toMatch(/self/);
    expect(screen.getByTestId("scope-external").textContent).toMatch(/eşleşti|matched/i);
    const chain = screen.getByTestId("explain-pair").textContent ?? "";
    expect(chain).toMatch(/kart-test-2/);
    expect(chain).toMatch(/398befdf-78f6-4780-833b-aa7c7ee5ef5d/);
    expect(chain).toMatch(/approval-required/);
    expect(chain).toMatch(/approved-by-operator/);
    const selected = document.querySelector(".timeline-mark.is-selected");
    expect(selected?.textContent).toMatch(/2026-09-06T17:13:11Z/);
    expect(document.body.textContent).not.toMatch(/Conarium|Tugra|Tuğra|Cedulon/);
  });
});

const auditRead: RailAction = {
  record: {
    claims: {
      subject: "audit.explain",
      decision: "allow",
      reasonCode: "allow",
      timestampMs: 1788714999999,
      decider: "verax-proxy",
      ref: "audit-explain-1",
      policyHash: "f7963a24b19e982a3e9826feab098bbbdced10b7b036d4426966d309417e452f",
      effectHash: null,
    },
  },
  effect: null,
  rule: null,
  finding: null,
};

describe("which record the exhibit opens on", () => {
  it("opens on the spend, not on the panel reading its own ledger", () => {
    // The newest record is the explain call the panel just made. A visitor
    // who lands on it is shown the screen inspecting itself, not an account.
    render(
      <Observatory
        actions={[auditRead, allow, defer]}
        status="ok"
        demo={false}
        pending={approvals}
        reconcile={reconcile}
      />,
    );
    const detail = document.querySelector(".detail-pane")?.textContent ?? "";
    expect(detail).toMatch(/398befdf/);
    expect(detail).not.toMatch(/audit-explain-1/);
    expect(document.querySelector(".record-row.is-selected")?.textContent ?? "").toMatch(/meta-ads/);
  });
});

describe("a resolved defer on the screen", () => {
  it("says the same thing in the status column, the outcome column, the rail and the detail pane", () => {
    // kart-test-2 is the measured defer the operator answered. Four places on
    // the screen render its ending. They read one ledger, so they have to
    // land on one sentence; the screen contradicting itself is the fault
    // this record was picked to prove it cannot have.
    render(
      <Observatory
        actions={[defer, allow]}
        status="ok"
        demo={false}
        pending={approvals}
        reconcile={reconcile}
      />,
    );
    const row = document.querySelector(".record-row") as HTMLElement;
    // The screen opens on the spend that has an effect; this row is the defer
    // behind it, so ask for it before reading the detail pane.
    fireEvent.click(row);
    const status = (row.querySelector(".record-status")?.textContent ?? "").trim();
    const outcome = (row.querySelector(".record-outcome")?.textContent ?? "").trim();
    expect(status.length).toBeGreaterThan(0);
    // The raw claim stays readable, but it is no longer the last word.
    expect(outcome).toMatch(/defer approval-required/);
    expect(outcome).not.toBe("defer approval-required");
    expect(outcome.endsWith(status)).toBe(true);
    expect((screen.getByTestId("detail-result").textContent ?? "").trim()).toBe(outcome);
    expect(screen.getByTestId("rail-records").textContent ?? "").toContain(outcome);
  });
});
