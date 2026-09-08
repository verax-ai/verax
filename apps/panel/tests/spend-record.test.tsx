import { cleanup, render, screen } from "@testing-library/react";
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
      actor: "emek.dogru",
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
    approver: { id: "emek.dogru", via: "cli", resolves: "kart-test-2" },
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
    expect(spend).toMatch(/1000 TRY/);
    expect(spend).toMatch(/amountMinor/);
    expect(spend).toMatch(/meta-ads/);
    expect(spend).toMatch(/emek\.dogru/);
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
