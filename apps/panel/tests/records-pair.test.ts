import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { pairFromLedger } from "../src/records/pair.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";

function row(opts: {
  ref: string;
  decision: "allow" | "deny" | "defer";
  reason: string;
  requestHash?: string;
  resolves?: string;
  decider?: string;
}): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: opts.decision,
        reasonCode: opts.reason,
        timestampMs: 1,
        decider: opts.decider ?? "verax-proxy",
        ref: opts.ref,
        requestHash: opts.requestHash,
        policyHash: "f7",
        effectHash: null,
      },
    },
    effect: null,
    rule: null,
    finding: null,
    inputs: opts.resolves
      ? {
          principal: { brain: "dev-brain", scopes: ["verax:pay"] },
          inputs: [],
          approver: { id: "emek.dogru", via: "cli", resolves: opts.resolves },
        }
      : undefined,
  };
}

describe("defer-approve pair", () => {
  it("shows both records from allowRef and from approver.resolves", () => {
    const defer = row({
      ref: "kart-test-2",
      decision: "defer",
      reason: "approval-required",
      requestHash: "shared",
    });
    const allow = row({
      ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      decision: "allow",
      reason: "approved-by-operator",
      requestHash: "shared",
      resolves: "kart-test-2",
      decider: "verax-operator",
    });
    const approvals: PendingApproval[] = [
      {
        ref: "kart-test-2",
        requestHash: "shared",
        subject: "spend",
        ruleText: "need approval",
        inputsSummary: { count: 0, ids: [] },
        expiresAtMs: 9,
        status: "approved",
        brain: "dev-brain",
        allowRef: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      },
    ];
    const fromAllow = pairFromLedger([defer, allow], allow, approvals);
    assert.equal(fromAllow.defer?.record.claims.ref, "kart-test-2");
    assert.equal(fromAllow.resolution?.record.claims.ref, "398befdf-78f6-4780-833b-aa7c7ee5ef5d");
    const fromDefer = pairFromLedger([defer, allow], defer, approvals);
    assert.equal(fromDefer.defer?.record.claims.ref, "kart-test-2");
    assert.equal(fromDefer.resolution?.record.claims.ref, "398befdf-78f6-4780-833b-aa7c7ee5ef5d");
  });
});
