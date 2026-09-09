import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { recordLine } from "../src/records/line.ts";
import { countRecords } from "../src/records/summary.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";

const en = { "line.rule.none": "no matching rule" } as Record<string, string>;

function action(partial: { decision: "allow" | "deny" | "defer"; ref: string }): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: partial.decision,
        reasonCode: partial.decision === "defer" ? "approval-required" : partial.decision,
        timestampMs: 1,
        decider: "verax-proxy",
        ref: partial.ref,
        policyHash: "aa",
        effectHash: null,
      },
    },
    effect: null,
    rule: null,
    finding: null,
  };
}

function approval(partial: {
  ref: string;
  status: PendingApproval["status"];
  allowRef?: string;
}): PendingApproval {
  return {
    ref: partial.ref,
    requestHash: "h",
    subject: "spend",
    ruleText: "need approval",
    inputsSummary: { count: 0, ids: [] },
    expiresAtMs: 9,
    status: partial.status,
    brain: "b",
    ...(partial.allowRef ? { allowRef: partial.allowRef } : {}),
  };
}

describe("record sentence and list", () => {
  it("counts the same waiting rows the sentence does", () => {
    // Same last-write as the measured ledger: one request stayed pending,
    // the other was approved after a defer. The sentence already says 1.
    // The list must not keep saying 2.
    const actions = [
      action({ decision: "defer", ref: "kart-test-1" }),
      action({ decision: "defer", ref: "kart-test-2" }),
      action({ decision: "allow", ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d" }),
    ];
    const approvals = [
      approval({ ref: "kart-test-1", status: "pending" }),
      approval({ ref: "kart-test-2", status: "pending" }),
      approval({
        ref: "kart-test-2",
        status: "approved",
        allowRef: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      }),
    ];
    const pending = countRecords(actions, approvals, null).pending;
    const waiting = actions.filter((row) => recordLine(en, row, approvals).kind === "defer").length;
    assert.equal(pending, 1);
    assert.equal(waiting, pending);
  });
});
