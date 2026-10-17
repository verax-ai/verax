import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { spendFields } from "../src/records/spend.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";

const copy: Record<string, string> = {
  "spend.amount": "Amount: {amount}",
  "spend.amount.unmeasured": "Amount: not measured",
  "spend.payee": "Payee: {payee}",
  "spend.payee.unmeasured": "Payee: not measured",
  "spend.approver.unmeasured": "Approved by: not measured",
  "spend.statement.unbound": "Statement: not bound",
  "spend.statement.unmeasured": "Statement: not measured",
  "spend.statement.absent": "Statement: absent",
  "spend.statement.matched": "Statement: matched",
  "spend.statement.unpaid": "Statement: unpaid",
};

const action: RailAction = {
  record: {
    claims: {
      subject: "spend",
      decision: "allow",
      reasonCode: "approved-by-operator",
      timestampMs: 1,
      decider: "verax-operator",
      ref: "a1",
      policyHash: "ab",
      effectHash: null,
    },
  },
  effect: null,
  rule: null,
  finding: null,
};

function row(over: Partial<PendingApproval>): PendingApproval {
  return {
    ref: "d1",
    requestHash: "00",
    subject: "spend",
    ruleText: null,
    inputsSummary: { count: 0, ids: [] },
    expiresAtMs: 2,
    status: "approved",
    brain: "brain-1",
    allowRef: "a1",
    amount: 5_000,
    currency: "TRY",
    payee: "other-shop",
    ...over,
  };
}

describe("spendFields", () => {
  it("an unbound row says the amount and payee were not measured", () => {
    const fields = spendFields(copy, action, [row({ bound: false })], null, "en");
    assert.ok(fields);
    assert.equal(fields.amount, "Amount: not measured");
    assert.equal(fields.payee, "Payee: not measured");
  });

  it("a bound row reads amount and payee from its arguments", () => {
    const fields = spendFields(
      copy,
      action,
      [
        row({
          bound: true,
          args: { amountMinor: 1_000, currency: "TRY", payee: "ads-platform" },
        }),
      ],
      null,
      "en",
    );
    assert.ok(fields);
    assert.match(fields.amount, /10[.,]00/);
    assert.equal(/50[.,]00/.test(fields.amount), false);
    assert.equal(fields.payee, "Payee: ads-platform");
  });
});
