import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { recordLine } from "../src/records/line.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;

describe("record line", () => {
  it("says what was asked, what the rule said, and what happened — not a naked ref", () => {
    const action: RailAction = {
      record: {
        claims: {
          subject: "spend",
          decision: "allow",
          reasonCode: "approved-by-operator",
          timestampMs: 1,
          decider: "verax-operator",
          ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
          policyHash: "f7",
          effectHash: "ed",
        },
      },
      effect: {
        row: {
          ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
          effectClass: "spend",
          effectHash: "ed",
          timestampMs: 1,
        },
      },
      rule: { id: "spend-meta-ads", tool: "spend", text: "Payments to the Meta ads account need operator approval." },
      finding: null,
    };
    const approvals: PendingApproval[] = [
      {
        ref: "kart-test-2",
        requestHash: "rh",
        subject: "spend",
        ruleText: "Payments to the Meta ads account need operator approval.",
        inputsSummary: { count: 0, ids: [] },
        amount: 1000,
        currency: "TRY",
        payee: "meta-ads",
        expiresAtMs: 9,
        status: "approved",
        brain: "dev-brain",
        allowRef: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      },
    ];
    const line = recordLine(en, action, approvals);
    assert.equal(line.asked, "spend 1000 TRY → meta-ads");
    assert.match(line.rule, /Meta ads/);
    assert.equal(line.outcome, "allow approved-by-operator");
    assert.equal(line.label.includes("398befdf"), false);
    assert.match(line.label, /spend 1000 TRY → meta-ads/);
  });
});
