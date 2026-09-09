import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { recordLine, statusWord } from "../src/records/line.ts";
import { countRecords } from "../src/records/summary.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(
  readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8"),
) as Record<string, string>;

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

  it("does not let a row's outcome column outvote its own status word", () => {
    // Same measured ledger. kart-test-2 was deferred and later approved, so
    // its status word reads allowed. The outcome column is the second place
    // the row answers "what happened"; if it still ends on the raw defer
    // claim the row contradicts itself, which is F3 in a new column.
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
    for (const row of actions) {
      const line = recordLine(en, row, approvals, "en");
      // The same row with the approval ledger unread. Where reading it changes
      // the status word, it has to change the outcome too, otherwise one
      // column read the ledger and the other did not.
      const blind = recordLine(en, row, [], "en");
      if (line.kind === blind.kind) continue;
      assert.notEqual(line.outcome, blind.outcome, `${row.record.claims.ref}: ${line.outcome}`);
      const word = statusWord(en, line.kind);
      assert.ok(
        line.outcome.endsWith(word),
        `${row.record.claims.ref}: "${line.outcome}" does not end on "${word}"`,
      );
    }
  });

  it("says expired in the outcome column too, not only in the status word", () => {
    const row = action({ decision: "defer", ref: "kart-test-1" });
    const approvals = [approval({ ref: "kart-test-1", status: "expired" })];
    const line = recordLine(en, row, approvals, "en");
    assert.equal(line.kind, "expired");
    assert.ok(line.outcome.endsWith(statusWord(en, "expired")), line.outcome);
  });
});
