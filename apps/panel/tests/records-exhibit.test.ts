import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { exhibitRef } from "../src/records/exhibit.ts";
import type { RailAction } from "../src/rail/types.ts";

function row(partial: { ref: string; subject: string; withEffect: boolean }): RailAction {
  return {
    record: {
      claims: {
        subject: partial.subject,
        decision: "allow",
        reasonCode: "allow",
        timestampMs: 1,
        decider: "verax-proxy",
        ref: partial.ref,
        policyHash: "f7",
        effectHash: partial.withEffect ? "ed" : null,
      },
    },
    effect: partial.withEffect
      ? { row: { ref: partial.ref, effectClass: "spend", effectHash: "ed", timestampMs: 2 } }
      : null,
    rule: null,
    finding: null,
  };
}

describe("which record the screen opens on", () => {
  it("does not open on the panel's own read when a record did something", () => {
    // The measured ledger, newest first: the panel's explain call is the
    // newest record AND it carries an effect row with a receipt, so "has an
    // effect" alone does not tell the exhibit from the screen reading itself.
    const actions = [
      row({ ref: "8e6fc6f8", subject: "audit.explain", withEffect: true }),
      row({ ref: "398befdf", subject: "spend", withEffect: true }),
      row({ ref: "kart-test-2", subject: "spend", withEffect: false }),
      row({ ref: "kart-test-1", subject: "spend", withEffect: false }),
    ];
    assert.equal(exhibitRef(actions), "398befdf");
  });

  it("prefers a record with evidence over a newer one without", () => {
    const actions = [
      row({ ref: "kart-test-2", subject: "spend", withEffect: false }),
      row({ ref: "398befdf", subject: "spend", withEffect: true }),
    ];
    assert.equal(exhibitRef(actions), "398befdf");
  });

  it("opens on the newest read rather than nothing when every record is one", () => {
    const actions = [row({ ref: "8e6fc6f8", subject: "audit.explain", withEffect: true })];
    assert.equal(exhibitRef(actions), "8e6fc6f8");
  });

  it("has nothing to open on an empty ledger", () => {
    assert.equal(exhibitRef([]), null);
  });
});
