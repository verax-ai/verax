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
    // Newest first, and the newest is the audit call the panel just made.
    const actions = [
      row({ ref: "audit-1", subject: "audit.explain", withEffect: false }),
      row({ ref: "398befdf", subject: "spend", withEffect: true }),
      row({ ref: "kart-test-2", subject: "spend", withEffect: false }),
    ];
    assert.equal(exhibitRef(actions), "398befdf");
  });

  it("keeps the newest record when nothing in the ledger has an effect", () => {
    const actions = [
      row({ ref: "audit-1", subject: "audit.explain", withEffect: false }),
      row({ ref: "kart-test-1", subject: "spend", withEffect: false }),
    ];
    assert.equal(exhibitRef(actions), "audit-1");
  });

  it("has nothing to open on an empty ledger", () => {
    assert.equal(exhibitRef([]), null);
  });
});
