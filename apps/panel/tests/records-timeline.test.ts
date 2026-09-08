import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { formatStamp, timelineMarks } from "../src/records/timeline.ts";
import type { RailAction } from "../src/rail/types.ts";

function at(ref: string, timestampMs: number): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: "allow",
        reasonCode: "allow",
        timestampMs,
        decider: "verax-proxy",
        ref,
        policyHash: "aa",
        effectHash: null,
      },
    },
    effect: null,
    rule: null,
    finding: null,
  };
}

describe("timeline marks", () => {
  it("places marks from the records' own stamps and keeps a sparse span sparse", () => {
    const marks = timelineMarks([
      at("early", 1_000),
      at("late", 9_000),
      at("mid", 1_100),
    ]);
    assert.equal(marks.length, 3);
    assert.equal(marks[0]?.leftPct, 0);
    assert.equal(marks[1]?.leftPct, 100);
    assert.ok((marks[2]?.leftPct ?? 0) < 5);
    assert.equal(formatStamp(1_000), "1970-01-01T00:00:01Z");
  });

  it("does not invent a middle seat for a single stamp", () => {
    const marks = timelineMarks([at("one", 1788714791356)]);
    assert.equal(marks.length, 1);
    assert.equal(marks[0]?.leftPct, 0);
    assert.equal(marks[0]?.stamp, "2026-09-06T17:13:11Z");
  });
});
