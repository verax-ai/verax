import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { formatStamp, sameUtcDay, timelineGroups, timelineMarks } from "../src/records/timeline.ts";
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

  it("folds the stamps that would print on top of each other, and says how many", () => {
    // Three decisions inside a couple of seconds, one twenty minutes earlier:
    // the measured ledger's own shape.
    const marks = timelineMarks([
      at("a", 1_000),
      at("b", 1_200_000),
      at("c", 1_200_900),
      at("d", 1_201_500),
    ]);
    const groups = timelineGroups(marks, 1000, 88, false);
    assert.equal(groups.length, 2);
    assert.equal(groups[0]?.count, 1);
    assert.equal(groups[1]?.count, 3);
    assert.equal(groups[1]?.label, "3");
    // The fold names every stamp it stands for, so nothing is lost by folding.
    assert.equal(groups[1]?.title.split(" · ").length, 3);
    assert.deepEqual(groups[1]?.refs, ["b", "c", "d"]);
  });

  it("keeps every mark inside the track it was measured against", () => {
    const marks = timelineMarks([at("first", 1_000), at("last", 900_000)]);
    const groups = timelineGroups(marks, 400, 88, false);
    for (const g of groups) {
      assert.ok(g.leftPx >= 0, `${g.key} at ${g.leftPx}`);
      assert.ok(g.leftPx + 88 <= 400 + 0.5, `${g.key} ends at ${g.leftPx + 88}`);
    }
  });

  it("folds nothing when the track was never measured", () => {
    const marks = timelineMarks([at("a", 1_000), at("b", 1_100), at("c", 1_200)]);
    const groups = timelineGroups(marks, 0, 88, false);
    assert.equal(groups.length, 3);
    assert.ok(groups.every((g) => g.count === 1 && g.leftPx === -1));
  });

  it("prints the time of day only while every record shares one UTC day", () => {
    const oneDay = timelineMarks([at("a", 1788714791356), at("b", 1788714792053)]);
    assert.equal(sameUtcDay(oneDay), true);
    assert.equal(timelineGroups(oneDay, 1000, 88, true)[0]?.label, "17:13:11Z");
    const across = timelineMarks([at("a", 1788714791356), at("b", 1788714791356 + 86_400_000)]);
    assert.equal(sameUtcDay(across), false);
    assert.equal(timelineGroups(across, 1000, 88, false)[0]?.label, "2026-09-06T17:13:11Z");
  });
});
