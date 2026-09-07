import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { dustCount, dustPositions } from "../src/dust.ts";
import { measured, unmeasured } from "../src/measured.ts";
import type { GalaxyModel } from "../src/model.ts";
import { placeScene } from "../src/place.ts";
import { TIER_DUST } from "../src/quality.ts";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

function model(stars: number): GalaxyModel {
  return {
    core: { pulse: unmeasured("no heartbeat"), label: "body" },
    planets: [
      { id: "t1", label: "t1", size: measured(stars, "count"), freshness: measured(1, "now") },
    ],
    stars: Array.from({ length: stars }, (_, i) => ({
      id: `s${i}`,
      planetId: "t1",
      at: 1,
      kind: "decision",
    })),
    agents: [],
    edges: [],
  };
}

describe("dust is depth, not a tally", () => {
  it("dust count is the quality tier, not the number of records", () => {
    assert.equal(dustCount(0), TIER_DUST[0]);
    assert.equal(dustCount(2), TIER_DUST[2]);
    const few = placeScene(model(2));
    const many = placeScene(model(80));
    assert.equal(few.stars.length, 2);
    assert.equal(many.stars.length, 80);
    assert.equal(dustCount(0), dustCount(0));
    assert.notEqual(dustCount(0), few.stars.length);
    assert.notEqual(dustCount(0), many.stars.length);
  });

  it("the same tier always lays the same cloud", () => {
    const a = dustPositions(1, 48);
    const b = dustPositions(1, 48);
    assert.equal(a.length, TIER_DUST[1] * 3);
    assert.deepEqual(a, b);
  });

  it("source does not size dust from stars or planets", () => {
    const text = readFileSync(join(src, "dust.ts"), "utf8");
    assert.doesNotMatch(text, /stars\.length|planets\.length|model\./);
    assert.match(text, /quality knob|not a record count|not a tally/i);
  });
});
