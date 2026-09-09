import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { hashPoint } from "../src/address.ts";
import { UNMEASURED_RGB } from "../src/draw.ts";
import { measured, unmeasured } from "../src/measured.ts";
import { placeScene, SCENE_RADIUS } from "../src/place.ts";
import type { GalaxyModel } from "../src/model.ts";

const empty: GalaxyModel = {
  core: { pulse: unmeasured("no heartbeat"), label: "body" },
  planets: [],
  stars: [],
  agents: [],
  edges: [],
};

describe("placeScene", () => {
  it("puts the same planet on the same hash address twice", () => {
    const model: GalaxyModel = {
      ...empty,
      planets: [{ id: "acme", label: "acme", size: measured(4, "n"), freshness: measured(1, "now") }],
    };
    const a = placeScene(model).planets[0]!;
    const b = placeScene(model).planets[0]!;
    assert.deepEqual(a.at, b.at);
    assert.deepEqual(a.at, hashPoint("planet:acme", SCENE_RADIUS * 1.15));
  });

  it("does not invent a planet for a star with no tenant", () => {
    const model: GalaxyModel = {
      ...empty,
      stars: [{ id: "orphan", planetId: null, at: 1, kind: "decision" }],
    };
    const placed = placeScene(model);
    assert.equal(placed.planets.length, 0);
    assert.equal(placed.stars[0]?.planetId, null);
    assert.deepEqual(placed.stars[0]?.at, hashPoint("orphan", SCENE_RADIUS * 0.32));
  });

  it("keeps an agent's planet id so a focus can sit with that group", () => {
    const model: GalaxyModel = {
      ...empty,
      planets: [{ id: "acme", label: "acme", size: measured(1, "n"), freshness: measured(1, "now") }],
      agents: [{ id: "worker-1", label: "worker-1", planetId: "acme", lastActMs: measured(1, "n") }],
    };
    const placed = placeScene(model);
    assert.equal(placed.agents[0]?.planetId, "acme");
  });

  it("an unmeasured core is the purple mark, not a default pulse", () => {
    const placed = placeScene(empty);
    assert.equal(placed.core.unmeasured, true);
    assert.deepEqual(placed.core.color, UNMEASURED_RGB);
  });
});
