import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { aimOrbit, cameraPosition, createOrbit, focusOrbit } from "../src/camera.ts";
import {
  BODY_CLUSTER_MIN,
  bodyClusters,
  clusterLabelText,
  clusterMarkScale,
  type CrowdBody,
} from "../src/crowd.ts";
import { LABEL_FOV_DEG } from "../src/labels.ts";
import { measured, unmeasured } from "../src/measured.ts";
import type { GalaxyModel } from "../src/model.ts";
import { groupRadius, placeScene } from "../src/place.ts";

/** The galaxy stage measured off the live capture: 580 x 630 CSS pixels. */
const STAGE_ASPECT = 580 / 630;

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const opening = 85;

function eyeAt(distance: number, yaw = 0, pitch = 0.62) {
  const orbit = createOrbit(distance);
  orbit.yaw = yaw;
  orbit.pitch = pitch;
  orbit.targetYaw = yaw;
  orbit.targetPitch = pitch;
  orbit.targetDistance = distance;
  orbit.distance = distance;
  return { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };
}

function emptyModel(): GalaxyModel {
  return {
    core: { pulse: unmeasured("no heartbeat"), label: "body" },
    planets: [],
    stars: [],
    agents: [],
    edges: [],
  };
}

function crowdModel(count: number, groups: number): GalaxyModel {
  const planets = Array.from({ length: groups }, (_, i) => ({
    id: `g-${i + 1}`,
    label: `Group ${i + 1}`,
    size: measured(Math.floor(count / groups), "test.agents"),
    freshness: measured(1, "test.agents"),
  }));
  const agents = Array.from({ length: count }, (_, i) => ({
    id: `a-${i + 1}`,
    label: `Agent ${i + 1}`,
    planetId: `g-${(i % groups) + 1}`,
    lastActMs: measured(1, "test.agents"),
  }));
  return { ...emptyModel(), planets, agents };
}

function bodiesOf(model: GalaxyModel): CrowdBody[] {
  return placeScene(model).agents.map((a) => ({ id: a.id, at: a.at, source: a.source }));
}

function accounted(out: ReturnType<typeof bodyClusters>): number {
  let n = out.singles.length;
  for (const c of out.clusters) n += c.count;
  return n;
}

describe("body clusters", () => {
  it("leaves a three-agent fixture as named individuals", () => {
    const out = bodyClusters(bodiesOf(crowdModel(3, 2)), eyeAt(opening));
    assert.equal(out.clusters.length, 0);
    assert.equal(out.singles.length, 3);
    assert.ok(BODY_CLUSTER_MIN > 3);
  });

  it("draws a crowded 500 as clusters whose written count is the record count", () => {
    const bodies = bodiesOf(crowdModel(500, 12));
    const out = bodyClusters(bodies, eyeAt(opening));
    assert.ok(out.clusters.length > 0, "a 12-group crowd at opening must confess clusters");
    assert.equal(accounted(out), 500);
    for (const c of out.clusters) {
      assert.equal(c.count, c.ids.length);
      assert.equal(clusterLabelText(c.count, c.source), `${c.count} · ${c.source}`);
      assert.match(c.source, /test\.agents|scene\.records/);
      assert.ok(c.count >= BODY_CLUSTER_MIN);
    }
  });

  it("does not encode the count in the mark size", () => {
    assert.equal(clusterMarkScale(8), clusterMarkScale(80));
    assert.equal(clusterMarkScale(5), clusterMarkScale(500));
  });

  it("dissolves clusters when the same bodies have room on screen", () => {
    const model = crowdModel(500, 12);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const focusedIds = new Set(placed.agents.filter((a) => a.planetId === planet.id).map((a) => a.id));
    const bodies = bodiesOf(model);
    const far = bodyClusters(bodies, eyeAt(opening));
    const seat = focusOrbit(planet.at, groupRadius(placed, planet.id));
    const orbit = createOrbit(seat.distance);
    aimOrbit(orbit, seat, true);
    const near = bodyClusters(bodies, { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT });
    assert.equal(accounted(far), 500);
    assert.equal(accounted(near), 500);
    const farFocusedSingles = far.singles.filter((s) => focusedIds.has(s.id)).length;
    const nearFocusedSingles = near.singles.filter((s) => focusedIds.has(s.id)).length;
    assert.ok(
      nearFocusedSingles > farFocusedSingles,
      `focused singles far=${farFocusedSingles} near=${nearFocusedSingles}`,
    );
  });

  it("is used by the sky, and the sky does not slice agents away", () => {
    const crowd = readFileSync(join(src, "crowd.ts"), "utf8");
    assert.match(crowd, /export function bodyClusters/);
    assert.match(crowd, /export function clusterLabelText/);
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    assert.match(scene, /bodyClusters\(/);
    assert.match(scene, /clusterLabelText\(/);
    assert.match(scene, /data-testid="galaxy-clusters"/);
    assert.doesNotMatch(scene, /agents\.slice/);
    assert.doesNotMatch(scene, /stars\.slice/);
  });
});
