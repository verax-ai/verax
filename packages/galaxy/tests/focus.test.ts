import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  aimOrbit,
  CAMERA_NEAR,
  cameraPosition,
  clampLookAt,
  createOrbit,
  FOCUS_CLEARANCE,
  focusOrbit,
  LOOK_BOUND,
  ZOOM_MIN,
} from "../src/camera.ts";
import {
  AGENT_LABEL_SPRITE_SCALE,
  LABEL_ASPECT_FALLBACK,
  LABEL_FOV_DEG,
  labelNdcHeight,
  PLANET_LABEL_SPRITE_SCALE,
  labelBudget,
  labelCrowd,
  projectNdc,
  type Ndc,
} from "../src/labels.ts";
import { measured, unmeasured } from "../src/measured.ts";
import type { GalaxyModel } from "../src/model.ts";
import { groupRadius, GROUP_RADIUS, placeScene, SCENE_RADIUS } from "../src/place.ts";

/** The distance the sky opens at, as Galaxy.tsx sets it. */
const OPENING_DISTANCE = 85;

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

/**
 * The canvas the sky is drawn on, not the window: measured off the live
 * 1440x900 capture (VERAX_KALABALIK_20260910/focused.png) the stage is
 * 580 x 630 CSS pixels, because the sky sits in the middle pane. The camera
 * divides x by this, so a rule measured at 1 reads a gap that is not there.
 */
const STAGE_ASPECT = 580 / 630;


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
    planetId: groups > 0 ? `g-${(i % groups) + 1}` : null,
    lastActMs: measured(1, "test.agents"),
  }));
  return { ...emptyModel(), planets, agents };
}

function groupNdc(model: GalaxyModel, planetId: string, seat: ReturnType<typeof focusOrbit>): Ndc[] {
  const orbit = createOrbit(seat.distance);
  aimOrbit(orbit, seat, true);
  const cam = { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };
  const out: Ndc[] = [];
  for (const agent of placeScene(model).agents) {
    if (agent.planetId !== planetId) continue;
    const p = projectNdc(agent.at, cam);
    if (p) out.push(p);
  }
  return out;
}

function overlappingPairs(points: readonly Ndc[]): [number, number][] {
  const out: [number, number][] = [];
  // The box the GPU draws: scale over tan(fov/2), and that over the stage
  // aspect across. Written out here rather than imported, so the guard does
  // not pass just because the rule agrees with itself.
  const box = { spriteScale: AGENT_LABEL_SPRITE_SCALE, fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };
  const h = labelNdcHeight(box);
  const w = (h * LABEL_ASPECT_FALLBACK) / STAGE_ASPECT;
  for (let i = 0; i < points.length; i += 1) {
    for (let j = i + 1; j < points.length; j += 1) {
      const a = points[i]!;
      const b = points[j]!;
      if (Math.abs(a.x - b.x) < w && Math.abs(a.y - b.y) < h) out.push([i, j]);
    }
  }
  return out;
}

describe("focusOrbit", () => {
  it("aims at the planet record, not a made-up point", () => {
    const at = { x: 20, y: 4, z: -12 };
    const seat = focusOrbit(at, GROUP_RADIUS);
    assert.deepEqual(seat.target, at);
  });

  it("sits outside the group and inside the sky", () => {
    const at = { x: 20, y: 4, z: -12 };
    const seat = focusOrbit(at, GROUP_RADIUS);
    assert.ok(seat.distance >= ZOOM_MIN);
    assert.ok(seat.distance >= GROUP_RADIUS);
    assert.ok(seat.distance >= GROUP_RADIUS + FOCUS_CLEARANCE - 1e-9);
    assert.ok(seat.distance < SCENE_RADIUS, `focus distance ${seat.distance} must enter the sky (${SCENE_RADIUS})`);
  });

  it("keeps the camera in front of the near plane", () => {
    const at = { x: 20, y: 4, z: -12 };
    const seat = focusOrbit(at, GROUP_RADIUS);
    const orbit = createOrbit(seat.distance);
    aimOrbit(orbit, seat, true);
    const cam = cameraPosition(orbit);
    const toTarget = Math.hypot(cam.x - seat.target.x, cam.y - seat.target.y, cam.z - seat.target.z);
    assert.ok(toTarget > CAMERA_NEAR, `camera-to-target ${toTarget} <= near ${CAMERA_NEAR}`);
    assert.ok(toTarget >= ZOOM_MIN - 1e-9);
    assert.equal(cam.lookX, at.x);
    assert.equal(cam.lookY, at.y);
    assert.equal(cam.lookZ, at.z);
  });

  it("clamps a runaway target so the camera does not leave the sky", () => {
    const seat = focusOrbit({ x: 1000, y: 0, z: 0 }, GROUP_RADIUS);
    assert.ok(Math.hypot(seat.target.x, seat.target.y, seat.target.z) <= LOOK_BOUND + 1e-9);
    const finite = clampLookAt({ x: Number.NaN, y: 2, z: 0 });
    assert.equal(finite.x, 0);
    assert.equal(finite.y, 2);
  });

  it("reduced motion aims without spinning", () => {
    const orbit = createOrbit(120);
    orbit.yaw = 0.4;
    orbit.targetYaw = 0.4;
    const seat = focusOrbit({ x: 10, y: 0, z: 0 }, 4);
    aimOrbit(orbit, seat, true);
    assert.equal(orbit.yaw, 0.4);
    assert.equal(orbit.lookX, seat.target.x);
    assert.equal(orbit.lookY, seat.target.y);
    assert.equal(orbit.lookZ, seat.target.z);
    assert.equal(orbit.distance, seat.distance);
  });
});

describe("focus makes a group's names readable", () => {
  it("does not relax the crowd threshold, or shrink the box behind its back", () => {
    const labels = readFileSync(join(src, "labels.ts"), "utf8");
    assert.match(labels, /NEIGHBOUR_CLEARANCE = 4/);
    // The cheap way out of a crowd is to make the name smaller than it is
    // drawn: the boxes stop touching, nothing is reported hidden, and both
    // named thresholds look untouched. The drawn size is pinned here, and
    // the sky is pinned to the same constant.
    assert.equal(AGENT_LABEL_SPRITE_SCALE, 0.036);
    assert.equal(PLANET_LABEL_SPRITE_SCALE, 0.05);
    assert.equal(LABEL_ASPECT_FALLBACK, 4);
    assert.match(labels, /AGENT_LABEL_SPRITE_SCALE = 0\.036/);
    assert.match(labels, /PLANET_LABEL_SPRITE_SCALE = 0\.05/);
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    assert.match(scene, /scale=\{\[AGENT_LABEL_SPRITE_SCALE \* l\.aspect, AGENT_LABEL_SPRITE_SCALE, 1\]\}/);
    assert.match(scene, /const PLANET_LABEL_HEIGHT = PLANET_LABEL_SPRITE_SCALE;/);
  });

  it("leaves no two names printing on top of each other at the focus seat", () => {
    // The rule that let this through measured a disk while a name is a box:
    // two names outside each other's disk still overlap when one is wider
    // than the disk is across. Measured 8 Sep: 7 overlapping pairs, 8 of 14
    // names fused, and the screen said nothing was hidden.
    const model = crowdModel(123, 9);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const radius = groupRadius(placed, planet.id);
    const seat = focusOrbit(planet.at, radius);
    const ndc = groupNdc(model, planet.id, seat);
    const crowd = labelCrowd(ndc, "agent", seat.distance, SCENE_RADIUS, STAGE_ASPECT);
    const shown = ndc.filter((_, i) => crowd.keep[i] === true);
    const pairs = overlappingPairs(shown);
    assert.equal(
      pairs.length,
      0,
      `names printing on top of another: ${pairs.map(([a, b]) => `${a}x${b}`).join(" ")}`,
    );
    // Whatever is not shown has to be counted out loud, or the screen is
    // hiding records again -- the same defect in a quieter form.
    assert.equal(crowd.hidden, ndc.length - shown.length);
    assert.ok(shown.length > 0, "the focus seat exists to make a group readable");
  });

  it("shows a 123-agent / 9-group neighborhood at the focus seat", () => {
    const model = crowdModel(123, 9);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const members = placed.agents.filter((a) => a.planetId === planet.id);
    const radius = groupRadius(placed, planet.id);
    const seat = focusOrbit(planet.at, radius);
    const ndc = groupNdc(model, planet.id, seat);
    const crowd = labelCrowd(ndc, "agent", seat.distance, SCENE_RADIUS, STAGE_ASPECT);
    const budget = labelBudget(members.length, seat.distance, radius);
    assert.ok(members.length > 0);
    // The seat exists so a group can be read, and the measure of that is
    // the sky it replaced: from the opening distance this same group is a
    // knot. Six of fourteen print clear at the seat; the other eight would
    // land on one of those six, so they stand down and are counted. The old
    // rule printed all fourteen and reported none hidden -- eight of them
    // fused (measured 8 Sep, still on screen 10 Sep).
    const shown = crowd.keep.filter((k) => k).length;
    assert.ok(shown > 0, "the seat makes nothing readable");
    assert.equal(crowd.hidden, ndc.length - shown);
    const away = createOrbit(OPENING_DISTANCE);
    const awayCam = { ...cameraPosition(away), fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };
    const awayNdc: Ndc[] = [];
    for (const agent of placed.agents) {
      if (agent.planetId !== planet.id) continue;
      const q = projectNdc(agent.at, awayCam);
      if (q) awayNdc.push(q);
    }
    const awayCrowd = labelCrowd(awayNdc, "agent", OPENING_DISTANCE, SCENE_RADIUS, STAGE_ASPECT);
    const awayShown = awayCrowd.keep.filter((k) => k).length;
    assert.ok(
      shown > awayShown,
      `the seat has to read better than the sky: seat ${shown}, sky ${awayShown}`,
    );
    assert.equal(budget.show, true);
    assert.equal(budget.hidden, 0);
  });

  it("is what the sky uses when a planet is chosen", () => {
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    assert.match(scene, /focusOrbit\(/);
    assert.match(scene, /data-focus=/);
    assert.match(scene, /CAMERA_NEAR/);
  });

  it("thins a 500-agent / 12-group neighborhood instead of smearing it", () => {
    const model = crowdModel(500, 12);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const radius = groupRadius(placed, planet.id);
    const seat = focusOrbit(planet.at, radius);
    const ndc = groupNdc(model, planet.id, seat);
    const crowd = labelCrowd(ndc, "agent", seat.distance, SCENE_RADIUS, STAGE_ASPECT);
    assert.ok(ndc.length >= 40, `members=${ndc.length}`);
    assert.equal(crowd.show, false);
    assert.equal(crowd.reason, "crowd");
    // Forty-two names into one seat: the ones that would land on a
    // neighbour stand down, the rest are printed, and nothing is on top of
    // anything. The count of what stood down is what the sky says out loud.
    const shown = ndc.filter((_, i) => crowd.keep[i] === true);
    assert.ok(crowd.hidden > 0, `hidden=${crowd.hidden} of ${ndc.length}`);
    assert.equal(shown.length, ndc.length - crowd.hidden);
    assert.equal(overlappingPairs(shown).length, 0);
    assert.ok(crowd.densest > 1, `densest=${crowd.densest}`);
  });

  it("still hides the same group from outside the sky", () => {
    const model = crowdModel(123, 9);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const members = placed.agents.filter((a) => a.planetId === planet.id);
    const orbit = createOrbit(85);
    const cam = { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };
    const ndc: Ndc[] = [];
    for (const agent of members) {
      const p = projectNdc(agent.at, cam);
      if (p) ndc.push(p);
    }
    const crowd = labelCrowd(ndc, "agent", 85, SCENE_RADIUS, STAGE_ASPECT);
    assert.equal(crowd.show, false);
    assert.equal(crowd.reason, "crowd");
  });
});
