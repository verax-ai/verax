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
  LABEL_FOV_DEG,
  LABEL_READABLE_NEIGHBORS,
  labelBudget,
  labelCrowd,
  projectNdc,
  type Ndc,
} from "../src/labels.ts";
import { measured, unmeasured } from "../src/measured.ts";
import type { GalaxyModel } from "../src/model.ts";
import { groupRadius, GROUP_RADIUS, placeScene, SCENE_RADIUS } from "../src/place.ts";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

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
  const cam = { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG };
  const out: Ndc[] = [];
  for (const agent of placeScene(model).agents) {
    if (agent.planetId !== planetId) continue;
    const p = projectNdc(agent.at, cam);
    if (p) out.push(p);
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
  it("does not relax the crowd threshold", () => {
    assert.equal(LABEL_READABLE_NEIGHBORS, 4);
    const labels = readFileSync(join(src, "labels.ts"), "utf8");
    assert.match(labels, /LABEL_READABLE_NEIGHBORS = 4/);
    assert.match(labels, /NEIGHBOUR_CLEARANCE = 4/);
  });

  it("shows a 123-agent / 9-group neighborhood at the focus seat", () => {
    const model = crowdModel(123, 9);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const members = placed.agents.filter((a) => a.planetId === planet.id);
    const radius = groupRadius(placed, planet.id);
    const seat = focusOrbit(planet.at, radius);
    const ndc = groupNdc(model, planet.id, seat);
    const crowd = labelCrowd(ndc, "agent", seat.distance, SCENE_RADIUS);
    const budget = labelBudget(members.length, seat.distance, radius);
    assert.ok(members.length > 0);
    assert.equal(crowd.show, true, `crowd show=false densest=${crowd.densest} hidden=${crowd.hidden}`);
    assert.equal(crowd.hidden, 0);
    assert.equal(budget.show, true);
    assert.equal(budget.hidden, 0);
  });

  it("is what the sky uses when a planet is chosen", () => {
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    assert.match(scene, /focusOrbit\(/);
    assert.match(scene, /data-focus=/);
    assert.match(scene, /CAMERA_NEAR/);
  });

  it("keeps a 500-agent / 12-group neighborhood hidden: forty-two in that disk is still a crowd", () => {
    const model = crowdModel(500, 12);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const radius = groupRadius(placed, planet.id);
    const seat = focusOrbit(planet.at, radius);
    const ndc = groupNdc(model, planet.id, seat);
    const crowd = labelCrowd(ndc, "agent", seat.distance, SCENE_RADIUS);
    assert.ok(ndc.length >= 40, `members=${ndc.length}`);
    assert.equal(crowd.show, false);
    assert.equal(crowd.reason, "crowd");
    assert.ok(crowd.densest > LABEL_READABLE_NEIGHBORS, `densest=${crowd.densest}`);
  });

  it("still hides the same group from outside the sky", () => {
    const model = crowdModel(123, 9);
    const placed = placeScene(model);
    const planet = placed.planets[0]!;
    const members = placed.agents.filter((a) => a.planetId === planet.id);
    const orbit = createOrbit(85);
    const cam = { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG };
    const ndc: Ndc[] = [];
    for (const agent of members) {
      const p = projectNdc(agent.at, cam);
      if (p) ndc.push(p);
    }
    const crowd = labelCrowd(ndc, "agent", 85, SCENE_RADIUS);
    assert.equal(crowd.show, false);
    assert.equal(crowd.reason, "crowd");
  });
});
