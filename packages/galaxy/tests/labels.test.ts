import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { cameraPosition, createOrbit, ZOOM_MIN } from "../src/camera.ts";
import {
  LABEL_FOV_DEG,
  densestNeighborhood,
  labelBudget,
  labelCrowd,
  labelText,
  paintLabel,
  projectNdc,
  type CameraEye,
  type Ndc,
} from "../src/labels.ts";
import { measured, unmeasured } from "../src/measured.ts";
import type { GalaxyModel } from "../src/model.ts";
import { placeScene, SCENE_RADIUS } from "../src/place.ts";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

type Call = { text: string; x: number; y: number };

function fakeCanvas(withContext: boolean) {
  const calls: Call[] = [];
  const ctx = {
    canvas: null as unknown,
    font: "",
    fillStyle: "",
    textAlign: "",
    textBaseline: "",
    measureText: (text: string) => ({ width: text.length * 10 }),
    clearRect: () => {},
    fillRect: () => {},
    fillText: (text: string, x: number, y: number) => calls.push({ text, x, y }),
  };
  const canvas = {
    width: 0,
    height: 0,
    getContext: (kind: string) => (withContext && kind === "2d" ? ctx : null),
  };
  return { canvas, calls };
}

describe("label text", () => {
  it("shows the name the record carries", () => {
    assert.equal(labelText("brain-alpha"), "brain-alpha");
  });

  it("has no label when the record carries no name", () => {
    assert.equal(labelText(""), null);
    assert.equal(labelText("   "), null);
    assert.equal(labelText(undefined), null);
  });
});

describe("label painting", () => {
  it("paints the name onto the canvas", () => {
    const { canvas, calls } = fakeCanvas(true);
    const painted = paintLabel(canvas as unknown as HTMLCanvasElement, "planet-7");
    assert.equal(painted, true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.text, "planet-7");
    assert.ok(canvas.width > 0 && canvas.height > 0, "canvas must be sized for the text");
  });

  it("paints nothing when the page gives no 2d context", () => {
    const { canvas, calls } = fakeCanvas(false);
    assert.equal(paintLabel(canvas as unknown as HTMLCanvasElement, "planet-7"), false);
    assert.equal(calls.length, 0);
  });
});

describe("label budget", () => {
  // Opening distance is Galaxy.OPENING_DISTANCE (85). Kept as a literal so
  // this file does not load the renderer.
  const opening = 85;

  it("keeps a handful of names readable at opening distance", () => {
    const three = labelBudget(3, opening, SCENE_RADIUS);
    assert.equal(three.show, true);
    assert.equal(three.hidden, 0);
    const two = labelBudget(2, opening, SCENE_RADIUS);
    assert.equal(two.show, true);
    assert.equal(two.hidden, 0);
  });

  it("hides a 500-name set at opening distance and returns it when closer", () => {
    const far = labelBudget(500, opening, SCENE_RADIUS);
    assert.equal(far.show, false);
    assert.equal(far.hidden, 500);
    const near = labelBudget(500, ZOOM_MIN, SCENE_RADIUS);
    assert.equal(near.show, true);
    assert.equal(near.hidden, 0);
    assert.notEqual(far.show, near.show);
  });

  it("does not show a subset: hidden is 0 or the whole count", () => {
    for (const count of [1, 3, 50, 500]) {
      for (const distance of [ZOOM_MIN, opening, 200, 400]) {
        const out = labelBudget(count, distance, SCENE_RADIUS);
        assert.ok(out.hidden === 0 || out.hidden === count, `count=${count} d=${distance}`);
      }
    }
  });

  it("still exports labelVisible for the LOD that this rule sits on", () => {
    const labels = readFileSync(join(src, "labels.ts"), "utf8");
    assert.match(labels, /export function labelVisible/);
    assert.match(labels, /export function labelBudget/);
    assert.match(labels, /export function labelCrowd/);
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    assert.match(scene, /labelCrowd\(/);
    assert.match(scene, /data-testid="galaxy-labels-hidden"/);
  });
});

const opening = 85;

function eyeAt(distance: number, yaw = 0, pitch = 0.62): CameraEye {
  const orbit = createOrbit(distance);
  orbit.yaw = yaw;
  orbit.pitch = pitch;
  orbit.targetYaw = yaw;
  orbit.targetPitch = pitch;
  orbit.targetDistance = distance;
  orbit.distance = distance;
  const p = cameraPosition(orbit);
  return { ...p, fovDeg: LABEL_FOV_DEG };
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
    planetId: groups > 0 ? `g-${(i % groups) + 1}` : null,
    lastActMs: measured(1, "test.agents"),
  }));
  return { ...emptyModel(), planets, agents };
}

function projectAgents(model: GalaxyModel, cam: CameraEye): Ndc[] {
  const out: Ndc[] = [];
  for (const agent of placeScene(model).agents) {
    const p = projectNdc(agent.at, cam);
    if (p) out.push(p);
  }
  return out;
}

/** World points on a sphere shell. Unassigned placeScene piles at the origin. */
function scatterNdc(count: number, cam: CameraEye, radius = 40): Ndc[] {
  const golden = Math.PI * (3 - Math.sqrt(5));
  const out: Ndc[] = [];
  for (let i = 0; i < count; i += 1) {
    const y = 1 - (i / Math.max(1, count - 1)) * 2;
    const ring = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = golden * i;
    const p = projectNdc(
      { x: Math.cos(theta) * ring * radius, y: y * radius * 0.55, z: Math.sin(theta) * ring * radius },
      cam,
    );
    if (p) out.push(p);
  }
  return out;
}

describe("label crowd (neighborhood, not scene average)", () => {
  it("gives a clustered 500 and a scattered 500 different answers at the same count", () => {
    const cam = eyeAt(ZOOM_MIN);
    const clustered = labelCrowd(projectAgents(crowdModel(500, 12), cam), "agent", ZOOM_MIN, SCENE_RADIUS);
    const scattered = labelCrowd(scatterNdc(500, cam), "agent", ZOOM_MIN, SCENE_RADIUS);
    assert.equal(clustered.show, false);
    assert.equal(clustered.hidden, 500);
    assert.equal(clustered.reason, "crowd");
    assert.ok(clustered.densest > scattered.densest, `densest clustered=${clustered.densest} scattered=${scattered.densest}`);
    assert.equal(scattered.show, true);
    assert.equal(scattered.hidden, 0);
    assert.notEqual(clustered.show, scattered.show);
  });

  it("does not return clustered names at near zoom when the knot is still dense", () => {
    const cam = eyeAt(ZOOM_MIN);
    const clustered = labelCrowd(projectAgents(crowdModel(500, 12), cam), "agent", ZOOM_MIN, SCENE_RADIUS);
    assert.equal(clustered.show, false);
    assert.equal(clustered.hidden, 500);
    assert.equal(clustered.reason, "crowd");
  });

  it("returns scattered names at near zoom once each neighborhood holds one name", () => {
    const cam = eyeAt(ZOOM_MIN);
    const scattered = labelCrowd(scatterNdc(500, cam), "agent", ZOOM_MIN, SCENE_RADIUS);
    assert.equal(scattered.show, true);
    assert.equal(scattered.hidden, 0);
    assert.ok(scattered.densest <= 4, `densest=${scattered.densest}`);
  });

  it("keeps a three-name fixture readable and named", () => {
    const cam = eyeAt(opening);
    const three = crowdModel(3, 2);
    const ndc = projectAgents(three, cam);
    const out = labelCrowd(ndc, "agent", opening, SCENE_RADIUS);
    assert.equal(ndc.length, 3);
    assert.equal(out.show, true);
    assert.equal(out.hidden, 0);
    assert.ok(out.densest <= 4, `densest=${out.densest}`);
  });

  it("does not show a subset: hidden is 0 or the whole projected count", () => {
    const camNear = eyeAt(ZOOM_MIN);
    const camFar = eyeAt(opening);
    for (const [ndc, distance] of [
      [projectAgents(crowdModel(500, 12), camNear), ZOOM_MIN],
      [scatterNdc(500, camNear), ZOOM_MIN],
      [projectAgents(crowdModel(3, 2), camFar), opening],
      [scatterNdc(500, camFar), opening],
    ] as const) {
      const out = labelCrowd(ndc, "agent", distance, SCENE_RADIUS);
      assert.ok(out.hidden === 0 || out.hidden === ndc.length, `hidden=${out.hidden} n=${ndc.length}`);
    }
  });

  it("changes when the camera turns, because the metric is the image", () => {
    const along = eyeAt(80, 0, 0);
    const endOn = eyeAt(80, Math.PI / 2, 0);
    const worlds = Array.from({ length: 20 }, (_, i) => ({ x: (i - 10) * 2.4, y: 0, z: 0 }));
    const face = worlds.map((w) => projectNdc(w, along)).filter((p): p is Ndc => p !== null);
    const edge = worlds.map((w) => projectNdc(w, endOn)).filter((p): p is Ndc => p !== null);
    assert.ok(face.length > 0 && edge.length > 0);
    assert.notEqual(densestNeighborhood(face), densestNeighborhood(edge));
    const faceCrowd = labelCrowd(face, "agent", 80, SCENE_RADIUS);
    const edgeCrowd = labelCrowd(edge, "agent", 80, SCENE_RADIUS);
    assert.notEqual(faceCrowd.show, edgeCrowd.show);
  });
});

describe("no label sprite without a name on it", () => {
  it("never mounts a spriteMaterial without a texture", () => {
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    const materials = scene.match(/<spriteMaterial[^>]*>/g) ?? [];
    assert.ok(materials.length > 0, "the galaxy has no label sprites at all");
    for (const tag of materials) {
      assert.match(
        tag,
        /map=/,
        "a sprite with no texture is a coloured box pretending to be a name",
      );
    }
  });
});
