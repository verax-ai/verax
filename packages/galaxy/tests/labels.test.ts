import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { cameraPosition, createOrbit, ZOOM_MAX, ZOOM_MIN } from "../src/camera.ts";
import {
  AGENT_LABEL_SPRITE_SCALE,
  LABEL_FOV_DEG,
  densestOverlap,
  labelNdcHeight,
  PLANET_LABEL_SPRITE_SCALE,
  readableLabels,
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

/**
 * The canvas the sky is drawn on: measured off the live 1440x900 capture,
 * the galaxy stage is 580 x 630 CSS pixels because it sits in the middle
 * pane. The camera divides x by this.
 */
const STAGE_ASPECT = 580 / 630;
const BOX = { spriteScale: AGENT_LABEL_SPRITE_SCALE, fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };


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
    assert.match(scene, /crowdedLabelsText/);
    assert.match(scene, /data-reason=/);
    assert.match(scene, /hiddenLabels > 0 && hiddenLine/);
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
  return { ...p, fovDeg: LABEL_FOV_DEG, viewportAspect: STAGE_ASPECT };
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
    const clusteredNdc = projectAgents(crowdModel(500, 12), cam);
    const clustered = labelCrowd(clusteredNdc, "agent", ZOOM_MIN, SCENE_RADIUS, STAGE_ASPECT);
    const scattered = labelCrowd(scatterNdc(500, cam), "agent", ZOOM_MIN, SCENE_RADIUS, STAGE_ASPECT);
    assert.equal(clustered.show, false);
    assert.ok(clustered.hidden > 0);
    assert.equal(clustered.reason, "crowd");
    assert.ok(clustered.densest > scattered.densest, `densest clustered=${clustered.densest} scattered=${scattered.densest}`);
    assert.equal(scattered.show, true);
    assert.equal(scattered.hidden, 0);
    assert.notEqual(clustered.show, scattered.show);
    // The knot loses names, the open sky loses none.
    assert.ok(clustered.hidden > scattered.hidden);
  });

  it("prints no name on top of another when the knot is still dense", () => {
    const cam = eyeAt(ZOOM_MIN);
    const clusteredNdc = projectAgents(crowdModel(500, 12), cam);
    const clustered = labelCrowd(clusteredNdc, "agent", ZOOM_MIN, SCENE_RADIUS, STAGE_ASPECT);
    assert.equal(clustered.show, false);
    assert.ok(clustered.hidden > 0);
    assert.equal(clustered.reason, "crowd");
    // The knot is thinned, not smeared: what is left standing is readable,
    // and what stood down is in the count.
    const shown = clusteredNdc.filter((_, i) => clustered.keep[i] === true);
    assert.equal(shown.length, clusteredNdc.length - clustered.hidden);
    assert.equal(densestOverlap(shown, BOX), 1);
  });

  it("keeps a hidden count at near zoom on a clustered 500 so the confession line stays", () => {
    const cam = eyeAt(ZOOM_MIN);
    const clustered = labelCrowd(projectAgents(crowdModel(500, 12), cam), "agent", ZOOM_MIN, SCENE_RADIUS, STAGE_ASPECT);
    assert.ok(clustered.hidden > 0);
    assert.equal(clustered.reason, "crowd");
  });

  it("names a far handful as distance, not crowd", () => {
    const cam = eyeAt(ZOOM_MAX);
    const out = labelCrowd(projectAgents(crowdModel(3, 2), cam), "agent", ZOOM_MAX, SCENE_RADIUS, STAGE_ASPECT);
    assert.equal(out.show, false);
    assert.equal(out.reason, "distance");
  });

  it("returns scattered names at near zoom once each neighborhood holds one name", () => {
    const cam = eyeAt(ZOOM_MIN);
    const scattered = labelCrowd(scatterNdc(500, cam), "agent", ZOOM_MIN, SCENE_RADIUS, STAGE_ASPECT);
    assert.equal(scattered.show, true);
    assert.equal(scattered.hidden, 0);
    assert.equal(scattered.densest, 1, "nothing touches, so every box is alone");
  });

  it("keeps a three-name fixture readable, and stands down the one it would sit on", () => {
    const cam = eyeAt(opening);
    const three = crowdModel(3, 2);
    const ndc = projectAgents(three, cam);
    const out = labelCrowd(ndc, "agent", opening, SCENE_RADIUS, STAGE_ASPECT);
    assert.equal(ndc.length, 3);
    // Two of the three share a planet and land 0.012 NDC apart at the
    // opening distance, inside a box 0.144 wide: printing both is the white
    // smear this rule exists to stop. The old disk called them readable.
    assert.equal(out.hidden, 1);
    assert.equal(out.reason, "crowd");
    assert.equal(out.keep.filter((k) => k).length, 2);
    const shown = ndc.filter((_, i) => out.keep[i] === true);
    assert.equal(densestOverlap(shown, BOX), 1);
  });

  it("hides a far set whole, and a near one name by name", () => {
    // Distance is still all-or-nothing: at that range no arrangement of
    // these names is readable, and printing eight of five hundred would
    // leak, through which names survived, a count we are not making.
    // Close in the question is different -- the names are readable, some
    // of them land on each other -- so the set is thinned rather than
    // dropped, and every name stood down is counted in the line the sky
    // prints. Hiding fourteen readable names because two touch was the
    // other half of the defect measured on 8 Sep.
    const camFar = eyeAt(ZOOM_MAX);
    for (const ndc of [projectAgents(crowdModel(500, 12), camFar), scatterNdc(500, camFar)]) {
      const out = labelCrowd(ndc, "agent", ZOOM_MAX, SCENE_RADIUS, STAGE_ASPECT);
      assert.equal(out.reason, "distance");
      assert.equal(out.hidden, ndc.length);
      assert.ok(out.keep.every((k) => k === false));
    }
    const camNear = eyeAt(ZOOM_MIN);
    const near = projectAgents(crowdModel(500, 12), camNear);
    const out = labelCrowd(near, "agent", ZOOM_MIN, SCENE_RADIUS, STAGE_ASPECT);
    assert.ok(out.hidden > 0 && out.hidden < near.length, `hidden=${out.hidden} n=${near.length}`);
    assert.equal(out.keep.filter((k) => k).length, near.length - out.hidden);
    const shown = near.filter((_, i) => out.keep[i] === true);
    assert.equal(densestOverlap(shown, BOX), 1, "a printed name has nothing on top of it");
  });

  it("keeps an agent name off a group name that is already printed", () => {
    // Each kind used to be judged only against its own, so a group name and
    // an agent name could be printed on the same spot -- the same smear,
    // seen on the overview on 10 Sep. Group names go down first and keep
    // their claim; agent names have to clear them.
    const planetBox = {
      spriteScale: PLANET_LABEL_SPRITE_SCALE,
      fovDeg: LABEL_FOV_DEG,
      viewportAspect: STAGE_ASPECT,
    };
    const group = { x: 0.1, y: -0.2 };
    const taken = [{ at: group, box: planetBox }];
    const onTop = [{ x: 0.105, y: -0.198 }];
    const clear = [{ x: 0.9, y: 0.6 }];
    const free = readableLabels([...onTop, ...clear], BOX);
    assert.deepEqual(free.keep, [true, true], "nothing else on screen, both print");
    const guarded = readableLabels([...onTop, ...clear], BOX, taken);
    assert.deepEqual(guarded.keep, [false, true]);
    assert.equal(guarded.hidden, 1);
  });

  it("changes when the camera turns, because the metric is the image", () => {
    const along = eyeAt(80, 0, 0);
    const endOn = eyeAt(80, Math.PI / 2, 0);
    const worlds = Array.from({ length: 20 }, (_, i) => ({ x: (i - 10) * 2.4, y: 0, z: 0 }));
    const face = worlds.map((w) => projectNdc(w, along)).filter((p): p is Ndc => p !== null);
    const edge = worlds.map((w) => projectNdc(w, endOn)).filter((p): p is Ndc => p !== null);
    assert.ok(face.length > 0 && edge.length > 0);
    assert.notEqual(
      densestOverlap(face, BOX),
      densestOverlap(edge, BOX),
    );
    const faceCrowd = labelCrowd(face, "agent", 80, SCENE_RADIUS, STAGE_ASPECT);
    const edgeCrowd = labelCrowd(edge, "agent", 80, SCENE_RADIUS, STAGE_ASPECT);
    // Twenty names on one line: seen face-on they spread out and most are
    // printed; seen end-on they stack into one point and nearly all stand
    // down. Same records, same count, different image -- so a different
    // answer, which is what "the metric is the image" means.
    assert.ok(faceCrowd.hidden < edgeCrowd.hidden, `face=${faceCrowd.hidden} edge=${edgeCrowd.hidden}`);
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
