import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { labelBudget, labelText, paintLabel } from "../src/labels.ts";
import { ZOOM_MIN } from "../src/camera.ts";
import { SCENE_RADIUS } from "../src/place.ts";

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
    const scene = readFileSync(join(src, "Galaxy.tsx"), "utf8");
    assert.match(scene, /labelVisible\(/);
    assert.match(scene, /labelBudget\(/);
    assert.match(scene, /data-testid="galaxy-labels-hidden"/);
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
