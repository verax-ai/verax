import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { labelText, paintLabel } from "../src/labels.ts";

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
