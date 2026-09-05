import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ids = ["head", "face", "core", "left-hand", "right-hand", "torso", "ground"];

describe("anchors", () => {
  it("has seven points inside the sampled bbox", () => {
    const anchors = JSON.parse(
      readFileSync(join(root, "apps", "body-map", "src", "anchors.json"), "utf8"),
    ) as Record<string, [number, number, number]>;
    const meta = JSON.parse(readFileSync(join(root, "apps", "panel", "public", "verax-points.json"), "utf8")) as {
      bbox: { min: [number, number, number]; max: [number, number, number] };
    };
    assert.deepEqual(Object.keys(anchors).sort(), [...ids].sort());
    for (const id of ids) {
      const p = anchors[id];
      assert.ok(p, id);
      for (let i = 0; i < 3; i += 1) {
        assert.ok(p![i]! >= meta.bbox.min[i]! - 0.05, `${id} min ${i}`);
        assert.ok(p![i]! <= meta.bbox.max[i]! + 0.05, `${id} max ${i}`);
      }
    }
  });
});
