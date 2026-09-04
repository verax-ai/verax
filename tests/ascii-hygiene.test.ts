import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("8 optional ASCII in three named files", () => {
  it("wiring, sample-points, and index.html titles use ASCII arrows", () => {
    const wiring = readFileSync(join(root, "packages", "body", "src", "wiring.ts"), "utf8");
    const sample = readFileSync(join(root, "scripts", "sample-points.mjs"), "utf8");
    const html = readFileSync(join(root, "apps", "panel", "index.html"), "utf8");
    assert.deepEqual(
      {
        wiringArrow: wiring.includes("\u2192"),
        sampleDash: sample.includes("\u2014"),
        htmlDash: html.includes("\u2014"),
      },
      { wiringArrow: false, sampleDash: false, htmlDash: false },
    );
  });
});
