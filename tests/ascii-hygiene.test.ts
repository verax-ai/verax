import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("8 optional ASCII in two named files", () => {
  it("wiring and index.html titles use ASCII arrows", () => {
    const wiring = readFileSync(join(root, "packages", "body", "src", "wiring.ts"), "utf8");
    const html = readFileSync(join(root, "apps", "panel", "index.html"), "utf8");
    assert.deepEqual(
      {
        wiringArrow: wiring.includes("\u2192"),
        htmlDash: html.includes("\u2014"),
      },
      { wiringArrow: false, htmlDash: false },
    );
  });
});
