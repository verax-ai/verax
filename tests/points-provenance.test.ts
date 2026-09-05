import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("7 point cloud provenance", () => {
  it("STATUS states the operator source and the sidecar has a source field", () => {
    const status = readFileSync(join(root, "docs", "STATUS.md"), "utf8");
    const meta = JSON.parse(readFileSync(join(root, "apps", "panel", "public", "verax-points.json"), "utf8")) as {
      source?: unknown;
    };
    assert.equal(status.includes("provenance unverified"), false);
    assert.equal(typeof meta.source, "string");
    assert.equal(
      meta.source,
      "operator-generated (ChatGPT image, Meshy AI paid plan); see docs/STATUS.md",
    );
    assert.equal(status.includes("ChatGPT"), true);
    assert.equal(status.includes("Meshy AI"), true);
    assert.equal(status.includes("NOTICE"), false);
    assert.equal(status.includes("CC BY"), false);
  });
});
