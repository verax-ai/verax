import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const jsonPath = join(root, "apps", "panel", "public", "verax-points.json");
const glb = process.env.VERAX_MODEL_GLB;

describe("points-source", () => {
  it("matches VERAX_MODEL_GLB sha256 when the env is set", { skip: !glb }, () => {
    const meta = JSON.parse(readFileSync(jsonPath, "utf8")) as { sourceSha256?: string };
    const digest = createHash("sha256").update(readFileSync(glb!)).digest("hex");
    assert.equal(meta.sourceSha256, digest);
  });
});
