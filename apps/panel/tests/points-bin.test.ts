import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const pub = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

describe("committed point cloud", () => {
  it("has version 1, 60000 points, and a matching json sidecar", () => {
    const bin = readFileSync(join(pub, "verax-points.bin"));
    const meta = JSON.parse(readFileSync(join(pub, "verax-points.json"), "utf8")) as {
      version: number;
      count: number;
    };
    assert.equal(bin.readUInt32LE(0), 1);
    assert.equal(bin.readUInt32LE(4), 60_000);
    assert.equal(bin.length, 32 + 60_000 * 6);
    assert.equal(meta.version, 1);
    assert.equal(meta.count, 60_000);
  });
});
