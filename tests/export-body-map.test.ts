import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "export-body-map.mjs");

describe("export-body-map", () => {
  it("exits 2 when the destination argument is missing", () => {
    const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /pass the destination directory/);
  });
});
