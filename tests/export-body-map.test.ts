import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts", "export-body-map.mjs");
const dist = join(root, "apps", "body-map", "dist");

describe("export-body-map", () => {
  it("exits 2 when the destination argument is missing", () => {
    const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /pass the destination directory/);
  });

  it("drops stale hashed bundles from the destination before copying", { skip: !existsSync(dist) }, () => {
    const dest = mkdtempSync(join(tmpdir(), "verax-export-"));
    try {
      mkdirSync(join(dest, "assets"), { recursive: true });
      writeFileSync(join(dest, "assets", "index-STALE0000.js"), "stale");
      writeFileSync(join(dest, "assets", "keep.txt"), "keep");
      const result = spawnSync(process.execPath, [script, dest], { encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      const names = readdirSync(join(dest, "assets"));
      assert.ok(!names.includes("index-STALE0000.js"), "stale bundle should be removed");
      assert.ok(names.includes("keep.txt"), "unrelated files stay");
      assert.ok(names.some((n) => /^index-[A-Za-z0-9_-]+\.js$/.test(n)), "fresh bundle copied");
    } finally {
      rmSync(dest, { recursive: true, force: true });
    }
  });
});
