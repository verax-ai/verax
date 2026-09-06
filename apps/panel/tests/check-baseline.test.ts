import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "perf", "check-baseline.mjs");
const lastZero = join(root, "perf", "last-zero.json");

describe("panel-perf check-baseline", () => {
  it("fails last.json with frames 0 as panel-perf: no frames", () => {
    const ran = spawnSync(process.execPath, [script], {
      cwd: root,
      env: { ...process.env, VERAX_PERF_LAST: lastZero },
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(ran.status, 1, ran.stderr);
    assert.match(ran.stderr, /panel-perf: no frames/);
  });

  it("fails p95 0 even when frames meet the minimum", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perf-"));
    const last = join(dir, "last.json");
    writeFileSync(
      last,
      `${JSON.stringify({ key: "win32/swiftshader/local", frames: 40, p95: 0, gl: "swiftshader" })}\n`,
    );
    const ran = spawnSync(process.execPath, [script], {
      cwd: root,
      env: { ...process.env, VERAX_PERF_LAST: last },
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(ran.status, 1, ran.stderr);
    assert.match(ran.stderr, /panel-perf: no frames/);
  });
});
