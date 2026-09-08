import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { panelBuildNeeded } from "../packages/body/src/desktop.ts";

function stamp(path: string, secondsAgo: number): void {
  const when = new Date(Date.now() - secondsAgo * 1000);
  utimesSync(path, when, when);
}

function tree(): { dist: string; src: string; file: string } {
  const dir = mkdtempSync(join(tmpdir(), "verax-panel-fresh-"));
  const src = join(dir, "src");
  mkdirSync(src, { recursive: true });
  const file = join(src, "App.tsx");
  writeFileSync(file, "export const a = 1;\n", "utf8");
  const distDir = join(dir, "dist");
  mkdirSync(distDir, { recursive: true });
  const dist = join(distDir, "index.html");
  writeFileSync(dist, "<!doctype html>\n", "utf8");
  return { dist, src, file };
}

/**
 * The launcher used to skip the build whenever dist/index.html existed, so a
 * desktop session served whatever had been built once, however old. Changing
 * the panel and reopening it showed the previous app.
 */
describe("panel build freshness", () => {
  it("builds when there is no build at all", () => {
    const { src } = tree();
    assert.equal(panelBuildNeeded(join(src, "..", "dist", "nothing.html"), [src]), true);
  });

  it("skips the build when every source is older than the build", () => {
    const { dist, src, file } = tree();
    stamp(file, 600);
    stamp(dist, 60);
    assert.equal(panelBuildNeeded(dist, [src]), false);
  });

  it("builds when a source is newer than the build", () => {
    const { dist, src, file } = tree();
    stamp(dist, 600);
    stamp(file, 60);
    assert.equal(
      panelBuildNeeded(dist, [src]),
      true,
      "an edited panel must not be served from the previous build",
    );
  });

  it("builds when a source in another watched place is newer", () => {
    const { dist, src } = tree();
    const other = mkdtempSync(join(tmpdir(), "verax-panel-dep-"));
    const dep = join(other, "Galaxy.tsx");
    writeFileSync(dep, "export const b = 2;\n", "utf8");
    stamp(dist, 600);
    stamp(dep, 30);
    assert.equal(panelBuildNeeded(dist, [src, other]), true);
  });
});
