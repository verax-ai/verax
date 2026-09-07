import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { globSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { TIER_DUST } from "../packages/galaxy/src/quality.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const measure = join(root, "apps", "panel", "perf", "measure.mjs");

/**
 * The dust ladder and the perf harness state the same quality knob in two
 * places. Nothing compared them, so the harness asked for a count the scene
 * does not have and the run measured a tier nobody chose.
 */
describe("perf harness agrees with the galaxy", () => {
  it("asks for a dust count the quality ladder actually has", async () => {
    // @ts-expect-error measure.mjs is an untyped script
    const { DEFAULT_TIER } = await import("../apps/panel/perf/measure.mjs");
    assert.equal(typeof DEFAULT_TIER, "number", "DEFAULT_TIER export missing");
    assert.ok(
      (TIER_DUST as readonly number[]).includes(DEFAULT_TIER),
      `harness tier ${DEFAULT_TIER} is not one of ${TIER_DUST.join(", ")}`,
    );
  });

  it("names the measured scene and tier in the baseline key", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perf-key-"));
    const last = join(dir, "last.json");
    await new Promise<void>((resolve) => {
      const child = spawn(process.execPath, [measure], {
        env: {
          ...process.env,
          VERAX_PERF_FAKE_FRAMES: "40",
          VERAX_PERF_LAST: last,
          VERAX_PERF_TIER: "5000",
          GITHUB_ACTIONS: "",
        },
        stdio: "ignore",
      });
      child.on("close", () => resolve());
    });
    const record = JSON.parse(readFileSync(last, "utf8")) as { key?: string };
    assert.equal(
      record.key,
      `${process.platform}/swiftshader/local/galaxy@5000`,
      "a key without the scene compares the galaxy against the old scene's baseline",
    );
  });

  it("only sets query flags the panel or the galaxy reads", async () => {
    // @ts-expect-error measure.mjs is an untyped script
    const { withTier, DEFAULT_TIER } = await import("../apps/panel/perf/measure.mjs");
    const prev = process.env.VERAX_PERF_BLOOM;
    process.env.VERAX_PERF_BLOOM = "1";
    let asked: string[];
    try {
      asked = [...new URL(withTier("http://127.0.0.1:4173/", DEFAULT_TIER)).searchParams.keys()];
    } finally {
      if (prev === undefined) delete process.env.VERAX_PERF_BLOOM;
      else process.env.VERAX_PERF_BLOOM = prev;
    }
    const sources = [
      ...globSync(join(root, "apps", "panel", "src", "**", "*.{ts,tsx}")),
      ...globSync(join(root, "packages", "galaxy", "src", "**", "*.{ts,tsx}")),
    ]
      .map((file) => readFileSync(file, "utf8"))
      .join(String.fromCharCode(10));
    for (const name of asked) {
      assert.ok(
        sources.includes(`get("${name}")`),
        `the harness sets ${name}=..., and no scene reads it: the run claims a setting it never applied`,
      );
    }
  });
});
