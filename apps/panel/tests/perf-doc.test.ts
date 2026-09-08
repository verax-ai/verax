import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { TIER_DUST } from "../../../packages/galaxy/src/quality.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const doc = () => readFileSync(join(root, "docs", "PERF.md"), "utf8");
const baseline = () =>
  JSON.parse(readFileSync(join(root, "apps", "panel", "perf", "baseline.json"), "utf8")) as Record<
    string,
    unknown
  >;

/**
 * PERF.md and the harness state the same facts. Nothing compared them, so the
 * document kept describing the scene, the keys and the messages of a harness
 * that had already changed.
 */
describe("PERF.md still describes this harness", () => {
  it("names every key the baseline actually holds", () => {
    const text = doc();
    for (const key of Object.keys(baseline())) {
      assert.ok(text.includes(key), `PERF.md does not name the committed key ${key}`);
    }
  });

  it("does not name a key the baseline dropped", () => {
    const text = doc();
    const held = Object.keys(baseline());
    const named = text.match(/`(?:win32|linux|darwin)\/[a-z]+\/[A-Za-z-]+\/galaxy@\d+`/g) ?? [];
    assert.ok(named.length > 0, "PERF.md names no baseline key at all");
    for (const raw of named) {
      const key = raw.slice(1, -1);
      assert.ok(held.includes(key), `PERF.md names ${key}, which the baseline no longer holds`);
    }
  });

  it("quotes the tier the harness actually asks for", async () => {
    // @ts-expect-error measure.mjs is an untyped script
    const { DEFAULT_TIER } = await import("../perf/measure.mjs");
    const text = doc();
    const quoted = [...text.matchAll(/galaxy@(\d+)/g)].map((m) => Number(m[1]));
    assert.ok(quoted.length > 0, "PERF.md quotes no tier");
    for (const tier of quoted) {
      assert.ok(
        (TIER_DUST as readonly number[]).includes(tier),
        `PERF.md quotes tier ${tier}, which is not a rung of the ladder`,
      );
    }
    assert.ok(
      quoted.includes(DEFAULT_TIER),
      `PERF.md never quotes the default tier ${DEFAULT_TIER}`,
    );
  });

  it("does not promise the message check-baseline stopped printing", () => {
    assert.doesNotMatch(
      doc(),
      /; recorded`? and passes/,
      "PERF.md still says an unknown key is recorded; it is reported as not compared",
    );
  });
});
