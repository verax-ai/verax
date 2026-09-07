import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import type { AgentDraw, CoreDraw, PlanetDraw } from "../src/draw.ts";
import type { Measured } from "../src/measured.ts";

const srcDir = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

const VISUAL = ["pulse", "size", "freshness", "ring", "lastActMs", "brightness", "color"] as const;

function walkTs(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return walkTs(p);
    return e.name.endsWith(".ts") && !e.name.endsWith(".d.ts") ? [p] : [];
  });
}

/** Compile-time: every visual field on the public draw inputs is Measured. */
type VisualOf<T, K extends keyof T> = T[K] extends Measured<unknown> | undefined ? true : false;
const _corePulse: VisualOf<CoreDraw, "pulse"> = true;
const _planetSize: VisualOf<PlanetDraw, "size"> = true;
const _planetFresh: VisualOf<PlanetDraw, "freshness"> = true;
const _planetRing: VisualOf<PlanetDraw, "ring"> = true;
const _agentAct: VisualOf<AgentDraw, "lastActMs"> = true;
void _corePulse;
void _planetSize;
void _planetFresh;
void _planetRing;
void _agentAct;

describe("draw API Measured guard", () => {
  it("public draw inputs wrap every size/brightness/color field in Measured", () => {
    const hits: string[] = [];
    for (const file of walkTs(srcDir)) {
      const text = readFileSync(file, "utf8");
      const rel = file.slice(srcDir.length + 1).replace(/\\/g, "/");
      if (rel === "address.ts") continue;
      const withoutAppearance = text.replace(/export type Appearance\s*=\s*\{[\s\S]*?\};/g, "");
      for (const field of VISUAL) {
        const bare = new RegExp(
          `export\\s+type\\s+(?!Appearance\\b)\\w+\\s*=\\s*\\{[^}]*\\b${field}\\s*:\\s*number\\b`,
          "s",
        );
        if (bare.test(withoutAppearance)) hits.push(`${rel}: ${field}: number`);
        const fnBare = new RegExp(`export\\s+function\\s+\\w+\\s*\\([^)]*\\b${field}\\s*:\\s*number\\b`);
        if (fnBare.test(withoutAppearance)) hits.push(`${rel}: function ${field}: number`);
      }
    }
    assert.deepEqual(hits, []);
  });

  it("appearance helpers refuse a raw number at the type boundary", () => {
    // Runtime stand-in: the helpers only accept Measured objects.
    const src = readFileSync(join(srcDir, "draw.ts"), "utf8");
    assert.match(src, /pulse:\s*Measured<number>/);
    assert.match(src, /size:\s*Measured<number>/);
    assert.match(src, /freshness:\s*Measured<number>/);
    assert.match(src, /lastActMs:\s*Measured<number>/);
    assert.doesNotMatch(src, /export function \w+\([^)]*\b(?:pulse|size|freshness|ring|lastActMs)\s*:\s*number\b/);
  });
});
