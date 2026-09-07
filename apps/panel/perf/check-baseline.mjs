#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const lastPath = process.env.VERAX_PERF_LAST ?? join(dir, "last.json");
const baselinePath = process.env.VERAX_PERF_BASELINE ?? join(dir, "baseline.json");
const last = JSON.parse(readFileSync(lastPath, "utf8"));
const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
const gl = typeof last.gl === "string" && last.gl.length > 0 ? last.gl : "swiftshader";
const envTag = process.env.GITHUB_ACTIONS
  ? `gha-${process.env.RUNNER_OS ?? "unknown"}`
  : "local";
const key =
  typeof last.key === "string" && last.key.length > 0
    ? last.key
    : `${process.platform}/${gl}/${envTag}`;
const entry = baseline[key];
const minFrames = Number(process.env.VERAX_PERF_MIN_FRAMES ?? (process.env.GITHUB_ACTIONS ? 10 : 30));
const frames = typeof last.frames === "number" ? last.frames : 0;
const p95 = typeof last.p95 === "number" ? last.p95 : 0;
// A run that rendered nothing is a failure whether or not this key has a
// baseline: checking the key first would let a dead scene pass as "not compared".
if (frames < minFrames || p95 === 0) {
  process.stderr.write("panel-perf: no frames\n");
  process.exit(1);
}
if (!entry || typeof entry.p95 !== "number") {
  // An unknown key is not a pass either: nothing was compared. Recording is a
  // deliberate act (VERAX_PERF_RECORD=1), so a run cannot quietly become the
  // baseline it was supposed to be measured against.
  if (process.env.VERAX_PERF_RECORD !== "1") {
    process.stdout.write(`no baseline for ${key}; not compared\n`);
    process.exit(0);
  }
  baseline[key] = { p95, frames, at: new Date().toISOString() };
  writeFileSync(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  process.stdout.write(`recorded ${key} p95 ${p95} over ${frames} frames\n`);
  process.exit(0);
}
const limit = entry.p95 * 1.3;
if (last.p95 > limit) {
  process.stderr.write(
    `panel-perf: p95 ${last.p95} > ${limit} (baseline ${entry.p95} x 1.3)\n`,
  );
  process.exit(1);
}
process.stdout.write(`panel-perf: p95 ${last.p95} <= ${limit}\n`);
