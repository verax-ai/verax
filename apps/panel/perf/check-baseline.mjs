#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const lastPath = process.env.VERAX_PERF_LAST ?? join(dir, "last.json");
const baselinePath = process.env.VERAX_PERF_BASELINE ?? join(dir, "baseline.json");
// Which probe is speaking. The panel measures frame times; the body measures
// processor time per operation. The comparison is the same either way.
const label = process.env.VERAX_PERF_LABEL ?? "panel-perf";
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
// `value` is what a probe compares; older runs only wrote `p95` and still do.
const measured = typeof last.value === "number" ? last.value : last.p95;
const p95 = typeof measured === "number" ? measured : 0;
// A run that rendered nothing is a failure whether or not this key has a
// baseline: checking the key first would let a dead scene pass as "not compared".
if (frames < minFrames || p95 === 0) {
  process.stderr.write(`${label}: no frames\n`);
  process.exit(1);
}
const baselineValue = entry && typeof entry.value === "number" ? entry.value : entry?.p95;
if (!entry || typeof baselineValue !== "number") {
  // An unknown key is not a pass either: nothing was compared. Recording is a
  // deliberate act (VERAX_PERF_RECORD=1), so a run cannot quietly become the
  // baseline it was supposed to be measured against.
  if (process.env.VERAX_PERF_RECORD !== "1") {
    process.stdout.write(`no baseline for ${key}; not compared\n`);
    process.exit(0);
  }
  baseline[key] = { value: p95, p95, frames, stat: last.stat ?? "p95", at: new Date().toISOString() };
  writeFileSync(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  process.stdout.write(`recorded ${key} p95 ${p95} over ${frames} frames\n`);
  process.exit(0);
}
const limit = baselineValue * 1.3;
if (p95 > limit) {
  process.stderr.write(`${label}: ${p95} > ${limit} (baseline ${baselineValue} x 1.3)\n`);
  process.exit(1);
}
process.stdout.write(`${label}: ${p95} <= ${limit}\n`);
