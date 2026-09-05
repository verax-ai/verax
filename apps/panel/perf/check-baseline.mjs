#!/usr/bin/env node
import { readFileSync } from "node:fs";
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
if (!entry || typeof entry.p95 !== "number") {
  process.stdout.write(`no baseline for ${key}; recorded\n`);
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
