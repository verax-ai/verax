#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const last = JSON.parse(readFileSync(join(dir, "last.json"), "utf8"));
const baseline = JSON.parse(readFileSync(join(dir, "baseline.json"), "utf8"));
const limit = baseline.p95 * 1.3;
if (last.p95 > limit) {
  process.stderr.write(`panel-perf: p95 ${last.p95} > ${limit} (baseline ${baseline.p95} x 1.3)\n`);
  process.exit(1);
}
process.stdout.write(`panel-perf: p95 ${last.p95} <= ${limit}\n`);
