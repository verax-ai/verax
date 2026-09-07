#!/usr/bin/env node
// Discovers *.test.ts and hands them to node --test. A directory argument
// is treated as a module under --experimental-strip-types, so files are
// listed explicitly.
//
// Cost suites (*-perf.test.ts) run in a second pass, on their own. They
// saturate the CPU and the disk, and node --test runs files concurrently,
// so in one pass they compete with the browser suites: on a two-core
// Windows runner that pushed a panel `page.goto` past its 30 s budget
// while the same page loaded in 11.5 s without them. The contention also
// ran the other way, since a cost measured under load measures the runner.
// Every file still runs, and neither guard is relaxed; only the schedule
// changes.

import { spawnSync } from "node:child_process";
import { globSync } from "node:fs";

const files = [
  ...globSync("tests/**/*.test.ts"),
  ...globSync("packages/*/tests/**/*.test.ts"),
  ...globSync("apps/*/tests/**/*.test.ts"),
].sort();

if (files.length === 0) {
  console.error("run-unit-tests: no test files found");
  process.exit(1);
}

const isPerf = (file: string) => /-perf\.test\.ts$/.test(file);
const perf = files.filter(isPerf);
const rest = files.filter((file) => !isPerf(file));

function run(batch: string[], label: string, extra: string[] = []): number {
  if (batch.length === 0) return 0;
  console.log(`run-unit-tests: ${label} (${batch.length} file(s))`);
  const result = spawnSync(
    process.execPath,
    ["--experimental-strip-types", "--test", ...extra, ...batch],
    { stdio: "inherit" },
  );
  return result.status === null ? 1 : result.status;
}

// Both passes run even when the first fails, so one report names every
// failure rather than only the earliest.
const restStatus = run(rest, "suites");
const perfStatus = run(perf, "cost suites, alone", ["--test-concurrency=1"]);

process.exit(restStatus || perfStatus);
