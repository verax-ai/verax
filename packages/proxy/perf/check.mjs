#!/usr/bin/env node
// Compares what measure.ts just wrote against this machine's own baseline, for
// each timed operation. The comparison itself lives in the panel's
// check-baseline.mjs and is not copied here: one threshold, one place.

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const checker = join(here, "..", "..", "..", "apps", "panel", "perf", "check-baseline.mjs");
const baseline = join(here, "baseline.json");

let failed = 0;
for (const name of ["call", "approve"]) {
  const out = spawnSync(process.execPath, [checker], {
    stdio: "inherit",
    env: {
      ...process.env,
      VERAX_PERF_LABEL: `proxy-perf/${name}`,
      VERAX_PERF_LAST: join(here, `last-${name}.json`),
      VERAX_PERF_BASELINE: baseline,
    },
  });
  if (out.status !== 0) failed += 1;
}
process.exit(failed === 0 ? 0 : 1);
