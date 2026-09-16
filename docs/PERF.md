# Performance gates

Relative numbers only. Nothing here is a smoothness or throughput claim; a
gate compares a run against a baseline recorded on the same kind of machine.

## proxy-perf

`packages/proxy/perf/measure.ts` times the body's operations and writes
`last-*.json`; `packages/proxy/perf/check.mjs` hands each file to
`packages/proxy/perf/check-baseline.mjs`, where the one threshold lives.
`packages/proxy/perf/README.md` says what the runner's spread looks like and
what has to be true before the check becomes a gate.

## How check-baseline decides

- No frames (below the floor, or a zero value) fails first, known key or not.
  A run that measured nothing is a failure, never a "not compared".
- A key with no baseline prints `no baseline for <key>; not compared` and exits
  0. It compares nothing and does not say it did.
- Writing a baseline takes `VERAX_PERF_RECORD=1`, and it refuses to write over
  an entry that already exists, so a slow run cannot become its own threshold.
- With a baseline, the job fails when the measured value exceeds that entry
  x1.3.

## Galaxy frame times (removed 16 September 2026)

The panel drew a three.js galaxy from the ledger and the roster document, and
a `panel-perf` workflow measured its frame times under software GL on every
push. Both are gone: the panel is the records list, the black box and the
status view, and no workflow measures frames. The last committed baselines
were `win32/swiftshader/local/galaxy@5000` (p95 101.6 ms over 208 frames) and
`linux/swiftshader/gha-Linux/galaxy@5000` (p95 82.9 ms over 300 frames), both
from 8 September 2026, worst of three runs. Kept for the record; no run
produces them any more.

## Presence scene (historical)

Removed before the galaxy was. Kept for the record.

Headed GPU, Intel UHD, 5 September 2026, particle-only cloud:

| Points | Observed |
|---|---|
| 60000 | 3 frames/s |
| 30000 | 6.7 frames/s |
| 15000 | 240 frames/s |

Textured mesh plus particles, Chromium headed, 7 September 2026:

| Draw | Bloom | P95 (ms) | Frames |
|---|---|---|---|
| mesh + 20000 | off | 4.4 | 300 |
| mesh + 60000 | off | 4.5 | 300 |
| mesh + 20000 | on | 8.8 | 300 |
| mesh + 60000 | on | 7.3 | 300 |

Its software GL baselines were `win32/swiftshader/local` p95 73.6 over 282
frames and `linux/swiftshader/gha-Linux` p95 1043.5 over 10 frames, both from
5 September 2026. Both keys were removed rather than reinterpreted: no run
produces them any more.
