# Presence frame times

Relative numbers only. Software GL on a hosted runner is not a
smoothness claim. Absolute times on real GPUs belong in the table
below; a low-end row with P95 under 16.7 ms is not here yet.

| Machine | GPU | Date | Tier | P95 (ms) |
|---|---|---|---|---|
| Windows 10 desktop (this tree) | Chromium `--use-gl=swiftshader` | 2026-09-04 | 15000 | 52.5 |

`apps/panel/perf/baseline.json` records the same swiftshader 15k row.
The `panel-perf` job fails when a later `last.json` P95 exceeds
baseline x 1.3.
