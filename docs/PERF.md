# Presence frame times

Relative numbers only. Software GL on a hosted runner is not a
smoothness claim. Absolute times on real GPUs belong in the table
below; a low-end row with P95 under 16.7 ms is not here yet.

panel-perf on hosted runners is a render smoke and a per-environment
regression guard; it is not an fps claim.

| Machine | GPU | Date | Tier | P95 (ms) |
|---|---|---|---|---|
| Windows 10 desktop (this tree) | Chromium `--use-gl=swiftshader` | 2026-09-04 | 15000 | 52.5 |

`apps/panel/perf/baseline.json` is keyed by
`platform/gl/local` or `platform/gl/gha-<runner.os>`. The committed
row is `win32/swiftshader/local`. There is no CI baseline yet.

`measure.mjs` stops at 20 s or 300 frames, whichever comes first.
Fewer than 30 frames is `render-failed`. Each run starts its own
preview on a strict port and tears it down; a busy port is an
error, not a fallback. When a key has a baseline,
the `panel-perf` job fails if `last.json` P95 exceeds that entry
x 1.3. When the key is missing, check-baseline writes
`no baseline for <key>; recorded` and passes; `last.json` is uploaded
as an artifact.
