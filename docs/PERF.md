# Presence frame times

Relative numbers only. Software GL on a hosted runner is not a
smoothness claim. Absolute times on real GPUs belong in the table
below.

panel-perf on hosted runners is a render smoke and a per-environment
regression guard; it is not an fps claim.

## Headed GPU (Intel UHD, this laptop, 2026-09-05)

Old particle-only cloud (DEVIR 2026-09-05):

| Points | Observed |
|---|---|
| 60000 | 3 frames/s |
| 30000 | 6.7 frames/s |
| 15000 | 240 frames/s |

New textured mesh + particles (Chromium headed, default GPU):

| Draw | Bloom | P95 (ms) | Frames |
|---|---|---|---|
| mesh + 20000 | off | 4.4 | 300 |
| mesh + 10000 | off | 4.5 | 300 |
| mesh + 5000 | off | 4.5 | 300 |
| mesh + 20000 | on | 8.8 | 300 |

Default tier (20000, bloom off) is under the 16.7 ms window. Bloom
roughly doubles P95 and still stays under the window.

## Software GL baselines

| Machine | GPU | Date | Tier | P95 (ms) | Frames |
|---|---|---|---|---|---|
| Windows laptop, Intel UHD | Chromium `--use-gl=swiftshader` | 2026-09-05 | 20000 | 73.6 | 282 |
| GitHub Actions ubuntu-latest | Chromium `--use-gl=swiftshader` | 2026-09-05 | default | 1043.5 | 10 |

`apps/panel/perf/baseline.json` is keyed by
`platform/gl/local` or `platform/gl/gha-<runner.os>`. Committed keys:
`win32/swiftshader/local` and `linux/swiftshader/gha-Linux`.

On `GITHUB_ACTIONS`, `measure.mjs` uses a 40 s budget and accepts 10
frames. Locally it still wants 30 frames in 20 s.

`measure.mjs` stops at the budget or 300 frames, whichever comes first.
Fewer than the floor is `render-failed`. Each run starts its own
preview on a strict port and tears it down; a busy port is an
error, not a fallback. `--url` probes an already-running page.
When a key has a baseline,
the `panel-perf` job fails if `last.json` P95 exceeds that entry
x 1.3. When the key is missing, check-baseline writes
`no baseline for <key>; recorded` and passes; `last.json` is uploaded
as an artifact.
