# Galaxy frame times

Relative numbers only. Software GL is not a smoothness claim, and
`panel-perf` on a hosted runner is a render smoke plus a per-environment
regression guard, not an fps claim. Absolute times belong in the GPU table
below.

## What panel-perf measures

The galaxy tab, already open, on demo data: `?tab=galaxy&open=1&demo=1&tier=<n>`.
The tier is a dust count and must be a rung of the ladder in
`packages/galaxy/src/quality.ts`:

| Tier | Dust | Bloom |
|---|---|---|
| 20000 | 20000 | full |
| 10000 | 10000 | mid |
| 5000 | 5000 | off |

`measure.mjs` asks for 5000 by default. A tier the ladder does not have is
snapped to the nearest rung, and a forced tier also switches off the scene's own
quality ladder - so a harness asking for a number that is not a rung measures a
quality setting nobody chose. `tests/perf-harness-agreement.test.ts` compares the
harness default against the ladder so the two cannot drift apart.

## Real GPU

Chromium headed, default GPU (Intel UHD, this laptop), 8 September 2026:

| Tier | Bloom | P95 (ms) | Frames |
|---|---|---|---|
| 20000 | full | 4.3 | 300 |
| 5000 | off | 4.5 | 300 |

The heaviest rung is well under the 16.7 ms window. This is a single-machine
measurement, not an fps claim.

## Software GL - what the gate compares against

Chromium `--use-gl=swiftshader`, 8 September 2026, worst of three runs each:

| Environment | Tier | P95 (ms) | Frames | Runs |
|---|---|---|---|---|
| Windows laptop, Intel UHD | 5000 | 101.6 | 208 | 98.1 / 98.7 / 101.6 |
| GitHub Actions ubuntu-latest | 5000 | 82.9 | 300 | 82.6 / 82.9 / 70.7 |

Committed keys in `apps/panel/perf/baseline.json`:
`win32/swiftshader/local/galaxy@5000` and
`linux/swiftshader/gha-Linux/galaxy@5000`.

The entry holds the worst of the three runs, so the x1.3 gate sits above the
spread between runs rather than inside it.

## Why the lowest rung is the default

The bloom rungs cannot repeat themselves. Same machine, same scene, same
20 s budget:

| Asked | Effective rung | Bloom | P95 (ms) | Frames |
|---|---|---|---|---|
| 20000 | 20000 | full | 204.6 | 102 |
| 15000 | 10000 (snapped) | mid | 265.3 | 135 |
| 10000 | 10000 | mid | 134.6 | 160 |
| 5000 | 5000 | off | 51.0 | 300 |

The two middle rows are the same rung twice: p95 134.6 and 265.3. A gate that
swings 2x between identical runs measures the machine, not the tree. The lowest
rung fills the whole 300-frame window and repeats within about 5%, so it is the
one the default asks for. A bloom run stays available with
`VERAX_PERF_TIER=20000`; the gate does not watch bloom, which is a known gap
rather than a claim.

## The key names what was measured

`<platform>/<gl>/<env>/galaxy@<tier>` - for example
`win32/swiftshader/local/galaxy@5000`. Without the scene and the tier in the
key, a new scene is compared against the baseline of the scene it replaced,
which is how the galaxy first read as 1.3x over a threshold that described the
anatomy scene.

## An unknown key is not a pass

`check-baseline.mjs`:

- No frames (below the floor, or p95 0) fails first, known key or not. A run
  that rendered nothing is a failure, never a "not compared".
- A key with no baseline prints `no baseline for <key>; not compared` and exits
  0. It compares nothing and does not say it did.
- Writing a baseline takes `VERAX_PERF_RECORD=1`, and it refuses to write over
  an entry that already exists, so a slow run cannot become its own threshold.
- With a baseline, the job fails when `last.json` p95 exceeds that entry x1.3.

The gate can go red: with the lowest rung deliberately raised to 40000 dust, the
same harness measured p95 283.3 over 74 frames and `check-baseline` exited 1.

## Run it on an idle machine

Load moves the number more than most code changes do. On this laptop, the same
rung measured 51.0 ms when it ran third against an already-warm preview, and
96-102 ms across separate runs that each start their own preview. Compare a
branch against `main` under the same conditions, or compare nothing.

On `GITHUB_ACTIONS`, `measure.mjs` uses a 40 s budget and accepts 10 frames;
locally it wants 30 frames within 20 s. It stops at the budget or 300 frames,
whichever comes first, and fewer than the floor is `render-failed`. Each run
starts its own preview on a strict port and tears it down; a busy port is an
error, not a fallback. `--url` probes an already-running page. `last.json` is
uploaded as an artifact.

## Presence scene (historical)

`panel-perf` no longer measures this scene; the panel's default view is the
galaxy. Kept for the record.

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
