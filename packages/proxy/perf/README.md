# proxy-perf

A relative cost probe for the body's hot path: one policy decision
(`proxy.call`) and one approval (`approvePending`), measured against a ledger
that already holds 600 decisions.

```
node --experimental-strip-types packages/proxy/perf/measure.ts
node packages/proxy/perf/check.mjs
```

## What it measures, and why that

**User processor time per operation**, not wall-clock.

The unit suite guards approve's shape by counting file reads. That count is a
fact the filesystem hands us: it does not move with the machine, and it fails
the moment approve starts re-reading the ledger. What it cannot see is a
regression that burns cycles without touching a file. Measured on
11 Sep 2026, with a pure-CPU loop added to `approvePending` and no extra file
access at all: the counting guard passed, 6 of 6; this probe went from 3127 to
15210 microseconds per approve and the check failed.

Wall-clock was tried first and thrown away. On an idle laptop the same code
measured a p95 spread of 3.3x between identical runs, and a median over 300
rounds still swung 1.4x, because most of that time is disk rather than code.
Processor time is the part the code owns.

The first 30 rounds are warm-up and are dropped.

## There is no baseline yet, and that is deliberate

`baseline.json` is empty, so `check.mjs` prints `not compared` and exits 0. It
cannot fail a build today. Recording is a deliberate act - the checker only
writes a baseline under `VERAX_PERF_RECORD=1` - and it is deliberately not
done yet, because a threshold set before the spread is known is how a gate
ends up measuring the machine. That has now happened three times in this
repository in one week.

What it takes to turn it on:

1. Let the CI job run for a handful of pushes. It uploads `last-call.json` and
   `last-approve.json` as artifacts on every run.
2. Read the spread across those runs. The comparison allows 1.3x; if the
   runner's own spread is close to that, the gate would fire on nothing and
   the answer is more rounds, not a looser multiplier.
3. When the spread is comfortably inside it, record on a green run:
   `VERAX_PERF_RECORD=1 node packages/proxy/perf/check.mjs`, and commit the
   baseline with the numbers that justified it.

Locally the spread measured 1.25x on 11 Sep 2026, which is too close to 1.3 to
gate on. No local baseline is recorded for the same reason.
