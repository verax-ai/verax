# Scale probes

Development-only scripts that build a large ledger and time what the panel
asks of the body. Nothing here is a test: no probe asserts a number. Each one
writes a JSON file so a plan or a design note can quote a measurement with
its source. They are not part of `npm test`.

The numbers quoted in `docs/design/ledger-rotation.md` (17 September 2026,
100k decisions: 679 MB on disk, 2.8 s boot, 979 MB RSS) came from these
probes on one laptop. Run them again before trusting a figure on another
machine.

## What each probe does

| Probe | What it measures |
|---|---|
| `ledger-scale.ts` | Builds a ledger of N decisions through the real proxy and `FileLedger` (signed records, chained hashes, inputs log, evidence copy), starts the body on it, times `/healthz` and `GET /api/ledger` for the whole ledger and for a 24-hour window. Writes `last-scale-<N>.json`. |
| `agents-scale.ts` | On a ledger `ledger-scale.ts` built, times `GET /api/agents` for the last day (what the panel asks every poll) and for the whole ledger. Writes `last-agents-<N>.json`. |
| `panel-scale.ts` | Serves the built panel in front of the body, opens it in headless Chromium through the issuer's code flow, and measures time to first record on screen, the `/api/ledger` fetch, DOM node count, JS heap and the longest frame gap over two polling rounds. Writes `last-panel-<N>.json`. |
| `boot.ts` | Shared helper: starts the dev issuer and the body on loopback against a state directory that already holds a ledger, waits for `/healthz`, mints a session token. Removes a stale `ledger.lock` left by a killed body. |

## Running

```
node --experimental-strip-types packages/body/perf/ledger-scale.ts
node --experimental-strip-types packages/body/perf/agents-scale.ts
node --experimental-strip-types packages/body/perf/panel-scale.ts
```

`panel-scale.ts` needs the panel built first (`npm run build -w @verax-ai/panel`)
and Playwright's Chromium (the same one the panel tests use).

| Variable | Meaning | Default |
|---|---|---|
| `VERAX_SCALE_N` | decisions to generate, or which ledger to open | `10000` |
| `VERAX_SCALE_DIR` | state directory | `<tmp>/verax-scale-<N>` |
| `VERAX_SCALE_REUSE` | `1` reuses an existing directory instead of regenerating | unset |
| `VERAX_SCALE_OUT` | where the JSON result goes | the state directory |
| `VERAX_SCALE_AGENTS` | number of agents in the synthetic roster | `150` |
| `VERAX_SCALE_ROUNDS` | timing rounds per request | see each probe |
| `VERAX_SCALE_ISSUER_PORT` / `VERAX_SCALE_BODY_PORT` | loopback ports | `8796` / `8797` (panel probe: `8794` / `8795`) |
| `VERAX_SCALE_PIECE_ROWS` | rows per ledger piece while `ledger-scale.ts` generates; a value above N keeps one piece | the ledger's own bound (50k) |

The defaults stay away from `8787`, the port a live body on the same machine
normally listens on.

A 100k ledger takes several minutes to generate and about 700 MB on disk
across the four sizes used on 17 September (200, 1k, 10k, 100k). The
directories are safe to delete; a probe rebuilds them.

## Two-piece measurement (ledger rotation, F8)

`docs/design/ledger-rotation.md` §F8 asks for the same probe on two 100k
pieces: boot time, RSS, and a 24-hour window that crosses the piece
boundary. `ledger-scale.ts` generates through the real `FileLedger`, so
the pieces close where the ledger closes them; `VERAX_SCALE_PIECE_ROWS`
sets that bound for the run. When the manifest names a closed piece, the
probe also times a 24-hour window centred on that piece's last row
(`ledgerCross24h`, with the `piecesTouched` the body answered) and
records the manifest's piece list and the `/healthz` document. The
whole-ledger read is the 5000-row cap (`limit=5000` on `ledgerAll`).

```
VERAX_SCALE_N=100000 VERAX_SCALE_PIECE_ROWS=1000000 node --experimental-strip-types packages/body/perf/ledger-scale.ts
VERAX_SCALE_N=200000 VERAX_SCALE_PIECE_ROWS=100000  node --experimental-strip-types packages/body/perf/ledger-scale.ts
```

The first is the single-piece layout the 17 September figures came from,
run again on the same code for a regression check. The second closes
`legacy` at 100k rows and the next piece at 200k, so the body boots on an
empty open piece and a 200k-line index.
