# Status

This file states what the tree carries and what stays unproven. A
paragraph here is not a release.

## Phase 0 — workspace skeleton

The tree carries a workspace skeleton: three package stubs
(`@verax-ai/proxy`, `@verax-ai/body`, `@verax-ai/panel`), CRLF and claim
guards, typecheck, and CI workflows that run `npm test` as a non-root
user on Ubuntu and as a smaller claim on Windows.

Nothing in those packages runs. There is no proxy, no MCP listener, no
panel, no signed record, and no ledger. Unproven until a later commit
adds a call path and a test that exercises it.

Known gap: the skeleton cannot refuse a tool call, because no gate
exists yet.

## Phase 1 — proxy (this commit)

The tree carries `@verax-ai/proxy`: a fail-closed policy, a signed
decision record on every call, an effect row on allow (including a
throw), and a file/memory ledger. `defer` is a Cedulon decision kind
and is never produced; there is no approval queue.

Known gaps:

- all witnesses are self in phase 1; reconciliation is conditional by
  construction
- explain does not call signCheckpoint; durable checkpoint production
  is the phase 4 night watch. Until then window-coverage is
  notApplicable and balanced ignores that code
- a successful allow hashes what the proxy dispatched
  (`{ tool, arguments }`); whether the tool did that is the witness's
  job (phase 4), not the tool's self-report. The ToolResult hash lives
  as `resultHash` on the Verax ledger line, not on Cedulon's EffectRow
- an allow whose inner throws still writes a row (`<tool>:threw`); the
  effect hash is `sha256({ tool, arguments, threw: true })`, so
  `effect-mismatch` is intentional, not silent
- ledger backends: file (phase 1); obsigna daemon planned, not wired.
  One FileLedger per directory: a second instance throws
  `ledger-locked:<pid>`; a stale lock from a dead pid is replaced.
  `close()` drops the lock; the body calls it on SIGINT/SIGTERM
- record and effect keys live in the same process; independence is a
  declaration, not a separate witness
- duplicate-effect retry and late-event semantics are not designed
- no-bypass: export map only in this commit; CI scan + runtime
  registry land with the body; compiled-JS and foreign-binding paths
  are not covered
- payload encryption and retention policy not designed
- `spend` / `pay` are denied as `spend-not-wired`

## Phase 1 — body (this commit)

The tree carries `@verax-ai/body`: Streamable HTTP on Node `http`, a
resource-server Bearer check (`jose`, ES256/EdDSA), four tools, and
`verax doctor`. A missing issuer/jwks/audience pair exits 78 without
`listen`. Unauthenticated calls increment `metrics.json` and do not
write a decision record.

Known gaps:

- field names not yet aligned with Tugra
- no-bypass: CI scan + runtime registry; compiled-JS and foreign-binding
  paths are not covered
- the development issuer is not an authorization server; it has no
  authorize endpoint
- payload encryption and retention policy not designed
- memory items are not bound to the decision that read them (question 3
  is "not tracked yet")
- company effect is not connected (Talamus, question 4)
- GET /api/ledger and POST /api/contest/{ref} are HTTP, not MCP (they
  land with the panel)
- MCP is stateless (`sessionIdGenerator` unset). GET /mcp returns 405
  so the SDK client does not wait on a standalone SSE stream

## Phase 1 — panel (this commit)

The tree carries a 2D account-for rail: six golden actions, five
English questions, and a Contest button that re-runs `explain`. The
Vite proxy injects `VERAX_DEV_TOKEN` onto `/api` so the token does not
reach the browser.

Known gaps:

- questions 3 and 4 are explicit holes (`not tracked yet`, `not
  connected`); there is no invented green
- PKCE for the panel is not built
- GET /api/ledger and POST /api/contest/{ref} are HTTP, not MCP
- contest re-audits the whole ledger; no window bound (phase 4)
- the rail screenshot is a schematic PNG, not a live capture
- no React Three Fiber in the account-for rail commit

## Phase 2 — presence (this commit)

The tree carries a single `Points` field, an eight-state machine, and
adaptive draw-range quality. The committed cloud is derived from a
local GLB path (`VERAX_MODEL_GLB`); the GLB itself is not in git.

Known gaps:

- model provenance unverified
- unmeasured on target hardware until a low-end row shows P95 under
  16.7 ms
- `uAudio` is 0; no AnalyserNode
- all witnesses remain self; reconciliation stays conditional
