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
- an allow whose inner throws still writes a row (`<tool>:threw`); the
  audit must report that the effect hash does not match the intended
  hash, not stay silent
- ledger backends: file (phase 1); obsigna daemon planned, not wired
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
- the rail screenshot is a schematic PNG, not a live capture
- no React Three Fiber in this commit
