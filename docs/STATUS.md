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
- explain does not call `signCheckpoint` itself. `verax witness`
  writes a durable signed checkpoint to `checkpoints.jsonl`. Without
  that file, window-coverage stays notApplicable and balanced ignores
  that code. With a covering checkpoint the finding is evaluated.
- a successful allow hashes what the proxy dispatched
  (`{ tool, arguments }`); whether the tool did that is the witness's
  job (phase 4), not the tool's self-report. The ToolResult hash lives
  as `resultHash` on the Verax ledger line, not on Cedulon's EffectRow
- an allow whose inner throws still writes a row (`<tool>:threw`); the
  effect hash is `sha256({ tool, arguments, threw: true })`, so
  `effect-mismatch` is intentional, not silent
- ledger backends: file (phase 1); obsigna daemon planned, not wired.
  One FileLedger per directory: a second instance throws
  `ledger-locked:<pid>` (dead holder: `ledger-locked-stale:<pid>`).
  The directory lock is not a distributed lock: a lock is never taken
  over automatically; an operator removes a dead lock with
  `verax unlock`. A multi-process ledger belongs to the phase 4
  witness process. Operator unlock is recorded in unlocks.jsonl, not signed.
  Token checks on append/close are best effort; single writer by construction.
  `close()` drops the lock; the body calls it on SIGINT/SIGTERM.
  The `unlink-failed` unlocks.jsonl row is written when unlinkSync
  throws.
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
- the development issuer is not a production authorization server. It
  now serves local `GET /authorize` (PKCE S256) and `POST /token`.
  `NODE_ENV=production` still exits. It listens on
  `VERAX_DEV_ISSUER_PORT` (default 8790)
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

The tree carries a textured full-body figure, a `Points` field on top
of it, an eight-state machine, and adaptive draw-range quality. The
committed cloud is derived from a local GLB path (`VERAX_MODEL_GLB`).
The derived point cloud and the packed web GLB are build outputs;
neither source GLB is in git.

Known gaps:

- model provenance: concept image generated by the operator with ChatGPT; 3D model generated by the operator with Meshy AI on a paid plan (June 2026); rights rest with the operator; the source GLB is not in git
- the figure is a single static mesh; no rig, no lip sync, no audio
- panel-perf on hosted runners is a render smoke and a per-environment
  regression guard; it is not an fps claim. A throw after preview
  spawn still tears the child down (`runMeasure` finally). Bloom at
  60k points is in `docs/PERF.md` (measured idle; not an fps claim).
- `uAudio` is 0; no AnalyserNode
- all witnesses remain self; reconciliation stays conditional

## Evidence honesty (this commit)

Each line is what the tree carries, then what stays open.

- G1 — Panel: carries loading, error, empty, and stale as four states, a refresh control, a failed poll that keeps the last good rail, and `/healthz` counts that require `verax:audit`; unproven until a hosted panel is watched against a live body.
- G2 — Policy: carries a snapshot file per `policyHash` and the rail resolves the rule sentence from that hash; unproven until a second policy version is opened over an old decision in production.
- G3 — Explain: carries Cedulon `guarantee`, general `warnings`, and trust-root pin state (source `env` / `own-key` / none), and the summary never says `balanced` alone; pin defaults to the body's own record key; that proves the file, not an external root; unproven until a production pin (`VERAX_RECORD_PUBKEY_PIN`) is set and a foreign key is contested.
- G4 — Inputs: carries a `DecisionInputs` document (principal + declared memory versions) bound by `inputsHash`, including deny; unproven until brains declare `_inputs` on every call (optional unless `policy.requireInputs` is `true`).
- G5 — Effects: carries a one-row Cedulon `SignedEffectExtract` receipt at call time and a COSE Sign1 attestation over `{ ref, effectHash, witnessClass, resultHash }`; unproven until a witness other than `self` signs the row.
- G6 — Ledger I/O: carries a cached chain tail, an in-memory effect-ref index, and `fsync` after each append; unproven until a crash-restart drill on the production disk.
- F2 — Explain: carries every general Cedulon warning as a named condition; unproven until a production deny is read and the summary is not `conditional: conditional`.
- F3 — Inputs: carries `inputs-document-missing` when `claims.inputsHash` is on the record and the document is not on disk; unproven until a crash leaves a decision without `inputs.jsonl`.
- F4 — Trust root: carries `source` (`env` / `own-key` / none) and names an own-key pin; unproven until an external pin is set in production.
- F6 — Explain: carries the call-time row receipt; no window extract is signed at audit time; unproven until a production contest is compared to the call-time receipt.
- F7 — Inputs I/O: carries `fsync` on the inputs document before the decision lands; unproven until the same crash-restart drill as G6.
- F8 — Healthz: carries `ok` only for an unauthenticated probe or a token without `verax:audit`; ledger counts require `verax:audit`; an audit token also names `heartbeat` (from `heartbeat.json`, or null) and `witness` (last `witness-status.jsonl` class, or null). Unproven until an unauthenticated probe is watched on a hosted body.
- P4 — Reconcile: carries a channel-export matcher (`reconcile`) that names ghost / unsent / outOfScope without calling Cedulon `audit()`. `outOfScope` is only rows outside an explicit `--window-start/--window-end`; without a window the scope is the channel min/max and unmatched in-window rows are ghost (`nearestEffectDtMs`). CLI writes `/reconcile-report.json`. Unproven until a live Sent export is compared to a production ledger.
- P1 — Observatory: carries three tabs (status, galaxy, history; default galaxy), a detail pane with evidence scope, a timeline on history, demo data keyed by `loadPolicy(document).hash` plus golden `inputs.jsonl` (no `.rule-missing` on the sample), receipt/attestation read from the effect, network error stays `error` with an optional demo button, a product-independent galaxy fed from ledger + audit `/healthz` (`iss`+brain → planet, no invented tenant), a closed-sphere opening (spin until data; click flies each record to its hash address; `prefers-reduced-motion` is 300 ms linear; no progress bar), TR/EN copy (`?lang=en`), and F0 anatomy as a document on status (figure-box percentages from `anchors.mjs`). Layout shots cover 3 viewports × 3 tabs. Unproven until a hosted panel is watched against a live body. The presence `Stage` is off the main view. Panel-perf measures `tab=galaxy&open=1&demo=1`.
- P2 — Desktop: carries `verax desktop` (dev issuer → body → `vite preview` with token on env only → Edge/Chrome `--app=` with `--user-data-dir=<state>/browser-profile`, `--no-first-run`, `--no-default-browser-check`). A browser that exits within 3 s is `desktop-browser-exited-early` (exit 1). Window close kills the process tree (`taskkill /T` / POSIX group). `src/desktop.ts` is the only body file allowed to name `child_process`; it is still scanned for `import(`, `require(`, `eval`, and `tools/` imports. The CLI test builds `apps/panel/dist` when it is missing (D3). This machine (6 Sep 2026): Edge already open; `verax desktop` stayed up 20.0 s; ports closed 2.1 s after the isolated profile window closed. Still unproven on a host that has never run the profile path.

- S1 — Approvals: carries `defer` on `mode: "approve"`, `<stateDir>/approvals.jsonl` (rule sentence + inputs summary + amount/payee), `verax approve` (CLI only; queues when the ledger is locked; drain renames `approval-commands.jsonl` before apply), a panel pending list with no approve control, an explain `pair` (defer + resolution via `approver.resolves` / snapshot `allowRef`, not `prevRecordHash`), lazy `expired`, and `_ref` idempotency (`ref-reuse` / `ref-invalid` under a new nonce; retry uses that defer's resolution only). Approved `allow` uses `effectDescriptor` for `effectHash`. S1 `_ref` retry is at-least-once if the allow exists and the effect row is missing. Unproven until an operator approves a live hostile-brain call.
- S2 — Spend: carries `spend` (cap / payee / daily / currency → always `defer`), authorize-once on retry (`spend-reauth-required`), card CSV reconcile (`matched` / `ghost` / `authorizedUnpaid`); the body does not move money. On 6 September 2026 a live card charge of 10.00 TRY, made by hand on an advertising platform after the rail deferred and an operator approved it, was reconciled against that ledger: one statement row, one spend effect, `matched 1 · ghost 0 · authorizedUnpaid 0 · mismatch 0`. Two limits of that run remain part of the claim, now narrowed only where the tree actually narrowed them. A card date with a time (`DD.MM.YYYY HH:MM` or `YYYY-MM-DD HH:MM`) uses a two-minute window and the report marks that row `datePrecision: "minute"` — but only when the run names the statement's UTC offset (`--tz-offset 180` for Istanbul), because a statement prints local wall-clock time and names no zone. Without that offset the printed time is not trusted: the row stays `datePrecision: "day"` on the three-day card window, as does a date-only row. The 6 September statement was date-only, so that run is still the wide window. When a spend rule carries optional `descriptors` and the statement has no `verax:` ref, a configured stamp must hit or the row is ghost `descriptor-mismatch`; stamps are not guessed. That 6 September row had no descriptors on the policy, so the weak amount/currency/class path still carried it. Still unproven for a statement holding several rows of the same amount, for a payee that carries the reference through, for a timed statement row in production, and for a settled rather than pending row. `spend-not-wired` remains for `pay` and for `spend` when no spend rule is present (policy fixtures replace the hard deny).
- S3 — Bounds: carries priced-row reconcile refuse (`amount-unknown` when one side is priced and the other is not), host allow-list egress (`egress-blocked` / `egress-host-missing`; `message.send` `to` must contain `@` or the host is missing), a no-network `message.send` outbox stub, rate/daily counters (only `allow` and `defer` increment; unreadable counts fail closed), `ledger-disk-low` (HTTP 507 and a `disk_deny_unrecorded` metric when the deny cannot append), `verax halt` (`deny halted`, still signed), and `jti` revoke (401, no decision record). A ledger with no `.dir` (MemoryLedger) leaves halt and disk limits inactive; `createProxy` writes a warning. The suite now also locks halt-before-disk when both fire. Unproven until a hosted body is watched against a live outbound tool, a production halt, and a stolen-token drill with an external issuer.
- S4 — Tenant: carries a tenant key of SHA-256(`{ iss, sub }` plus `tenant` / `org` when present; not `aud`), memory and inbox under `tenants/<tenantKey>/`, signed `deny tenant-mismatch` (no body) when `memory.get` names another tenant's id, a `verax doctor` warning on legacy flat `memory/` (reads do not merge it), and a per-tenant `_ref` namespace so one tenant cannot close another's key. The ledger, the approvals snapshot and the resolution index key on `<tenantKey>:<_ref>`; the brain is answered with the raw `_ref` it sent, so its retry carries the same key back. `verax approve` accepts a raw `_ref` when exactly one pending row ends with `:<_ref>`; two hits list the candidates and exit `ambiguous-ref`. `audit.explain` (the brain tool only) denies another tenant's ref with a signed `tenant-mismatch` row and no record body; the operator `explain()` / panel contest path is unchanged. A missing memory id is still answered `not-found` over its allow row. Another tenant's id writes `deny tenant-mismatch` and is spoken as the `not-found` family (`spokenReason`, one table); the recorded code is never rewritten. The operator `explain()` / panel contest path still shows the full reason. The brain still owns both records and can tell them apart through `audit.explain`. Card reconcile reads descriptors from the newest `policies/<hash>.json` snapshot and names that hash on `report.scope.policyHash`. Two subjects on one issuer were driven over HTTP against one body: the second read the first's id and got a signed `deny tenant-mismatch` with no body. Unproven until two live customers share one body.
- S5 — Session: carries local PKCE and an operator scope on the audit doors: `GET /api/ledger` and `POST /api/contest/{ref}` hand out every tenant's decisions, the inputs documents that name their principals and the approval snapshots that carry spend arguments, so they now require `verax:audit`, which a brain token does not hold (the development issuer mints one token for both roles and does hold it). Unproven until a production authorization server is pinned in PRM. The panel holds the access token in memory (not `localStorage`, not the bundle) and refuses a code that comes back without the `state` that tab sent. A refresh runs `authorize` again. Vite may still inject `VERAX_DEV_TOKEN` for desktop MCP brains and tests when the request has no Authorization header; that path is not the panel session.
- S6 — Spoken reason: `spokenReason` maps `tenant-mismatch` to `not-found` on the brain-facing string only. `memory.get` and `audit.explain` therefore answer another tenant's id/ref and a missing id/ref with the same `not-found` family; the ledger row stays `deny`/`tenant-mismatch` vs `allow`. Operator `explain()` and `/api/*` are unmasked. A brain that explains the two records it owns can still tell them apart. `/healthz` counts now require `verax:audit` (a brain `verax:read` token is `{ ok: true }` only). The development issuer refuses an unlisted `redirect_uri` and caps `codes` at 100. Unproven until two live customers share one body.
- S7 — Inputs required: carries optional `policy.requireInputs` on the document root (`version: 1` stays). When it is `true`, a call with no `_inputs` key is a signed `deny inputs-required` (`effectHash: null`, no body). An empty array is a declaration and is not that deny. A broken declaration stays `input-invalid`. `inputs-required` is not masked. `DecisionInputRow` still names `validFromMs` / `validUntilMs`; optional `source` is additive. The panel reads `authorization_servers` from resource metadata before a session; an unreadable document is a visible rail error (last-resort issuer named, no silent redirect). `verax doctor` warns when the panel port is off the issuer redirect allow-list, when the panel last-resort issuer differs from `VERAX_ISSUER`, or when the development token scope lacks `verax:audit`. Doctor only reports. Unproven until brains declare `_inputs` on every production call.

## Phase 4 — independent witness (this commit)

`verax witness <stateDir>` is a second process. It holds
`keys/witness.private.pem` and signs an effect row over loopback HTTP.
The body never loads that file (`loadOrCreateSigners` still only has
record + effect). A reachable witness writes `witnessClass: "same-org"`
and a `witness-status.jsonl` `signed` row. An unreachable witness leaves
the class `self` and records `self-fallback` / `unreachable`. That is
not a third-party witness. The same process signs a durable checkpoint
onto `checkpoints.jsonl`; `explain` then evaluates window-coverage
instead of listing it as notApplicable. FileLedger also appends each
decision/effect line to `evidence-copy/` and writes `heartbeat.json`
(`alive` + last row n). `verax doctor` is the speaker: a stale
heartbeat is `heartbeat` / silent; a short or corrupt copy is
`evidence-copy`. The panel is a session UI and is not watching this.
Seven pilot drills live in `tests/pilot-drills.test.ts` (stolen token,
hostile tool, cross-tenant record, repeated `_ref`, tampered memory,
full disk, silenced copy). They are tests, not a live body.

Remaining gaps, still open:

- `_inputs` is optional unless `policy.requireInputs` is `true`; without that flag a call with no declaration still stores `inputs: []`. The flag is off on the default policy. Production brains have not been required to declare yet.
- a FileLedger effect is `same-org` only when `verax witness` signed it
  in another process; without that process the class is `self` and
  `witness-status.jsonl` records the fallback. MemoryLedger tests and
  the body effect key remain `self`. This is not a third-party witness.
- Cedulon's `EffectRow` still cannot hold `resultHash`; the attestation does
- a brain can still tell a cross-tenant miss from a missing id by explaining the two records it owns (`deny`/`tenant-mismatch` vs `allow`). The spoken answers on those two calls are now the same `not-found` family; that hop is the accepted remaining limit, not a claim that the oracle is closed
- the development issuer is still not a production authorization server; `NODE_ENV=production` still exits. `/authorize` now refuses a `redirect_uri` outside `VERAX_DEV_REDIRECT_URIS` (default `http://127.0.0.1:5173/` and `http://127.0.0.1:4173/`) with `400 invalid_request`, and the in-memory `codes` map is capped at 100 (expired rows drop first, then the oldest)
- the panel reads `authorization_servers` from `/.well-known/oauth-protected-resource` before it starts a session. If that document cannot be read, the session does not redirect: the rail shows `resource metadata unreachable` and names the last-resort issuer (`VITE_VERAX_ISSUER`, else `http://127.0.0.1:8790`). Vite proxies `/.well-known`. `verax desktop` still passes its panel port to the issuer allow-list
- a JWT-less fixture principal keeps the raw `_ref` as `claims.ref` so S1 tests stay pinned; production tokens always carry `iss` and are prefixed
