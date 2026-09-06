# Phase 3 design — gates, spend rail, bounds

This is a design, not a release. Cedulon closed types stay closed:
`DecisionRecordClaims` gains no field; `Ledger` in
`packages/proxy/src/types.ts` (the append/read/extract surface) does
not change. New meaning uses `reasonCode`, the existing `inputsHash`
document (`DecisionInputs`), `LedgerEffect` row fields already on
disk, and Verax files next to the ledger. `vendor/` is not edited.

Order covered here: access paths, action authority, untrusted
content, damage limits, plus the approval queue. Isolation of the
signer process and evidence-copy/heartbeat are Phase 4 (threat:
"the ledger can be silenced"; "the tool server is hostile").

## 1. Approval queue and `defer`

**Threat.** The brain is hostile: any tool name, any arguments, any
replay (`THREAT_MODEL.md`). A grant is a signed decision, not a mood.
An approval is of one concrete command, not a batch.

**Decision.** A rule may set `mode: "approve"`. After fail-closed
checks pass, the proxy writes `decision: "defer"` (`reasonCode:
approval-required`, `effectHash: null`, `effectClass` may name the
tool). It does not call `inner`. Index: `<stateDir>/approvals.jsonl`
(operator snapshot: `ref`, `requestHash`, `subject`, args, expiry,
status). Signed truth is the decision chain, not the index. CLI
`verax approve <stateDir> <ref>` recomputes `requestHash` from the
snapshot and refuses a mismatch. The chained `allow` uses the same
`requestHash`, `reasonCode: approved-by-operator`,
`prevRecordHash = hash(defer)`, `effectHash = requestHash` (the
intended effect is the authorized request). Expiry writes `deny` /
`expired`. The brain retries the same arguments (same
`requestHash`); different arguments are a new decision. There is no
“approve all”. Optional `_ref` (stripped like `_inputs`) is the
idempotency key; see §7. `spend.reference` is a payee memo, not
`ref`.

**Types.** No new claims. Queue file is Verax. `ExplainResult` may
gain a Verax `pair` (`defer` + resolution) so explain shows both
records; Cedulon `audit()` still sees the whole chain.

**Accept (red first).** Defer is signed and chained. Approve is a
second signed record. Different args → new defer. After TTL →
`expired`. Panel has no “approve all” control (UI test). Same
`_ref` + same `requestHash` → no third record.

**STATUS.** Carries a defer→allow pair and an approvals index;
unproven until an operator approves a live hostile-brain call.

## 2. `spend` and the manual card rail

**Threat.** Action authority: tool name + payee + amount + window.
The tool server is hostile; reconciliation notices mismatch, it does
not pay.

**Decision.** Tool `spend { amount, currency, payee, reference }`.
Policy: amount cap, payee allow-list, daily total; **always**
`defer` when those pass. Over cap / unknown payee / daily breach →
`deny` (`spend-cap` / `spend-payee` / `spend-daily`). `pay` stays
`spend-not-wired`. After approve, the effect row is “payment
authorized” (`effectClass: "spend"`, `effectHash = requestHash`).
**The body does not move money.** A human pays in the payee’s own
console. The statement arrives later as operator CSV.

**Adapter.** Do not mint a Cedulon `SignedRailExtract` over that CSV:
the extract type is a signed rail window (`accountId`, `railId`,
settlements). A typed file is not a rail. P4 `reconcile` already
names `ghost` / `unsent` / `outOfScope` without calling `audit()`.
S2 extends Verax `ChannelRow` with optional `amount` and `currency`
(not a Cedulon field). `verax reconcile --channel card` parses CSV →
`ChannelRow`. Match: amount + currency (minor-unit tolerance) + time
window; `ref` if present. Report buckets: `matched` · `ghost`
(statement row, no authorization) · `authorizedUnpaid` (approved
`spend` effect, no statement row). `unsent` remains for other
classes. If a rail later signs extracts, `explain` already accepts
`SignedRailExtract`.

**Accept.** Fixture statement: 3 matched, 1 ghost, 1
`authorizedUnpaid`. Policy fixtures replace the hard
`spend-not-wired` deny for `spend`. STATUS must say spend does not
pay.

**STATUS.** Carries authorization + CSV match; unproven until a live
card statement is compared to a production ledger.

## 3. Egress allow-list

**Threat.** Access paths: the brain must not get unbounded exit
(`THREAT_MODEL.md` — any arguments).

**Decision.** `policy.egress[]` is a host allow-list. Any call that
names `host` or `url` is checked; missing host on an egress tool →
`deny egress-host-missing`; host not listed → `deny egress-blocked`
(signed, no `inner`). `message.read` has no destination and skips
the check. S3 adds `message.send` as a **no-network** stub (tenant
`outbox.jsonl` only) so a deny is a real ledger row. Mail/WA later
reuse the same list.

**Accept.** Call to a host not on the list is a ledger `deny` with
`egress-blocked`.

**STATUS.** Carries host allow-list deny; unproven until a hosted
body is watched against a live outbound tool.

## 4. Damage limits

**Threat.** A looping brain or a full disk looks like silence
(operator forgetful; ledger can be silenced). Phase 3 records the
refusal; Phase 4 proves a second copy.

**Decision.**

- Rate: count signed decisions for `principal.brain` in the last
  60 s and per UTC day (ledger is the counter; unreadable ledger →
  fail closed). Breach → `deny rate-limited` / `deny daily-limited`.
- Disk: free space on `stateDir` below `policy.limits.diskFreeBytes`
  (default 64 MiB) → `deny ledger-disk-low`. If the deny cannot be
  appended, HTTP 507 and a metrics bump — no silent drop.
- Halt: `verax halt <stateDir>` writes `<stateDir>/halted`. New
  work is `deny halted` (still signed). Clear the file to resume.
- Revoke: S3 tokens carry `jti`. Dev issuer `POST /revoke`. Body
  checks `<stateDir>/revoked-jti.jsonl`. Unknown/revoked `jti` →
  401, no decision record (same as today’s unauthenticated path).

**Accept.** Each deny code has a ledger fixture. Halt still appends.
Revoke rejects the next Bearer. Disk test injects the free-space
probe.

**STATUS.** Carries rate/daily/disk/halt/jti revoke; unproven until
a production halt and a stolen-token drill with an external issuer.

## 5. Tenant boundary (B7)

**Threat.** Pilot accept: "another customer's record". Memory is
flat under `stateDir/memory` today.

**Decision.** Tenant key = SHA-256 of
`{ brain, sub, aud }` (canonical). `principal.brain` is JWT `sub`
today; `aud` is the separator for two customers on one body. Memory
and inbox live under `tenants/<tenantKey>/`. `memory.get` of another
tenant’s id → `deny tenant-mismatch` (signed, no body). Not “one
tenant per `stateDir`”: one body may host several triplets. Legacy
`memory/` without a prefix: `verax doctor` warns; reads do not
silently merge.

**Accept.** Two tokens, same `stateDir`, different `sub` or `aud`;
A `memory.put`, B `memory.get` → `tenant-mismatch` on the ledger.
That is the Phase 3 slice of the pilot test; a full stolen-token
scenario stays Phase 4.

**STATUS.** Carries path split + `tenant-mismatch`; unproven until
two live customers share one body.

## 6. Authorization server and PKCE

**Threat.** Access paths. Today the panel token is injected by the
Vite proxy from the environment; the dev issuer has JWKS only
(`STATUS.md`). PKCE is not built.

**Decision.** **Option A for this tree:** add `GET /authorize`
(PKCE S256) and `POST /token` to the **development** issuer
(`NODE_ENV=production` still exits). Panel session uses the code
flow; access tokens stay in memory, not `localStorage`, not the
bundle. Desktop MCP brains may still read a token file. The body
stays issuer-agnostic (RFC 9728 PRM `authorization_servers`,
`jose` verify). **Option B** (Auth0/Keycloak) is configuration of
that same interface, not a Phase 3 dependency: a local product
must not require a vendor to prove PKCE. Tokens are not printed
and do not leave env/file except the in-memory panel session.

**Accept.** Authorize without `code_challenge` fails. Token
response is not in a panel source file. PRM still lists the
configured issuer.

**STATUS.** Carries local PKCE; unproven until a production
authorization server is pinned in PRM.

## 7. Retry and idempotency (lands with S1)

**Threat.** Hostile replay; “duplicate-effect retry … not designed”
(`STATUS.md`).

**Decision.** `_ref` is the idempotency key (Cedulon `ref` /
`nonce`, as today when generated). Same `requestHash` + same `ref`
→ return the existing decision, no new record. Different `ref` →
new decision. Same `ref` + different `requestHash` → `deny
ref-reuse`. A second **effect** on the same `ref` already becomes
`LedgerEffect.row.effectClass: "duplicate-effect"`
(`ledger.ts`; `explain` skips that class). Do not invent another
flag. Late channel events stay P4 `ghost` / `outOfScope`.

**Accept.** Replay same `_ref` + args: one decision. Second
`appendEffect`: `duplicate-effect` marker, existing tests stay
green.

**STATUS.** Carries decision-side short-circuit; unproven until a
production brain retries after process restart.

## 8. Untrusted content provenance

**Threat.** Tool results, mail, and memory are data, not commands.
Prompt injection is not filtered (`THREAT_MODEL.md`).

**Decision.** No injection scanner. `policy.requireInputs: true` →
a call with no `_inputs` is `deny inputs-required` (today missing
declaration stores `inputs: []`). Invalid `_inputs` stays
`input-invalid`. Tugra alignment: keep `validFromMs` /
`validUntilMs` on `DecisionInputRow`; optional `source` object on
the row (memory.put already requires `source`). Do not rename
validity fields.

**Accept.** `requireInputs: true` and no `_inputs` → signed
`inputs-required`.

**STATUS.** Carries mandatory `_inputs` when configured; unproven
until brains declare on every production call.

## 9. Slices

| Slice | Lands | Tests first |
| --- | --- | --- |
| S1 | defer, approvals.jsonl, `verax approve`, panel pending list, explain pair, expiry, §7 | red: pair, expiry, no approve-all, idempotent `_ref` |
| S2 | `spend` + always-defer, card CSV, `authorizedUnpaid` | red: 3/1/1 fixture; STATUS “does not pay” |
| S3 | egress, rate/daily/disk, `verax halt`, `jti` revoke | red: each `reasonCode` |
| S4 | tenant triplet, path split, `tenant-mismatch` | red: cross-tenant get |
| S5 | dev-issuer authorize + PKCE, panel session | red: missing challenge |

One commit per slice. `STATUS.md` gains that slice’s line only
when tests are green. Policy document stays `version: 1` with
additive optional fields (`mode`, `egress`, `requireInputs`,
`limits`, `spend` on a rule).

## 10. Not in Phase 3

Independent witness / separate signer process; durable checkpoint;
evidence copy + heartbeat; compiled-JS / foreign-binding no-bypass;
payload encryption and retention; penetration test; `pay` rail;
real `message.send` delivery. Those are Phase 4 or later, because
they need a second process or a second copy, which this host
cannot honestly claim.
