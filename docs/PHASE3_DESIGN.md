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
An approval is of one concrete command, not a batch. The host
operator is trusted; anyone outside the OS is not.

**Decision.** A rule may set `mode: "approve"`. After fail-closed
checks pass, the proxy writes `decision: "defer"` (`reasonCode:
approval-required`, `effectHash: null`, `effectClass` may name the
tool). It does not call `inner`. Index: `<stateDir>/approvals.jsonl`
(operator snapshot: `ref`, `requestHash`, `subject`, args, **rule
sentence**, **inputs summary**, **amount/payee** when present,
expiry, status). Signed truth is the decision chain, not the index.
S1 approve is **CLI only** (`verax approve <stateDir> <ref>`). The
panel lists pending rows and has no approve control. Panel approve
is after S5, under a separate `verax:approve` scope. The CLI
recomputes `requestHash` from the snapshot and refuses a mismatch.
The chained `allow` uses the same `requestHash`, `reasonCode:
approved-by-operator`, `prevRecordHash = hash(defer)`, and
`effectHash = sha256Canonical(effectDescriptor(name, args))` — the
same descriptor the effect row will use. `requestHash` is only the
defer↔allow bind; it is not the effect hash (a mismatch would be
Cedulon `effect-mismatch`). The allow's `inputsHash` document
carries `approver` (OS user / operator id, `via: "cli"`). Expiry is
**lazy**: the next call that names that `_ref`, or `verax approve`,
writes `deny` / `expired`. The brain retries the same arguments
(same `requestHash`); different arguments are a new decision. There
is no "approve all". Optional `_ref` (stripped like `_inputs`) is
the idempotency key; see §7. `spend.reference` is a payee memo, not
`ref`. If the body holds `ledger.lock`, the CLI queues
`approval-commands.jsonl` and the next `proxy.call` applies it.

**Types.** No new claims. Queue file is Verax. `ExplainResult` may
gain a Verax `pair` (`defer` + resolution) so explain shows both
records; Cedulon `audit()` still sees the whole chain.

**Accept (red first).** Defer is signed and chained. Approve is a
second signed record. Different args → new defer. After TTL →
`expired`. Panel has no "approve all" control (UI test). Same
`_ref` + same `requestHash` → no third record. Approved `allow`
`effectHash` equals `effectDescriptor`, not `requestHash`.

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
`spend-not-wired`. After approve, the effect row is "payment
authorized" (`effectClass: "spend"`, `effectHash` =
`effectDescriptor("spend", args)`). **The body does not move
money.** A human pays in the payee's own console. The statement
arrives later as operator CSV.

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

**Decision.** `policy.egress[]` is a host allow-list. A tool is
egress only when the policy/registry marks it `egress: true` and
names a host extractor for that tool. A marked tool whose extractor
returns no host → `deny egress-host-missing` (fail closed). Host
not listed → `deny egress-blocked` (signed, no `inner`). Do not
sniff `host` / `url` keys on arbitrary arguments. `message.read` is
not egress. S3 adds `message.send` as a **no-network** stub (tenant
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

- Rate: in-memory counters seeded from the ledger at open
  (`effectRefs` pattern) and incremented on append. Only `allow`
  and `defer` count; `deny` does not. Unreadable ledger → fail
  closed. Breach → `deny rate-limited` / `deny daily-limited`.
- Disk: free space on `stateDir` below `policy.limits.diskFreeBytes`
  (default 64 MiB) → `deny ledger-disk-low`. If the deny cannot be
  appended, HTTP 507 and a metrics bump — no silent drop.
- Halt: `verax halt <stateDir>` writes `<stateDir>/halted`. New
  work is `deny halted` (still signed). Clear the file to resume.
- Revoke: S3 tokens carry `jti`. Dev issuer `POST /revoke`. Body
  checks `<stateDir>/revoked-jti.jsonl`. Unknown/revoked `jti` →
  401, no decision record (same as today's unauthenticated path).

**Accept.** Each deny code has a ledger fixture. Halt still appends.
Revoke rejects the next Bearer. Disk test injects the free-space
probe.

**STATUS.** Carries rate/daily/disk/halt/jti revoke; unproven until
a production halt and a stolen-token drill with an external issuer.

## 5. Tenant boundary (B7)

**Threat.** Pilot accept: "another customer's record". Memory is
flat under `stateDir/memory` today.

**Decision.** `aud` names the body (`VERAX_AUDIENCE`) and is the
same for every caller on that body; it cannot separate customers.
Tenant key = SHA-256 of `{ iss, sub }` plus an explicit
`tenant` / `org` JWT claim when present (else `iss` + `sub`).
`principal.brain` is JWT `sub` today. Memory and inbox live under
`tenants/<tenantKey>/`. `memory.get` of another tenant's id →
`deny tenant-mismatch` (signed, no body). Not "one tenant per
`stateDir`". Legacy `memory/` without a prefix: `verax doctor`
warns; reads do not silently merge.

**Accept.** Same `aud`, different `sub` **and** different
`iss` / `tenant`; A `memory.put`, B `memory.get` →
`tenant-mismatch` on the ledger. That is the Phase 3 slice of the
pilot test; a full stolen-token scenario stays Phase 4.

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
bundle. A refresh loses the session and runs `authorize` again
(accepted). After S5 the Vite proxy may still inject
`VERAX_DEV_TOKEN` for **dev-only** tooling (desktop MCP brains,
tests); that path is not the panel session. The body stays
issuer-agnostic (RFC 9728 PRM `authorization_servers`, `jose`
verify). **Option B** (Auth0/Keycloak) is configuration of that
same interface, not a Phase 3 dependency. Tokens are not printed.

**Accept.** Authorize without `code_challenge` fails. Token
response is not in a panel source file. PRM still lists the
configured issuer.

**STATUS.** Carries local PKCE; unproven until a production
authorization server is pinned in PRM.

## 7. Retry and idempotency (lands with S1)

**Threat.** Hostile replay; "duplicate-effect retry … not designed"
(`STATUS.md`). The brain chooses `_ref`.

**Decision.** `_ref` is the idempotency key (Cedulon `ref` /
`nonce` when generated). Format: opaque, length 1–64, characters
`[A-Za-z0-9._-]`. Invalid → `deny ref-invalid` with a **new**
generated `ref`/`nonce`. Same `requestHash` + same `ref` → return
the existing decision, no new record. Different `ref` → new
decision. Same `ref` + different `requestHash` → `deny ref-reuse`
written under a **new** `ref`/`nonce` (Cedulon nonce uniqueness).
Per-tenant namespace for `_ref` lands with S4 (today the key is
the raw `_ref`; S4 prefixes the tenant key so tenants cannot
pre-empt each other). A second **effect** on the same `ref`
already becomes `LedgerEffect.row.effectClass: "duplicate-effect"`
(`ledger.ts`; `explain` skips that class). Do not invent another
flag. Late channel events stay P4 `ghost` / `outOfScope`.

**Accept.** Replay same `_ref` + args: one decision. Second
`appendEffect`: `duplicate-effect` marker, existing tests stay
green. Bad `_ref` → `ref-invalid` with a different claims.ref.

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
| S1 | defer, approvals.jsonl, `verax approve` (CLI only), panel pending list (no button), explain pair, lazy expiry, §7 | red: pair, expiry, no approve-all, idempotent `_ref`, effectHash = descriptor |
| S2 | `spend` + always-defer, card CSV, `authorizedUnpaid` | red: 3/1/1 fixture; STATUS "does not pay" |
| S3 | egress extractors, rate/daily/disk, `verax halt`, `jti` revoke | red: each `reasonCode` |
| S4 | tenant `iss`+`sub`(+claim), path split, `_ref` namespace | red: same `aud`, different `iss`/`tenant` |
| S5 | dev-issuer authorize + PKCE, panel session; Vite inject stays dev-only | red: missing challenge |

One commit per slice. `STATUS.md` gains that slice's line only
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
