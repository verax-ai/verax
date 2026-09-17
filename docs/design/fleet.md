# Fleet view (many bodies)

This is a design, not a release. No code in this tree reads a second
body's ledger. The note answers plan §2-G
(`Work\VERAX_PANEL_OLCEK_VE_SITE_PLANI_20260917.md`). STATUS line: G8.

Every figure names its source. A quantity that was not timed is marked
**not measured**.

## Why this exists

STATUS does not describe a multi-body view. The company model in the
plan is one body per machine, each with its own state directory and
`ledger.lock`. `@verax-ai/inventory` is a roster document the *one*
body serves (`docs/STATUS.md` Galaxy paragraph; `packages/inventory`).
D1/D2 built `/api/agents` and a group fold on that one body
(`Work\VERAX_OLCEK_OLCUMU_20260917.md` D1/D2;
`apps/panel/src/observatory/Observatory.tsx` `groupAgents` 727–748).

150 agents on one PC is a roster-size problem and is already a table.
Two PCs plus a Hetzner box is a *body*-size problem and is not.

## What a fleet is

**Decision.** A fleet is several ledgers, each written by one body on
one machine. The panel, or a later collector, *reads* them. It does not
merge them into one write path.

---

## G1 — Model

Three options. Each is judged on identity/token, network, offline
check of signatures, and the single-writer rule
(`docs/STATUS.md` Phase 1 proxy: one `FileLedger` per directory;
`ledger-locked:<pid>`; `verax unlock` for a dead holder).

### (a) Panel talks to many bodies (client merge)

The operator session holds a list of body base URLs. Each poll asks
`/api/ledger`, `/api/agents`, `/healthz` on each URL and folds the
answers on the client.

| Axis | What holds |
|---|---|
| Identity / token | Each body has its own `aud` (`tenantKey` deliberately omits `aud`: `packages/proxy/src/tenant.ts` 13–14, 16–26). A token minted for body A is not, by construction, a token for body B. The panel would hold one access token per body, or the issuer would have to list every audience. Today's development issuer is one process per `verax desktop` / body (`docs/STATUS.md` S5, Phase 1 body). |
| Network | The browser must reach each loopback or VPN address. A body behind NAT the panel cannot route to is absent, not empty. |
| Offline check | None. No body, no rows. Signatures are checked by each body on write, not again at the panel. |
| Single writer | Held. The panel has `verax:audit` (and optional `verax:approve` on the body it can reach). It does not take `ledger.lock` on a remote disk. |

**Cost.** Token sprawl; CORS / loopback; a laptop panel cannot see a
machine that is off. **Not measured:** poll time × N bodies.

### (b) A collector pulls copies, checks signatures, merges

A second process (or a designated body) copies closed pieces and/or
tails, verifies COSE and `prevRecordHash`, and serves one `/api/*`.

| Axis | What holds |
|---|---|
| Identity / token | The collector has its own audience. It needs a *read* path into each machine (file sync, or a pull scope that does not exist today — `/api/ledger` is `verax:audit` and already hands every tenant, `server.ts` 456–460). |
| Network | Pull over whatever sync the operator already runs. Lag is the pull interval (**not measured**). |
| Offline check | Yes: COSE + chain + checkpoints can be checked without the live body, on the copy. |
| Single writer | Held only if the collector never appends. A collector that "repairs" a chain is a second writer and is out. |

**Cost.** Bytes leave the machine that made them. That is an
operator-held copy, in the same family as `evidence-copy`, but on a
*different* host — which is the THREAT_MODEL gap the on-disk copy does
not close. It is also the shape of a central ledger if the collector
starts answering writes.

### (c) Each body writes a daily checkpoint to a shared place

`verax witness` already signs a window onto `checkpoints.jsonl`
(`packages/body/src/witness.ts` 176–197; `checkpointsPath`
`packages/proxy/src/checkpoints.ts` 5–7). Each body could also write
that signed row to a shared directory, object store, or git remote.

| Axis | What holds |
|---|---|
| Identity / token | The checkpoint is already signed by the witness key. The shared place is write-only from each body; readers verify the COSE. |
| Network | One small append per window, not the 345 MB full-ledger payload of the 100k run. |
| Offline check | Coverage and chain-of-checkpoints, yes. The *rows* the panel paints are not in a checkpoint. |
| Single writer | Held. The shared place is not a ledger. |

**Cost.** This is a coverage / heartbeat layer, not a fleet *view*.
`/api/agents` needs decisions + inputs + the roster
(`packages/body/src/agents.ts` 43–83). A checkpoint does not carry
those.

### Choice this note recommends

**Live view: (a). Coverage layer: (c). Do not build (b) as the
default.**

(a) matches "records stay on the customer's machine" (G4) and the
single-writer rule. (c) reuses the hook that already exists and gives
an operator a way to see that a machine they cannot reach still signed
a window. (b) is the right tool only when the patron accepts
operator-held copies on a second host and a written rule that the
collector never appends.

**Rejected as default.** (b) without that rule. It becomes a central
ledger the first time someone "fixes" a row there.

**Rejected.** A mesh where bodies append to each other. Two writers, two
locks, no design for that (STATUS: a multi-process ledger belongs to
the phase 4 witness process — still one directory).

---

## G2 — Identity

### Roster agent ↔ body

`inventory.json` groups are labels (`packages/inventory/src/index.ts`
21, 87–96). The sample uses `team-a` / `team-b`
(`packages/inventory/tests/fixtures/inventory-sample.json`). D2 folds
the agents table on `roster.group`
(`Observatory.tsx` `groupAgents` 727–748). Tests use the label
`"This PC"` (`apps/panel/tests/agents.test.tsx` 32, 94). That is a
*convention*, not a machine id.

`/api/agents` keys a row on `inputs.principal.brain`, and files a
roster agent under `agent.id` (`agents.ts` 55–82). The roster does not
name a body.

**Decision.** Do not overload `groupId` as a host. Add a fleet document
the panel (or a future collector) reads, separate from the per-body
roster:

```
{ "bodies": [
    { "id": "pc-emek", "label": "This PC", "baseUrl": "http://127.0.0.1:8787" },
    { "id": "hetzner-1", "label": "Hetzner", "baseUrl": "http://10.x.x.x:8787" }
] }
```

`id` is the fold key. `baseUrl` is how (a) reaches the body. A body
the document names and that does not answer is `stale` / unreachable;
the panel does not invent rows for it.

Optional later: `inventory.json` may grow an optional `bodyId` on an
agent so a *single* body that somehow served two hosts could say so.
Not required for one-body-per-machine.

### Tenant key across bodies

`tenantKey` is SHA-256 of `{ iss, sub }` plus `tenant` / `org` when
present; `aud` is omitted so the body is not part of the key
(`packages/proxy/src/tenant.ts` 11–26; STATUS S4). The same person, same
issuer, two bodies → the same tenant key *string*, but two ledgers.
`_ref` namespaces do not collide on write: each `FileLedger` has its
own `byRef`.

**Decision.** A fleet row is keyed `bodyId + ref` (and `bodyId +
tenantKey + _ref` for retries the operator looks at). The panel must
not merge two bodies' `ref` values as one record. Memory and inbox
stay under each body's `tenants/<tenantKey>/` (STATUS S4). There is no
cross-body memory.

**Rejected.** Making `aud` part of `tenantKey`. That would split one
person's memory on one body the moment the audience string changed, and
STATUS S4 already forbids it.

Tokens stay per body (G1a). A shared production issuer that mints one
token with several audiences is an authorization-server change, not
this note. Unproven until that server exists (STATUS S5).

---

## G3 — Panel

Today `/api/agents` is one body (`server.ts` 473–496). The status tab
draws one table and folds on roster group (`groupAgents`).

**Decision, when (a) lands.**

1. Outer fold: fleet `bodies[].label` ("This PC", "Hetzner"). Same
   open/close pattern as D2 (`tr.agents-group`).
2. Inner fold: existing roster group, including `listede yok` /
   `grupsuz` (`Observatory.tsx` 727–748; copy keys
   `agents.state.offRoster`, `agents.group.none`).
3. Unreachable body: one group row, no agent rows, last successful
   `/healthz` time if the tab still holds one, otherwise "not reached".
   Do not replay a stale agents list as if it were live unless the
   header says it is stale (G1 panel already keeps last-good rail on a
   failed poll — STATUS G1; reuse that word).
4. `/api/ledger` stays per body. The records tab either names which
   body is in view, or interleaves with a body column. Interleave
   without a column is rejected: two `ref`s would look like one chain.

Approve stays on the body that holds the defer. A `verax:approve`
token for body A cannot close a defer on body B.

---

## G4 — What will not be built

**No central single ledger.** Records stay on the machine that decided.
A collector copy (G1b), if the patron later wants one, is a verified
*image* for reading, not the write path, and not a place a second
`FileLedger` takes a lock.

Also out:

- Crossing `ledger.lock` over the network.
- One `decisions.jsonl` appended by many bodies.
- A panel that silently drops a body that failed to answer.
- Changing `tenantKey` to include `aud` or `bodyId`.

---

## Guard plan (red first, when this is implemented)

1. Two fake bodies, two refs equal as strings, records tab shows two
   rows keyed by `bodyId`. A merge-by-ref stays red.
2. Outer fold names both labels; closing "Hetzner" does not hide
   "This PC" agents.
3. A body that returns 401/network error renders unreachable, not an
   empty roster.
4. Approve on body A does not POST to body B's `/api/approve`.

## Measure plan

N-body poll time is **not measured**. When (a) is built, time 1 / 2 / 5
bodies against the 17 Sep 100k-after-C numbers (panel open 256 ms, first
ledger 18 ms / 691 KB, agents ~108 ms / 18.4 KB —
`Work\VERAX_OLCEK_OLCUMU_20260917.md` C, D1). Linear growth is the
honest default until measured.

---

## What this note does not do

- No panel UI in this change.
- No inventory schema change in this change.
- No collector implementation.
- No site copy about "fleet".
