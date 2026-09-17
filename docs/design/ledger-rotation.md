# Ledger rotation and archive

This is a design, not a release. No code in this tree splits a ledger
file. The note answers plan §2-F (`Work\VERAX_PANEL_OLCEK_VE_SITE_PLANI_20260917.md`).
STATUS line: G7.

Every figure below names its source. A quantity that was not timed on
this machine is marked **not measured**.

**Decisions taken (17 September 2026, operator).** F1 piece bound:
50,000 decision rows or 200 MB of `decisions.jsonl`, whichever comes
first; not a calendar month on its own. F4 retention: no automatic
delete; a drop is an explicit operator command; the default keep window
when an operator does drop is 13 months after close. Both stay design
until the F7 guards have been seen red and the F8 measurement has run.

## Why this exists

B (tail window) and C (panel last 200) cut the *read* path. They do not
cut *boot* or the growth of one file.

On 17 September 2026 a 100k-decision ledger on this laptop was:

| What | Value | Source |
|---|---|---|
| Disk, whole state dir | 679 MB | `Work\VERAX_OLCEK_OLCUMU_20260917.md` §1 |
| `decisions.jsonl` | 193.6 MB | same |
| `effects.jsonl` | 138.9 MB | same |
| `inputs.jsonl` | 14.2 MB | same |
| `evidence-copy/` | 332.5 MB | same |
| Boot to `/healthz` 200 | 2.79 s | same §2 |
| RSS at boot | 979 MB | same §2 |
| RSS after five full reads | 1,855 MB (later 1,361 MB after B) | same §2, B result |
| `/api/ledger` all rows | 4.6 s / 345 MB after B | same B result |
| 24 h window after B | 155 ms | same |
| Last 200 after B | 11 ms / 691 KB | same |

`FileLedger` constructor calls `loadCaches()`, which `JSON.parse`s every
decision line and then every effect line
(`packages/proxy/src/ledger.ts` 418, 422–457). The indexes that stay in
memory are `byRef`, `resolvedBy`, `reauthByHash`, `countedAt`,
`effectRefs`, `tailHash`, `decisionCount`, `effectCount`, `lastDecisionMs`.

Assumption carried from the plan (not a measurement of a live fleet):
150 agents × 50 decisions/day = 7,500/day → 100k in ~13 days → 2.7 M
rows in a year in one file (`Work\VERAX_OLCEK_OLCUMU_20260917.md` §5).

## Shape on disk (proposed)

Today one directory holds the live names
(`ledger.ts` 412–416, 415 for the copy dir):

```
<stateDir>/decisions.jsonl
<stateDir>/effects.jsonl
<stateDir>/inputs.jsonl
<stateDir>/approvals.jsonl
<stateDir>/evidence-copy/decisions.jsonl
<stateDir>/evidence-copy/effects.jsonl
<stateDir>/heartbeat.json
<stateDir>/ledger.lock
<stateDir>/checkpoints.jsonl
```

After rotation the *write* path points at one active piece. Closed
pieces keep the names they were first written under. A small manifest
names them all:

```
<stateDir>/ledger-manifest.json    # atomically replaced
<stateDir>/pieces/<id>/decisions.jsonl
<stateDir>/pieces/<id>/effects.jsonl
<stateDir>/pieces/<id>/inputs.jsonl
<stateDir>/index.jsonl             # durable ref index; see F3
<stateDir>/evidence-copy/pieces/<id>/decisions.jsonl
<stateDir>/evidence-copy/pieces/<id>/effects.jsonl
```

`approvals.jsonl`, `checkpoints.jsonl`, `heartbeat.json`, and
`ledger.lock` stay one file each: they are not the growth that was
measured.

A first implementation may keep writing the historical names
(`decisions.jsonl` and friends) as the *active* piece and only create
`pieces/<id>/` at close. That is an implementation choice. The rule that
is not a choice: **do not rename a jsonl that a reader may still hold
open**. See F5.

---

## F1 — Piece bound

**Decision.** Close the active piece when it reaches **50,000 decision
rows or 200 MB of `decisions.jsonl`, whichever first**. Calendar month
is a *label* on the closed piece (`2026-09-a`, `2026-09-b`), not the
trigger.

**Why.** The reason to rotate is boot cost, which is the active piece
`loadCaches` parses. A month at the plan's 7,500/day assumption is
~225,000 rows — larger than the 100k run that opened in 2.79 s / 979 MB
RSS. Monthly-only therefore misses the point of F. 50k is half the
measured 100k file in row count; RSS at 50k was **not measured**. 200 MB
is just above the 193.6 MB `decisions.jsonl` of that 100k run, so a
fatter row mix cannot silently grow past what was already timed.

**Alternative.** 10,000 rows (measured: 1.03 s / 165 MB RSS). Cheaper
boot, more pieces, more often a 24 h window spans two files.

**Rejected.**

- Monthly-only. See the 225k arithmetic above.
- Size-only with no row cap. A thin row mix could still hold enough
  parsed objects to blow RSS; row cap is the boot bound.
- Rotate on every Cedulon checkpoint window. Checkpoints are coverage
  proof (`packages/body/src/witness.ts` 176–197), not a storage
  scheduler. They fire when the witness is asked, not when the file is
  large.

### Panel "older" page when `to=` falls in a closed piece

Today `GET /api/ledger?from&to&limit` calls `decisionsWindow`
(`packages/body/src/server.ts` 498–524;
`packages/proxy/src/ledger.ts` 625–644). The tail reader walks *one*
file from the end, 64 KiB at a time
(`packages/proxy/src/jsonl-tail.ts` 32–36). `more` is true when the
limit cut the window inside that file. `WINDOW_SLACK_MS` is 60 s
(`ledger.ts` 94): a stamp a minute older than `from` still counts as
in-window; older than that, the reader **stops**.

If `to` is older than the active piece's first stamp, a single-file
reader that stops at the file head returns `more: false` and an empty
or short page — it never looks at a closed piece.

**Decision.** The window reader takes the manifest, selects pieces whose
`[firstMs, lastMs]` overlaps `[from, to)`, and walks them newest-first
with the same tail visitor. When a piece is exhausted before `limit`,
it continues into the next older overlapping piece. `more` is true when
any older overlapping row remains, including in a closed piece.

The panel does not change: it already asks `to=<oldest held>&limit=200`
(`Work\VERAX_OLCEK_OLCUMU_20260917.md` C result). The body becomes
honest about `more` across the cut.

---

## F2 — Chain handoff

**Decision.** The first record of a new piece sets `prevRecordHash` to
the last record hash of the previous piece — the same pointer
`appendDecisionChained` already writes (`ledger.ts` 588–605, `tailHash`
from `loadCaches` 436–437). Pieces are a storage split. The chain is
one chain.

On close, the body asks the witness for a checkpoint over
`[piece.firstMs, piece.lastMs + 1)` via the existing hook
(`requestWitnessCheckpoint` / `signWindowCheckpoint` in
`packages/body/src/witness.ts` 176–218; `checkpointsPath` in
`packages/proxy/src/checkpoints.ts` 5–7). The checkpoint's
`lastCheckpointHash` already links to the previous signed row
(`witness.ts` 162–173, 191). That is the natural Cedulon hook (task O5).

If the witness is down, rotation still closes the piece and writes the
manifest. Window-coverage stays `notApplicable` until a covering
checkpoint exists — today's STATUS rule (Phase 1 explain gap; Phase 4
paragraph). Rotation does not fail closed on a silent witness: a stuck
active file is worse than an unsigned close.

**Alternative.** Reset `prevRecordHash` to `null` at the first row of
each piece, and treat the checkpoint as the only join. Rejected:
`explain` already walks `findDecisionRecordChainBreak` on the prefix
(`packages/proxy/src/explain.ts` 152–155). A null prev in the middle of
the operator's history is a break.

**Rejected.** Signing the close with the *record* key instead of the
witness key. Checkpoints are the witness's job; the record key already
signed every row.

### How `verax doctor` / `explain` find a closed piece

`verax doctor` today compares line counts of `decisions.jsonl` /
`effects.jsonl` to `evidence-copy/` of the same names
(`packages/body/src/doctor.ts` 307–340). After rotation it walks the
manifest and compares each piece to its copy. A missing manifest with
legacy flat files is read as one piece named `legacy`.

`explain(ledger, ref)` today loads **every** decision and every effect
(`explain.ts` 103–105) and hands them to Cedulon `audit()`. Contest
"re-audits the whole ledger" is already a STATUS gap (Phase 1 panel).
Rotation does not claim to make contest cheap. First implementation may
still concatenate pieces for `explain` / `exportExtract`. What rotation
must make cheap is `loadCaches` and the window APIs.

Finding *which* piece holds `ref` is F3's index. `explain-unknown-ref`
stays the miss.

---

## F3 — Boot and indexes

**Decision.** `loadCaches` parses **only the active piece** plus
`index.jsonl`. Lifetime `decisionCount` / `effectCount` come from the
manifest (sum of closed `n` + active memory), not from parsing closed
bodies.

Indexes that must survive a restart without parsing closed pieces:

| Index | Why it must be durable | Built today from |
|---|---|---|
| `byRef` and `<tenantKey>:<ref>` | `_ref` retry; approve a defer that now sits in a closed piece | `ledger.ts` 439–450, 460–487 |
| `resolvedBy` | `already-resolved` | `ledger.ts` 491–509 |
| `reauthByHash` | spend authorize-once | `ledger.ts` 447, 731–732 |
| `effectRefs` | `duplicate-effect` | `ledger.ts` 453–456, 669 |

`tailHash` is the last hash of the active piece, or of the last closed
piece if the active file is still empty.

`countedAt` (rate / daily caps, `countedWork` in `ledger.ts` 850–867)
only needs the last UTC day plus one minute. Rebuild it from the active
piece and, if the close was today, the tail of the previous piece. Do
not persist the whole array.

`index.jsonl` is append-only, one object per decision, written in the
same `SerialQueue` turn as the decision line. Suggested fields (byte
size **not measured**; this is a field list, not a disk claim):

```
{ "ref", "tenantRef", "piece", "ts", "kind", "requestHash", "resolves", "hasEffect" }
```

A closed piece does not need to be rewritten. If `index.jsonl` is
missing or shorter than the manifest's lifetime `n`, boot may rebuild
it by reading closed pieces once and then stay on the cheap path. That
rebuild is the failure mode, not the steady path.

**Alternative.** Keep `loadCaches` on every piece and only rotate for
the window reader. Rejected: that is today's boot cost with extra files.

**Rejected.** SQLite / a second store for the index. The tree's ledger
is jsonl plus a lock file. A second engine is a new crash story.

### `_ref` reuse and approving an old defer

S1 already keys the ledger and the approvals snapshot on
`<tenantKey>:<_ref>` (STATUS S4). After rotation the durable index
answers `lookupByRef` the same way. The new `allow` appends to the
*active* piece; `prevRecordHash` is the live tail, not the defer's hash
(STATUS S1: the bind is `approver.resolves`, not `prevRecordHash`).

HTTP approve today also full-scans `decisions()` to find the defer
(`packages/body/src/server.ts` 427–428) even though `approvePending`
uses `lookupDecisionByRef`. Implementation must switch that scan to the
index; otherwise "approve old defer" still opens every piece.

---

## F4 — `evidence-copy` and retention

**What the copy is.** Each append mirrors the line into
`evidence-copy/<name>` and rewrites `heartbeat.json`
(`ledger.ts` 743–761). `verax doctor` is the speaker: short or corrupt
copy → `evidence-copy` fail; stale heartbeat → `heartbeat` / silent
(STATUS Phase 4; `doctor.ts` 283–340). Pilot drill 7 is the silenced
copy (`tests/pilot-drills.test.ts`).

**What the copy is not.** It is not a witness class. Witness class lives
on the effect row (`self` / `same-org` / …). The copy is a second
on-disk image of the same bytes so that deleting or truncating the
primary is visible on the same host. THREAT_MODEL: "silence is
indistinguishable from nothing happened if the only copy lives on the
same host." Two files on one disk are still one host. The copy is a
doctor signal, not a third party.

**Decision.** The copy rotates *with* the piece: one copy directory per
piece id, same line bytes. Doctor compares piece to piece.

**Retention (defined here, not implemented).**

1. Closed pieces and their copies stay on the machine that wrote them
   until an operator moves or drops them. No automatic delete.
2. A piece may be moved to operator-chosen cold storage only after a
   signed checkpoint covers its window, or after the operator records
   that they moved it without one (doctor then names the gap).
3. The copy moves with its source piece. Deleting the copy while the
   source remains is today's doctor fail.
4. Dropping a piece is an explicit operator command (not in this phase).
   After a drop, `explain` of a ref that lived there is
   `explain-unknown-ref`; healthz lifetime totals keep the dropped `n`
   so the count does not silently shrink.
5. Suggested default keep window, when an operator *does* drop: 13
   months after close (a year plus a month of slack). That number is a
   policy default, **not measured** against any regulation.

**Rejected.** Auto-delete after N days. THREAT_MODEL already says
silence and "nothing happened" collapse when files vanish.

**Still not designed.** Payload encryption. A right-to-erase path that
can honour a deletion request without leaving a hole that looks like
tamper. Append-only and erasure still conflict (THREAT_MODEL
"retention and erasure"; STATUS Phase 1 gaps, now split: encryption
still open, *this* keep/move/drop is the designed part).

---

## F5 — Lock and the rotation instant

**Decision.** The single writer rotates. Rotation runs inside
`SerialQueue` (`ledger.ts` 36–47, 392) while `ledger.lock` is held
(`acquireLock` 546–553, `assertOwned` 530–534). An append that arrives
during rotation waits on the queue; it is not refused.

Sequence, all in one queue turn:

1. `fsync` the active jsonl handles (they are already opened per write
   and closed in `appendDurable`, `ledger.ts` 97–104 — so this is
   "open, sync, close" of the current paths).
2. Write the piece-close row into the manifest via the same atomic
   replace the witness listen file already uses
   (`packages/body/src/atomic-write.ts` 37–64).
3. Switch in-memory paths to a new piece id. Create empty new files.
4. `tailHash` stays the last hash of the closed piece until the next
   `appendDecisionChained`.
5. Incoming `build(prev)` then chains onto that hash on the new file.

**Atomic rename.** Use it for `ledger-manifest.json` (small). Do **not**
rename a live jsonl to archive it.

**Why.** Measured on 11 September 2026 in `atomic-write.ts` 9–18: a
reader polling every 20 ms during 60 in-place rewrites saw 12 torn
reads; 26 of 60 plain `renameSync` calls failed with `EPERM` on Windows
while a reader held the destination. The helper retries 100 × 20 ms.
`decisionsWindow` holds a file handle for the whole tail walk
(`jsonl-tail.ts` 39–96). That walk is *not* on `SerialQueue`. A rename
of `decisions.jsonl` under a panel poll is the 11 Sep failure mode.

**Windows.** `FileLedger` already declines directory ACL checks on
`win32` (`ledger.ts` 108–111). Rotation adds no new ACL claim. If a
manifest rename hits `EPERM`, retry with the existing helper. If a
jsonl rename is ever attempted and fails, the manifest is the source of
truth and the old path remains readable — which is why jsonl is not
renamed.

**Crash in the middle.** Manifest commit is the cut. Files that exist
without a manifest row are doctor-fail leftovers. A manifest row whose
files are missing is doctor-fail missing-piece. Neither case is taken
over automatically (same rule as a stale lock: operator, not a second
writer).

**Rejected.** Unlock, rotate as a second process, lock again. A window
with no writer is a window a second body could take the `wx` lock
(`ledger.ts` 549–551).

---

## F6 — API

**`GET /api/ledger`.** Same query string (`from`, `to`, `limit`). The
body walks pieces as in F1. Response gains `piecesTouched: string[]`
(ids only) so a broken window is diagnosable. Rows do not need a piece
field for the panel to paint; add one later if contest needs it.

**`GET /api/agents`.** Same default last 24 h (`server.ts` 473–480;
`packages/body/src/agents.ts` 36–44). It already uses
`decisionsWindow`. After F1 it spans pieces the same way. Approvals
stay one file, so `pending` is unchanged.

**`GET /healthz`.** Today's `counts()` is whatever `loadCaches` saw
(`ledger.ts` 615–618; `server.ts` 327–345). If boot only parses the
active piece and `counts()` is left as-is, the operator sees the ledger
*shrink* after every close.

**Decision.** `decisions` / `effects` / `lastDecisionMs` remain
**lifetime** totals (manifest sum + active). Add `activeDecisions` and
`pieces` (count of manifest rows) so a panel can show both. Unauthenticated
`/healthz` stays `{ ok: true }` (STATUS F8).

**Rejected.** healthz = active piece only. A rotation would look like
data loss.

---

## F7 — Guard plan (red first)

These tests do not exist. They should fail on today's tree.

1. **Chain after close.** Close a piece; append one row. The new row's
   `prevRecordHash` equals `decisionRecordHash` of the last row of the
   closed piece. Mutate to `null` → red.
2. **Window spans the cut.** 60 rows, close at 30, ask `from`/`to` that
   covers 20..40 with `limit=10`. Both pieces appear; `more` is true
   when more older-in-window rows exist. A reader that only opens the
   active file stays red.
3. **Approve old defer.** Defer in a then-closed piece; `verax approve`
   / HTTP approve writes `allow` on the active piece with
   `resolves = defer.ref`. `lookupByRef` after a new `FileLedger`
   process still finds the defer. Boot that only parsed the active
   file and had no `index.jsonl` stays red.
4. **`_ref` reuse.** Same tenant, same `_ref` after close → `ref-reuse`
   / existing resolution, not a third defer.
5. **Boot does not parse closed bodies.** Dist seam on `ledgerFs` (the
   B0/B pattern in `tests/healthz-in-memory.test.ts` /
   `tests/ledger-window.test.ts`): after close, a new instance's
   `loadCaches` reads 0 bytes from closed `decisions.jsonl` paths
   except when rebuilding a missing index.
6. **healthz totals.** Close at 50; healthz `decisions` is still 50, not
   0. `activeDecisions` is 0 until the next append.
7. **Doctor per piece.** Truncate one closed copy → `evidence-copy`
   fail; the other piece's copy staying equal is not enough.
8. **Write during close.** An append enqueued with rotation lands on
   the new piece and does not throw `ledger-lost-lock`.
9. **Windows rename.** Manifest replace under a concurrent reader does
   not throw; jsonl paths are never passed to `renameSync`. Reuse the
   11 Sep helper.

---

## F8 — Measure plan

Same scripts as 17 September 2026: `packages/body/perf/boot.ts`,
`ledger-scale.ts` (untracked in that run;
`Work\VERAX_OLCEK_OLCUMU_20260917.md` §0). They are still not in this
tree.

| Run | What to time |
|---|---|
| 100k single piece | Regression vs 2.79 s / 979 MB RSS / 155 ms 24 h / 11 ms last 200 |
| 100k + 100k two pieces | Boot, RSS, 24 h window, last 200, healthz |
| 200k single piece (if produced) | Control: two files vs one file of the same row count |

Targets are goals, not measurements: two-piece boot in the same order
as today's 100k (seconds, not tens), 24 h window still on the order of
the 155 ms B result when the window sits in the active piece. A 24 h
window that crosses the cut is **not measured** yet; record it.

Machine line from the 17 Sep note: Intel Core Ultra 9 275HX, 31 GB,
NVMe, Windows 11, Node 24.16.0, loopback.

---

## What this note does not do

- No spike, no panel change, no live body change.
- No payload encryption.
- No right-to-erase.
- No change to Cedulon's `Ledger` interface (`docs/PHASE3_DESIGN.md`
  opening rule still holds).
- No central archive service (that is `docs/design/fleet.md`).
