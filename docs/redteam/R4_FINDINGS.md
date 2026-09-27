# R4 findings — everything except the installer

Independent of R1, R2, and R3. R3 stayed on `verax install` / `uninstall` / `doctor`; this round did not. Product code was not changed. Each provable row has a test in `tests/attack-r4.test.ts` that asserts the safe behaviour and fails on the current tree.

No critical findings. Two high findings.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R4-1 | high | Whoever can hand `verify` a ledger directory | An effect row keeps `ok: true` after its `effectHash`, `effectClass`, and `resultHash` are replaced, as long as `row.ref` still names a decision. The attestation is not checked. `verify` reports VERIFIED over a row that describes a different action. | `packages/proxy/src/verify-ledger.ts:284` | `R4-1 verify rejects an effect whose hash or result no longer matches its decision` |
| R4-2 | high | The brain, holding `verax:pay` | `reference` may contain CR and other C0 controls. `verax approve` prints that string on the held line, so a carriage return redraws `payee=` before the operator types the amount. The amount check still passes. The recorded payee is the policy payee, not the one left on screen. | `packages/proxy/src/policy.ts:168`, `packages/body/src/approve-cli.ts:75` | `R4-2 a spend reference cannot redraw the approve line` |
| R4-3 | medium | Whoever can hand `reconcile` an effects file | `reconcile` matches a channel row to an effect by `ref` and time. It never opens decisions. An effect with no decision is `matched`, not a ghost. | `packages/proxy/src/reconcile.ts:407`, `packages/body/src/reconcile-cli.ts:240` | `R4-3 reconcile does not match an effect that has no decision` |
| R4-4 | medium | The brain, holding `verax:memory` | Each HTTP call is capped at 1 MiB. `memory.put` has no per-tenant total. Two 700 KiB bodies both store. After install, that write is the service account's disk. | `packages/body/src/tools/memory.ts:144`, `packages/body/src/server.ts:208` | `R4-4 a tenant cannot fill the disk through memory.put` |
| R4-5 | medium | A web page the operator visits, after DNS rebinding to `127.0.0.1` | The dev issuer binds loopback and does not apply the body's Host check. `POST /revoke` has no credential check. A rebound browser appends any `jti` to `revoked-jti.jsonl`. | `scripts/dev-issuer.mjs:692` | `R4-5 the issuer does not revoke a jti for a rebound browser` |

## R4-1 an effect can lie and still verify

**Steps.** Copy a ledger `verifyLedger` already accepts. On the first effect row, set `resultHash` to 64 zeroes, `row.effectHash` to 64 `f`s, and `row.effectClass` to `spend`. Leave `row.ref` and the decision file alone.

**Expected.** `ok: false`, and a problem that names the effect. A bound effect is one whose `effectHash` is the decision's and whose attestation still covers `{ ref, effectHash, witnessClass, resultHash }`.

**Actual.** `ok: true` and `problems: []`. The loop counts an effect as bound when `row.ref` is any decision ref. Signatures are checked on decisions only.

**Fix.** For each effect, require a decision with that ref whose recorded `effectHash` equals `row.effectHash`, and require the attestation to verify over the row that was read. A mismatch is `effectsOrphaned` or a named problem, and `ok` is false.

## R4-2 reference redraws the approve line

**Steps.** With a spend rule whose payee is `true-ads`, call `spend` with `reference` set to `inv` + CR + `held tool=spend payee=other-ads amount=100 currency=TRY reference=ok`. Run `verax approve` on a TTY and type `100`.

**Expected.** The call is `deny spend-args-invalid` before a snapshot exists. A reference is one line of printable text. The held line the operator sees contains `payee=true-ads` and does not contain a second `payee=`.

**Actual.** Policy returns `defer approval-required`. `heldLine` interpolates `reference` raw. On a terminal the CR returns to column 0 and the rest of the reference overwrites the real payee. The typed amount still matches, so the approval proceeds for `true-ads`.

**Fix.** Reject C0 and DEL in `payee` and `reference` inside `spendArgsInvalid` (and the same class of marks in any other field `heldLine` prints). `heldLine` should still strip controls so a row already on disk cannot redraw the prompt.

## R4-3 reconcile matches an effect with no decision

**Steps.** Call `reconcile` with one channel row `ref=ghost-spend` and one effect with that ref and the same timestamp. Pass no decisions file and no approval snapshot. Leave the amount unset on both sides so the unpriced gate would otherwise match.

**Expected.** `matched` is empty and the channel row is a ghost. A match requires a decision with that ref.

**Actual.** `matched.length` is 1. `loadEffectsFromDir` is the only ledger read in `runReconcile`.

**Fix.** Load decision refs the same way `verifyLedger` does, and treat an effect whose ref is not a decision as unmatched. Do not put that channel row in `matched`.

## R4-4 memory has no tenant quota

**Steps.** As one principal, `memory.put` two bodies of 700_000 bytes under two ids.

**Expected.** The second call is an error. Bytes already stored for that tenant count, and the next put that would pass 1 MiB is refused. The per-request HTTP cap does not reset the total.

**Actual.** Both calls return `{ ok: true }`. `memoryPut` writes the JSON it was given. `MAX_BODY_BYTES` applies to one HTTP body only.

**Fix.** Before `writeFile`, sum the tenant `memory/` directory (or keep a counter) and refuse with a signed deny when the put would pass a fixed per-tenant cap. Count the file that would be replaced, not only new ids.

## R4-5 issuer revoke is open on loopback

**Steps.** Start `scripts/dev-issuer.mjs` on `127.0.0.1`. `POST /revoke` with `Host: rebind.example` and `{"jti":"not-a-session"}`. Send no bearer and no passkey.

**Expected.** `401`, and `revoked-jti.jsonl` does not contain that jti. A foreign Host on loopback is refused the same way `loopbackHostDecision` refuses it on the body.

**Actual.** `200 {"revoked":true}` and the jti is appended. The request handler never reads `Host` and never checks a credential on `/revoke`.

**Fix.** Apply the body's loopback Host rule before routing. Require an operator session (the same passkey-backed token `/authorize/verify` mints) before appending a jti. A missing or foreign caller writes nothing.

## Checked and solid

- Proxy HTTP smuggling. The body reads one JSON body through Node's HTTP parser and does not forward the raw client bytes upstream. Downstream HTTP sets `redirect: "error"` and sends only headers from the operator document, not the inbound agent bearer. No second finding beyond R4-5's Host gap on the issuer.
- Downstream stdio does not copy `process.env`. A stdio child still shares the user; that bound is already stated on the Downstream MCP row in `docs/STATUS.md`.
- `audit.explain` and `memory.get` deny another tenant. Own memory wins over a foreign id. `_ref` is tenant-scoped. R1 already covered path escape.
- Approval HTTP checks `requestHash` against the waiting snapshot. Local mode refuses `verax:approve` and `verax:audit`. The agent token path strips `verax:approve`. WebAuthn checks origin, RP ID, and a one-time challenge. Counter `0` stays equal on purpose for authenticators that do not increment; the challenge is deleted on use, so that is not an assertion replay.
- Pairing is eight digits, five attempts, then burned. A timing leak of the stored hash was not shown: the compare is not constant-time, and the disk write dominates, so it is not claimed as a break.
- Halt is a file. Restart does not delete it. Deleting the file is what resumes work; that is the operator's act, not a silent clear.
- Witness `/sign` and `/checkpoint` require the listen token. `/health` returns a pid and nothing else. Swapping `witness.listen.json` needs a writer in the state directory, which is the same-user case the threat model already names.
- Panel records go through React text nodes. No `dangerouslySetInnerHTML` on tool names, payees, or downstream text. The session token is a module variable, not a cookie, so a cross-origin frame does not inherit a signed-in panel. Clickjacking an approval was not shown. The panel still sets no `Content-Security-Policy` or `frame-ancestors`; that is defense in depth, not a spend without an operator.
- Inventory parse does not read other MCP clients' configs and does not execute values it finds. `readInventoryFile` returns absence on broken JSON.
- `docs/STATUS.md` portable-verification row says each effect is bound by `effectHash`. R4-1 is that claim failing. The other matrix rows that were opened in this pass match the code that was read.
