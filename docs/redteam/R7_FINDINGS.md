# R7 findings — attack the fixes

Independent of R6. R6 was clean; this round attacks the boundaries added since R3. Product code was not changed. Tests were not executed (the task forbids commands). Each provable row has an `it` in `tests/attack-r7.test.ts` that asserts the safe behaviour, which the current tree does not implement.

No critical findings. One high finding.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R7-1 | high | A local non-admin, on a root Administrators already owns | The root DACL check only matches English names (`Users`, `Everyone`, `Authenticated Users`, `Interactive`, `CREATOR OWNER`). A write ACE printed as `*S-1-5-32-545` or as a localized name (`VORDEFINIERT\Benutzer`, `BUILTIN\Kullanıcılar`, `ERSTELLER-BESITZER`) is treated as admin-only. `planInstall` continues. `installedBoundaryChecks` reports the root ACL ok. | `packages/body/src/install.ts:550`, `packages/body/src/install.ts:1626` | `R7-1 a non-admin write ACE is refused when icacls names it by SID or by a non-English account` |
| R7-2 | medium | The brain, holding `verax:memory` | The per-tenant cap sums the directory, then writes. Two `memory.put` calls in flight both read the directory before either write lands, so each sees the other as absent. Two 600_000-byte bodies both store. The admission queue does not cover this: `launchInner` returns the tool promise and the queue settles before `memory.put` runs. | `packages/body/src/tools/memory.ts:157`, `packages/proxy/src/proxy.ts:392` | `R7-2 two in-flight memory puts cannot pass the tenant quota together` |

## R7-1 the root DACL parser misses a SID and a translated name

**Invariant the fix claims.** Before any child is written, a fresh `%ProgramData%\Verax` is locked to Administrators and SYSTEM, and the directory is empty afterwards. An existing root is kept only when the owner is Administrators or SYSTEM and the DACL has no non-admin write ACE.

**What was tried.** The English case `BUILTIN\Users:(OI)(CI)(M)` is already refused (`tests/attack-r3.test.ts`). The same rights were handed to `planInstall` as `*S-1-5-32-545` (Users), `*S-1-1-0` (Everyone), `VORDEFINIERT\Benutzer`, `BUILTIN\Kullanıcılar`, and `ERSTELLER-BESITZER`, with owner `BUILTIN\Administrators` and the install marker present. `principalHit` compares the ACE tail to `users`, `everyone`, `authenticated users`, and `interactive`. `rootDaclRejected` adds a `/creator owner/i` scan and nothing else. Well-known SIDs are not in that list. `icacls` prints those SIDs when the name is unresolved, and it prints the localized name on a non-English Windows.

**Expected.** `plan.ok` is false and the message says the root was not created by verax install. A write ACE for Users, Everyone, or CREATOR OWNER is the same ACE in every language and when it is written as `*S-1-…`.

**Actual.** `plan.ok` is true. The owner check passes. `rootDaclRejected` returns false. Doctor's `install-root-acl` row says the ACL names only Administrators and SYSTEM.

**Fix.** Treat these SIDs as non-admin writers: `S-1-5-32-545`, `S-1-1-0`, `S-1-5-11`, `S-1-5-4`, `S-1-3-0`. Refuse the ACE when the principal is not Administrators (`S-1-5-32-544`) or SYSTEM (`S-1-5-18`), instead of requiring an English word.

## R7-2 parallel puts walk around the quota

**Invariant the fix claims.** `memory.put` refuses when this tenant's stored bytes plus the new file would pass the cap (default 1 MiB). Replacing an id counts the new bytes, not the old file. Other tenants are not counted.

**What was tried.** One principal, empty memory directory, two `memory.put` calls started together, each with a 600_000-byte body. Each file alone is under 1 MiB. Together they are over it. Symlinks were not a bypass: `stat` follows them, so a link at a large file counts against the cap. Other tenants are excluded on purpose.

**Expected.** One call returns `memory-quota`. The tenant directory stays within the cap.

**Actual.** Both calls return `{ ok: true }`. `readdir` runs, then `writeFile`. Nothing holds the directory across that gap. `SerialQueue` awaits only the admission callback, and that callback returns `{ kind: "run", work }` from `launchInner` without awaiting `runInner`. The second put reads the directory while the first write is still pending.

**Fix.** Hold one lock per tenant memory directory from the size check through `writeFile`. The second put must observe the first file.

## Checked and solid

1. **Fresh root, empty after the lock.** `applyLockRoot` creates the directory, sets the owner and the Administrators/SYSTEM DACL, then `readdir`. A child name refuses and deletes the root. An `EEXIST` on create refuses. That is the file race W1 already required. R7-1 is the ACE that is not a child file.
2. **Token grant by SID, profile from ProfileList, `verax-svc` by SID, home from getent/dscl, existing Linux `verax`.** `planInstall` still refuses a Windows account with `createdByUs` false, a `USERPROFILE` that disagrees with `profileImagePath`, and a Linux account with `createdByUs` false. The grant args use `ADMINISTRATORS_SID` and `SYSTEM_SID`. No second hole showed beside the read-back parser.
3. **Effect binding.** A row is bound only when the decision's `effectHash` matches, or the class is exactly `duplicate-effect` and the hash is `sha256Canonical({ refused: "duplicate-effect", ref })`, or the class ends with `:threw` and a decision with that ref exists. The attestation and the receipt still have to verify under one key, and `canonical(receipt effect)` must equal `canonical(row)`. Changing the class, the hash, or the result without that signature orphans the row. Unsigned rows are not bound. `:threw` does not skip the signature. In-ledger mode takes the first receipt key and checks every row against it; a key the attacker inserts first makes honest rows fail, and the trust note already says that key was not pinned. Pinning is the check the docs name.
4. **Checkpoints.** Each loaded row is verified under the pinned key or the first key in the file. `loadCheckpoints` drops a malformed line; the next row's `prevCheckpointHash` then fails `findCheckpointChainBreak`, so a skipped middle row does not become coverage. The tail is the verified prefix. A bad signature is a problem, so `ok` is false.
5. **Reconcile.** `reconcile` matches only when `decisionRefs` contains the effect ref. The default set is empty, so a missing decision is not a match. `runReconcile` passes `loadDecisionRefsFromDir`.
6. **Spend controls and approve.** `SPEND_CONTROL` and `heldLine` use one class, `\p{Cc}\p{Cf}\p{Zl}\p{Zp}`. U+2028, U+2029, and U+0085 are in it. `escapeHeld` rewrites those marks, and also `=` once any mark is present, so a stored row cannot open a second `payee=`. The class is on the spend arguments the gate reads (`payee`, `reference`, `currency`) and on every field `heldLine` prints (`subject`, `payee`, `currency`, `reference`, `requestHash`).
7. **Approved retry.** The retry path calls `applyInputValidity(resolved.reasonCode, …)` and writes a deny when that reason is set, before `launchInner`. An expired cited input is `input-invalid` on the retry.
8. **Dev issuer.** `issuerHostDecision` runs before the route, and `POST /revoke` requires `role === "operator"`. An agent token is 403. A foreign Host is not served the revoke.
9. **Docs.** `docs/STATUS.md` portable-verification row matches the verify path that was read (one effect key, one witness key, tail from the verified prefix, `:threw` and `duplicate-effect` called out in `verify-ledger.ts`). It does not mention the memory cap or the root-ACE parser. The false sentence is the doctor detail `root ACL names only Administrators and SYSTEM`, which R7-1 makes untrue. No README sentence was found that claims more than the code keeps.
