# R6 findings — the product from the outside

Independent of R1–R5. Those rounds read one layer each. This round starts from the same place a hostile client does: a tool call, an approval, a ledger directory handed to `verify`. Product code was not changed. Tests were not executed (the task forbids commands). Each provable row has an `it` in `tests/attack-r6.test.ts` that asserts the safe behaviour, which the current tree does not implement. The fuzz `it` asserts invariants that hold on this tree.

No critical findings. No high findings.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R6-1 | medium | The brain, holding `verax:pay` | `reference` may contain U+2028, U+2029, and U+0085. Those are line breaks, and they are outside the C0/bidi set R4-2 closed. The call is held, and `verax approve` prints the reference on the held line, so a second line can show another `payee=`. The amount check still uses the real amount. The first line still shows the real payee, which is why this is not the carriage-return overwrite. | `packages/proxy/src/policy.ts:171`, `packages/body/src/approve-cli.ts:89` | `R6-1 a spend reference cannot carry a line separator or a C1 newline` |
| R6-2 | medium | The brain, holding a tool the operator already approved | A retry of an approved `_ref` does not read `resolved.reasonCode`. After the cited input's `validUntilMs`, the same call still runs `inner` and writes an effect. The arguments are the ones the operator approved. The input gate is the part that is skipped. | `packages/proxy/src/proxy.ts:591` | `R6-2 an approved retry does not run after the cited input has expired` |

## R6-1 a reference can break the held line

**Steps.** Policy payee `true-ads`. Call `spend` with `reference` set to `inv` plus U+2028 (and the same for U+2029 and U+0085) plus `payee=other`.

**Expected.** `deny` / `spend-args-invalid`. No snapshot. A reference is one line. The marks that start a new line are in the same class as CR.

**Actual.** `defer` / `approval-required`. `SPEND_CONTROL` is C0, DEL, and the bidi set. U+2028 and U+2029 sit just before that bidi range. U+0085 is a C1 next-line. `heldLine` prints `reference` after escaping only that same set, so the mark reaches the terminal.

**Fix.** Treat U+2028, U+2029, and C1 (U+0080–U+009F) as `spendArgsInvalid`, and escape them in `heldLine` so a row already on disk cannot open a second line.

## R6-2 the approved retry skips the input clock

**Steps.** `memory.put` in approve mode, with `_inputs` citing a document whose `validUntilMs` is 5000. Call at t=1000. Operator approves. Retry the same `_ref` and the same arguments at t=6000.

**Expected.** `denied:input-invalid`. `inner` is not called. No effect row. A fresh call at t=6000 is already denied for that reason; an approval does not extend the input's life.

**Actual.** `inner` runs and an effect is appended under the allow ref. `resolveInputs` has already returned `input-invalid`, and that reason is applied only when the admission path creates a new decision. The approved branch calls `launchInner` without looking at it.

**Fix.** On every retry, if `resolved.reasonCode` is set, write a deny for that reason and do not call `inner`. Keep the approval bound to the inputs that were valid when the operator approved, and refuse once those inputs are not.

## Checked and solid

1. **Money without the operator.**
   - Defer/approve race. `approvePending` and the admission path each take a serial queue. A second approve of the same ref returns `already-resolved`. The spend effect is written in that same approve, before `updateStatus`. A crash after the allow and before the effect leaves no `authorized: true` row; the brain's retry is `spend-reauth-required`, not a second authorization.
   - `_ref` reuse. A different argument object is `ref-reuse`. Another tenant's key is a different scoped ref (`tenantKey` plus the raw ref). A restart rebuilds that index from the inputs principal.
   - Argument changes that keep `requestHash`. `_ref` and `_inputs` are stripped before the hash, so a new amount, payee, or reference does not match. Extra spend keys are `spend-args-invalid` on the first call. The hash does not keep a different payee.
   - Approval TTL. `now > expiresAtMs` writes `expired` and does not write a spend effect. A halted file denies new calls; deleting it is the operator's act and does not turn a defer into an allow.
   - Same-user shell. `verax approve --from-script` skips the typed amount. That is the local-mode case `README.md` calls "not a boundary", the init banner states, and `docs/STATUS.md` points at `docs/THREAT_MODEL.md` ("a brain with a shell"). Installed mode is the boundary those documents name: the state directory is not the agent's. Not refiled.
2. **A lie that verifies.** Shortening a golden ledger, or rewriting an effect class, hash, or result, fails the checks R4 and R5 added: effect hash, signed class, attestation, checkpoint signature. A checkpoint whose `receiptCount` is below the file length stays `ok` only together with the tail line that those records are not covered; `renderVerify` prints that line above `VERIFIED`. Deleting covered records breaks the count or the chain head. Rewriting rows with the state-directory key is the same-user case the threat model and the local-issuer row already state. Pins do not make a same-user key into a second party.
3. **Blind the operator.** CR and bidi in `payee` / `reference` are `spend-args-invalid` (R4-2). The panel renders tool names and payees as text; this pass did not find `dangerouslySetInnerHTML` on those fields. `pairFromLedger` can attach a different row with the same `requestHash`, and nothing in the panel calls it. Pending rows stay pending until status changes. R6-1 is the line-break that set still misses.
4. **Tenant escape.** `memory.get` / `memory.put` resolve under `tenants/<tenantKey>/memory`. `message.read` / `message.send` use the same key. A foreign id is not that path. `_ref` lookup uses the tenant key whenever `iss`, `tenant`, or `org` is set, which a local token's `iss` is. `/api/ledger` and `/api/approve` still require `verax:audit` / `verax:approve`, and local mode answers 403 for those scopes.
5. **Stuck open / lost record.** An allow without an effect does not become a second run when `in-flight/<hash>.start` remains; the retry is `outcome-unknown`. A poison approval command is appended and the pending row stays pending, so the operator still sees it. Disk-low deny is unsigned only when the append itself throws, which is the recorded `ledger-disk-low` path. Plain request volume was not treated as a finding.

Fuzz. `R6 fuzz` draws 80 calls from seed `0x6e6`, builds the argument object the way `CallTool` does (`arguments ?? {}`), and evaluates them. Spend is never `allow`. A `memory.get` without `verax:read` is never `allow`. Twelve deny verdicts are also sent through `createProxy`: `inner` is not called and no effect is written. No crash and no break on this tree, so that `it` is written to pass.
