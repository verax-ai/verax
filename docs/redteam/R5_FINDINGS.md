# R5 findings — crypto call sites, ledger tail, MCP, tokens, what ships

Independent of R1–R4. Those rounds stayed on token forgery, Host rebinding, install, and effect-hash binding. This round did not reopen them. Product code was not changed. Tests were not executed (the task forbids commands). Each provable row has an `it` in `tests/attack-r5.test.ts` that asserts the safe behaviour, which the current tree does not implement.

No critical findings. One high finding.

Disposition in this tree: R5-1 and R5-2 are fixed. R5-3 is accepted: test-only keys, named TEST-KEY-NOT-A-SECRET, not in any package files list, no product code references them.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R5-1 | high | Whoever can hand `verify` a ledger directory | `checkpoints.jsonl` is treated as signed coverage when a row has `claims` and a `coseHex` string. The COSE signature is never checked. Drop the newest decision and its effect, then write a checkpoint whose `receiptCount` equals the shorter file. `verify` reports VERIFIED. History changed. | `packages/proxy/src/checkpoints.ts:22`, `packages/proxy/src/verify-ledger.ts:269` | `R5-1 verify rejects a checkpoint whose signature does not verify` |
| R5-2 | medium | Whoever can hand `verify` a ledger directory | The effect COSE payload and the receipt signature do not have to agree with `row.effectClass`. The receipt check compares `ref` and `effectHash` only. Rewriting the row's class to `spend` leaves `ok: true`. | `packages/proxy/src/verify-ledger.ts:196` | `R5-2 verify rejects an effect row whose class is not the signed class` |
| R5-3 | low, accepted | Anyone who clones the repo | accepted: test-only keys, named TEST-KEY-NOT-A-SECRET, not in any package files list, no product code references them. Two PKCS#8 private keys stay under the golden-ledger fixtures because the golden ledger is signed with them. | `packages/proxy/tests/fixtures/keys/record-signer.TEST-KEY-NOT-A-SECRET.pem:2` | `R5-3 private keys stay under tests/fixtures and are named TEST-KEY-NOT-A-SECRET` |

## R5-1 an unsigned checkpoint covers a shortened ledger

**Steps.** Copy the golden ledger. Delete the last decision (`ref` `n6`) and the effect with that ref. Write `checkpoints.jsonl` as one JSON object whose `claims.receiptCount` is the number of decisions left and whose `coseHex` is the two characters `00`. Do not sign it. Call `verifyLedger`.

**Expected.** `ok: false`, and a problem that says the checkpoint signature does not verify. A checkpoint counts only after its COSE signature verifies under a witness key the reader pinned, or the absence of a verifiable checkpoint is stated and is not coverage. A file that merely contains `coseHex` does not make the tail "covered".

**Actual.** `loadCheckpoints` keeps every row that has `claims` and a string `coseHex`. `tailStatement` reads `receiptCount` from those claims and, when the count equals the number of decisions left, adds no problem. `ok` is true. The tail line says the records after the newest checkpoint are zero. `docs/STATUS.md` says a signed checkpoint's covered count is held against the ledger. The signature is not held.

**Fix.** Verify the checkpoint COSE before trusting `receiptCount` or `chainHeadHash`. A row that does not verify is a problem, and `ok` is false. Do not let that row satisfy the tail.

## R5-2 the effect class on the row is not the signed class

**Steps.** Copy the golden ledger. On the first effect, set `row.effectClass` to `spend`. Leave the receipt, the attestation, `effectHash`, and `ref` as they are.

**Expected.** `ok: false`, and a problem that names the effect class. The class on the row must be the class inside the signed receipt effect (and the class the decision recorded, except the `:threw` case the writer already documents).

**Actual.** `ok: true`. `effectSignatureCoversRow` checks the receipt's `ref` and `effectHash` against the row and does not check `effectClass`. The COSE payload that is compared is `{ ref, effectHash, witnessClass, resultHash }`. The class the file shows is `spend`. The signed receipt still says `memory.get`.

**Fix.** Require `signedRow.effectClass === row.effectClass` before counting the effect bound. A mismatch is orphaned and `ok` is false.

## R5-3 committed test private keys

**Steps.** Read `packages/proxy/tests/fixtures/keys/record-signer.TEST-KEY-NOT-A-SECRET.pem` and `effect-signer.TEST-KEY-NOT-A-SECRET.pem`.

**Expected.** No `BEGIN PRIVATE KEY` block in the repository. A golden ledger can ship a public key and signatures. The private half stays out of git.

**Actual.** Both files are PKCS#8 private keys. The names say they are not production secrets. `files` on inventory, proxy, and body is `dist` (proxy also ships `policy/`), so an npm install does not receive `tests/`. The keys still sign the committed golden ledger, and anyone with the clone can produce new rows that verify under those public keys.

**Accepted.** The private PEMs stay. The golden ledger is signed with them. accepted: test-only keys, named TEST-KEY-NOT-A-SECRET, not in any package files list, no product code references them. `tests/attack-r5.test.ts` keeps that true: every committed PEM private key lives under a `tests/fixtures/` path and has `TEST-KEY-NOT-A-SECRET` in its file name, and no file under `packages/*/src` references those names.

## What an npm install receives

No finding beyond R5-3, which does not ship. From each package `package.json`, `tsconfig.build.json`, and `.github/workflows/release.yml` (no `.npmignore` in the repo):

- `@verax-ai/inventory` and `@verax-ai/body`: `files` is `dist` only. `@verax-ai/proxy`: `dist` plus `policy/` (the shipped default policy). npm also packs `README` and `LICENSE` by its own defaults. `prepack` runs `tsc`. There is no `postinstall`, `install`, or `prepare`.
- Build `compilerOptions` do not set `sourceMap` or `declarationMap`. TypeScript's default is off, so the tarball is not described as containing source maps. No secret is compiled into `src/`.
- `release.yml` publishes with `npm publish -w <pkg> --provenance --access public` after `npm ci --ignore-scripts` and `npm test`. `confirm` is passed as `CONFIRM` and compared in the shell; it is not expanded inside the script. Nothing in the workflow installs a dependency script from the packages.

## Checked and solid

- Effect hash, result hash, and a stripped attestation. R4 already requires the decision's `effectHash` and a verifying attestation. Not reopened. R5-2 is the class field that check still skips.
- Torn last line. `verifyLedger`'s `readJsonl` pushes `unreadable row` and that string is a problem, so `ok` is false. A partial line does not verify.
- Two bodies, one state directory. `acquireLock` creates `ledger.lock` with `flag: "wx"`. A live pid is `ledger-locked`. A dead pid is not taken over; `verax unlock` is required. That matches the threat-model sentence that the lock is not stolen.
- Rotation while writing. `appendDurable` writes the decision, then `maybeRotate` closes the piece. A crash between them leaves a durable line on the open piece. The next open rebuilds a short index from the pieces (`parseIndexText` skips a torn index line). That does not make `verify` accept a rewritten decision.
- Checkpoint rollback of a real signature, and replay of an older checkpoint, were not shown separately from R5-1. Once a row is accepted without a signature, rolling the claims back is the same bug.
- Effects before the decision. `appendDecision` fsyncs the decision line before the tool path appends an effect. Not reopened (R1 case 13).
- MCP sessions. `StreamableHTTPServerTransport` is constructed with `sessionIdGenerator: undefined` and closed in `finally` after each POST. There is no session id to reuse, and a downstream result cannot be delivered on a request the proxy did not forward: the downstream client is the SDK session opened at startup, not a client-supplied id. `tools/list` is taken once in `openDownstream`. A child that changes behaviour afterwards is the hostile tool server the threat model already names.
- Agent tokens. `init --local` sets `sub` to one subject, `jti` to a new UUID, `iat` to now, and `exp` to now plus the day count. `jwtVerify` requires `exp`, `iat`, and `sub`, with a 60s clock tolerance, and rejects `iat` more than 60s ahead. `isRevokedJti` scans the whole file and does not truncate it, so a revocation is not forgotten by growth. A token for one `sub` is another brain only if the issuer put that `sub` in it. Registering two agents onto one id was not found: `agentsWindow` keys rows by the inputs `principal.brain`, and the roster updates that row in place.
- Canonical JSON, COSE alg confusion, detached payloads, indefinite CBOR, and signature malleability. `node_modules/@cedulon` is not in this worktree, so the shipped library bytes were not read. Verax compares `canonical(decodedPayload)` to the row fields it intends to bind and then calls `verifyCoseSign1`. No second call site was found that displays a claim the signature does not cover, other than R5-2's `effectClass`.
- `server.json` `0.3.0` matches the three package versions. The portable-verification row in `docs/STATUS.md` is the claim R5-1 breaks. The witness row matches `witness.ts`: a second process, its own key, `same-org` when it answers.
