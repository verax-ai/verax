# R11 findings — outside eye on supply chain, panel/desktop, passkey, crypto

Round R11 ran against 0ddf9c4 with a different model family from R1–R10 (OpenAI Codex, read-only sandbox), aimed at
the four surfaces that had no dedicated round: supply chain and release, panel and desktop, passkey/operator approval,
and cryptography/ledger format. The run reproduced its findings with in-memory probes and then stopped before writing
its report, so this file was assembled at the gate from those probes. Every row below was re-run or re-read at the gate;
the column "measured" says which.

Two high findings. Two medium findings. One low finding.

| id | severity | attacker | description | file:line | measured |
| --- | --- | --- | --- | --- | --- |
| R11-1 | high | Another local user while `verax desktop` runs | One unauthenticated `POST /token` whose JSON body is `null` throws in the dev issuer and the process exits. `verax desktop` supervises only the browser, so the body keeps running and keeps fetching keys from the issuer's port. The freed loopback port can be bound by another user, who serves a JWKS of their own and mints a token with `verax:approve`. | `scripts/dev-issuer.mjs` (`/token` body handling), `packages/body/src/desktop.ts:312-470` | issuer crash: reproduced at the gate (`TypeError: Cannot read properties of null (reading 'grant_type')`, port closed). Desktop supervision: read at the gate. Body accepting a replacement JWKS: reproduced by the round in simulation; the end-to-end takeover is code-traced. |
| R11-2 | high | Whoever can create a pending approval while the operator is confirming another (the agent) | The panel's approval confirmation is state on the component, not on the row. The operator presses Approve on request A; a new pending request B becomes the row on screen at the next poll; the open confirmation now shows B and Yes sends B's `ref` and `requestHash`. | `apps/panel/src/blackbox/BlackBox.tsx` `ConsoleApprove` | reproduced at the gate: "Confirmation persisted: true", "Approval callback ref: B". |
| R11-3 | medium | Whoever writes a ledger and chooses its key when no key is pinned; any consumer that trusts the label | A COSE_Sign1 labelled alg `-19` verifies under an Ed448 key. RFC 9864 assigns `-19` to Ed25519 only. With a pinned Ed25519 key an Ed448 signature does not verify, so this does not forge records; it makes the algorithm label untrue. | `@cedulon/cose` `verifyCoseSign1` (dependency), key loading in `packages/proxy/src/verify-ledger.ts` | reproduced by the round (`verifyCoseSign1(ed448 signature, ed448 key) === true`). |
| R11-4 | medium | Whoever can write the ledger directory | A `checkpoints.jsonl` line that does not parse as a checkpoint is dropped before verification, so a damaged checkpoint file reads as "no checkpoint" and the result is `ok: true` even with `--checkpoint-key` pinned. Deleting the file has the same outcome, which the tail line states; a damaged file should be named as damaged. | `packages/proxy/src/checkpoints.ts`, `verify-ledger.ts` `tailStatement` | reproduced by the round: `{"ok":true,"checkpointTrust":"pinned","tail":"no checkpoint…","problems":[]}` for a file containing `{}`. |
| R11-5 | low | Whoever can write the ledger directory | A manifest that is not valid JSON makes `verifyLedger` throw. `verax verify` prints a Node stack and exits 1: it never says VERIFIED, but it prints no `NOT VERIFIED` line and no `--json` document. Parse errors in the index and checkpoint readers are the same class. | `packages/proxy/src/ledger-manifest.ts` `readLedgerManifest`, `verify-ledger.ts` | reproduced at the gate (exit 1, stack, no JSON). |

## Checked and solid (this round)

1. Release workflows pin actions by commit, pass confirmation inputs through environment variables rather than
   interpolating them into shell, and do not restore dependency caches in the publish job.
2. Installer npm calls run with lifecycle scripts disabled and an isolated npm configuration.
3. The dev issuer's passkey routes check the RP ID, the origin, user verification, and use each challenge once.
4. A manifest piece deleted from the middle of a multi-piece ledger (with or without removing it from the manifest) is
   reported: the hash chain breaks and the index names records the ledger no longer holds (measured at the gate).

## Not covered

The round stopped before it wrote its own account of what it did not read; npm dependency install scripts and the
MCP registry publish path were not reported on in detail and are not claimed as checked here.
