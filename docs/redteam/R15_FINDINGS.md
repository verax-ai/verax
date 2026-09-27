# R15 findings — whole-repository chain review

Round R15 read the repository as chains (call, install, desktop, the fixes already in the tree), not as one file at a time. The tree under review was `fix/pre-launch-attack`. One high finding, five medium, five low. This file records what was fixed in F24 and what was left open.

| id | severity | description | status |
| --- | --- | --- | --- |
| R15-1 | high | Elevated `doctor`, `verify`, `unlock`, `halt`, `witness`, `reconcile` and `serve` ran without the code check that `install`, `uninstall` and `approve` already had. | fixed |
| R15-2 | medium | On Linux and macOS an elevated `approve` queued `approval-commands.jsonl` as root mode 0600. The service could rename it, could not read it, and the drain deleted it. | fixed |
| R15-3 | medium | `verax desktop` names origins by IP, so the passkey ceremony cannot complete in a browser, and the body it starts has no `VERAX_ALLOWED_ORIGINS`, so the panel's approve is `origin-not-allowed`. Both fail closed. | open |
| R15-4 | medium | `verax verify` checked every effect row under one key, so a ledger with both `self` and `same-org` rows was `NOT VERIFIED`. | fixed |
| R15-5 | medium | The body stored a `same-org` answer without checking it against `listen.publicKeyPem`. | fixed |
| R15-6 | medium | Elevated `approve` built the daily cap from `VERAX_POLICY_FILE` before the state-directory snapshot. | fixed |
| R15-7 | low | `approvePending`, `/api/approve` and the drained queue did not read `halted`. | fixed |
| R15-8 | low | `noteTenantRef` can point a tenant-scoped ref at a bare nonce, so a later call answers `allowed` while a fresh defer is still pending. | open |
| R15-9 | low | `verax verify` does not read `inputs.jsonl`, so an edited approver id still verifies. `explain` names the hash mismatch. | open |
| R15-10 | low | Elevated `approve` took `ProgramData` from the environment without the ancestor check the installer uses. | fixed |
| R15-11 | low | The dev issuer accepts a `text/plain` body, so a page can burn the pairing code without a preflight. | open |

## Fixes

- R15-1: the CLI dispatcher calls `elevatedCommandCodeRefusal` once when the process is elevated, before any command except `--help` and `--version`. Install and approve keep their check for direct callers and skip it when the dispatcher already passed. `unreadableSentence` names the administrator-owned copy. The threat model states that a same-user elevated PowerShell runs that user's profile, which the code check does not see.
- R15-2: on POSIX the queue file is opened without following a link, and when the writer's uid is not the state directory's uid it is `fchown`ed to that directory before the bytes are written. A file the drain cannot read is renamed to `approval-commands.unreadable-<ts>` and kept, and the error is logged.
- R15-4: `self` rows verify under the effect key and `same-org` rows under the witness key (`--witness-key`, otherwise the first `same-org` receipt key). The result carries `witnessTrust` with the same agreement-is-not-trust wording.
- R15-5: `requestWitnessSign` checks the receipt and the attestation against `listen.publicKeyPem` before it returns `same-org`. A mismatch is `self-fallback` with reason `witness-key-mismatch` and no `same-org` row.
- R15-6: an elevated approve ignores `VERAX_POLICY_FILE` and reads only the snapshot in the state directory. A spend with no snapshot is `approve-policy-missing`. An approve that is not elevated is unchanged.
- R15-7: `approvePending` refuses with `halted` when the state directory holds `halted`, and the pending row stays pending. `/api/approve` answers HTTP 409 `approve-halted`. The drain goes through the same function.
- R15-10: resolving the installed state directory on Windows applies the ProgramData ancestor check and refuses otherwise.

Corrections made at the gate: the queue writer that now chowns the approval file for the service refuses a file with
more than one hard link, so the chown cannot reach another file; the Windows remedy says to start the administrator-owned
copy from a PowerShell opened with `-NoProfile`, because an elevated shell of the same user otherwise runs that user's
`$PROFILE`. Child-process tests that start the CLI from the checkout now expect the code refusal when the test runner is
elevated (the Windows CI runner is); those flows are covered on Linux and macOS CI and in non-elevated Windows runs.

## Open

R15-3, R15-8, R15-9 and R15-11 are not changed in this round.
