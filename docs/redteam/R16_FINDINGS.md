# R16 findings — file-by-file review of the F23–F24 changes

Round R16 read the files F23 and F24 changed, one file at a time, in council mode. The tree under review was `fix/pre-launch-attack`. Two high findings, eleven medium. R16-1 and R16-11 were introduced by the R15 fixes (F24): R16-1 by the `runCli` refactor that returned after `main()`, and R16-11 by the per-row key selection that let a pinned effect key cover no `same-org` row.

| id | severity | description | status |
| --- | --- | --- | --- |
| R16-1 | high (function) | `verax` with no command returned as soon as it was listening, so the process exited. | fixed |
| R16-2 | medium | An unknown first argument fell through to serve. | fixed |
| R16-3 | medium | The `VERAX_*` clean-up before `--env-file` compared names with case sensitivity. | fixed |
| R16-4 | medium | Elevated `demo --with-conarium` fetched and ran code with npx. | fixed |
| R16-5 | medium | A spend whose policy could not be loaded was refused only when elevated. | fixed |
| R16-6 | medium | An approve that was not elevated used `VERAX_POLICY_FILE` without comparing its hash to the defer. | fixed |
| R16-7 | medium | The approval line escaped `=` only when a control character was present, so a reference could look like a second field. | fixed |
| R16-8 | medium | A non-spend approval hid its arguments and accepted Enter; a spend amount that was not an integer minor-unit amount was accepted the same way. | fixed |
| R16-9 | medium | `requestWitnessCheckpoint` accepted any `coseHex` without checking `listen.publicKeyPem`. | fixed |
| R16-10 | medium | `lastCheckpointHash` turned a checkpoint file that could not be parsed into a new chain. | fixed |
| R16-11 | high | A pinned `--effect-key` with an unpinned witness key verified a ledger whose rows had been marked `same-org`. | fixed |
| R16-12 | medium | On Windows an existing desktop state directory was not checked against the invoking SID. | fixed |
| R16-13 | medium | SDDL masks `KA`, `KR`, `KW` and `KX` were read as no rights. | fixed |

## Fixes

- R16-1: the no-command path waits the same way `serve` does, after `main()` returns.
- R16-2: a first argument that is not a command and does not start with `--` prints `unknown command: <arg>` and the usage, and exits 64. No arguments still serve. `--env-file` and `--log-file` without a command still reach `main()`, which does not read those flags.
- R16-3: names are compared with `toUpperCase().startsWith("VERAX_")` on the object passed to the clean-up.
- R16-4: an elevated `demo --with-conarium` exits 78 with `refusing: demo --with-conarium fetches and runs code with npx; run it from a terminal that is not elevated`.
- R16-5: a spend whose policy cannot be loaded is `approve-policy-missing` whether or not the process is elevated.
- R16-6: when not elevated, `VERAX_POLICY_FILE` is used only when `loadPolicy`’s hash equals the defer’s `policyHash`; otherwise the snapshot is used.
- R16-7: each held field is its own line, `name: "<JSON-escaped value>"`.
- R16-8: a non-spend approval shows its arguments the same way and requires `yes`. A spend whose amount is not an integer minor-unit amount is `approve-amount-unreadable`.
- R16-9: a checkpoint answer is checked against `listen.publicKeyPem`. A mismatch writes no checkpoint and appends `witness-status.jsonl` with reason `witness-key-mismatch`.
- R16-10: a checkpoint file that exists and cannot be parsed stops checkpointing with reason `checkpoint-unreadable`. A missing file is still the start of the chain.
- R16-11: `--effect-key` pinned with any `same-org` row requires `--witness-key`, and `--witness-key` pinned with any `self` row requires `--effect-key`. Otherwise `ok` is false and the problem names that rule. Both pins together verify as before.
- R16-12: on Windows an existing directory is refused with `desktop-dir-refused:<dir>` unless `directoryOwnerSid` equals the invoking SID. The lookup is injectable.
- R16-13: `KA` is `0xF003F`, `KR` is `0x20019`, `KW` is `0x20006`, `KX` is `0x20019`. An unknown two-letter alias is not zero rights; callers treat it as write.

Corrections made at the gate: the new one-field-per-line prompt quoted values with `JSON.stringify`, which leaves
U+0085, U+FEFF, U+2028 and U+2029 unescaped; the R6-1 guard caught it, and every terminal-control code point is written as
a `\u` escape again. Two new tests did not reach the code they named (a same-day spend is counted at the request, so the
second spend never deferred) and were rewritten across a UTC day boundary. Child-process tests that start this checkout's
CLI skip on an elevated runner, where the CLI refuses that code before the command.
