# R17 findings — attacks on the R14–R16 fixes

Round R17 attacked the fixes from R14, R15 and R16. The tree under review was `fix/pre-launch-attack` at `0800665`. No critical findings. Three high, three medium, five low.

| id | severity | fix attacked | status |
| --- | --- | --- | --- |
| R17-1 | high | R14-9, R15-1 | fixed |
| R17-2 | high | R14-9, R15-1 | partly closed in code |
| R17-3 | high | R16-7, R16-8 | fixed |
| R17-4 | medium | R14-8, R15-2 | fixed |
| R17-5 | medium | R15-1 | fixed |
| R17-6 | medium | R14 `mkdirLeaf` | fixed |
| R17-7 | low | R15-4, R16-11 | fixed |
| R17-8 | low | R15-4, R16-11 | fixed |
| R17-9 | low | R15-6, R16-6 | fixed |
| R17-10 | low | R16-10 | fixed |
| R17-11 | low | R16-2 | fixed |

Method: attacks on the R14–R16 fixes. Each row names the fix that was attacked.

## Fixes

- R17-1: the elevated gate runs the installer's Node trust check on `process.execPath`, ancestors included. An untrusted Node is refused with the message `planInstall` already prints (`/opt/verax-node` on Linux and macOS, the all-users nodejs.org installer on Windows). Approve and uninstall text names that Node, or `/usr/bin/node`, and does not use `env node`.
- R17-2: partly closed in code. When elevated, a non-empty `NODE_OPTIONS` or a preload flag still visible on `execArgv` (`--require`, `-r`, `--import`, `--loader`, `--experimental-loader`) is refused. Code which already ran can hide itself by clearing those before this process looks. On Windows a same-user elevated shell still inherits the user's environment and PowerShell profile. The threat model and README say to clear `NODE_OPTIONS` (`Remove-Item Env:NODE_OPTIONS`) and to prefer the panel with a passkey, or a separate administrator account.
- R17-3: each held argument is one line, `"<name>": "<value>"`, with the name JSON-quoted and terminal-control-escaped the same way as the value.
- R17-4: an elevated `approve` refuses a state directory the invoking user can change (`posixOthersCanReplace`, with the service-account owner kept when it is not the invoking user; the Windows ACL check otherwise). The message names that account. A process that is not elevated is unchanged.
- R17-5: the Install section says an account whose every process is elevated (built-in Administrator, `EnableLUA=0`) is refused from a user-writable npm prefix, and points at `%ProgramFiles%\verax-cli`.
- R17-6: `verax init --local --force` keeps an existing issuer directory that the running user owns and rewrites what is in it; a link or a directory owned by someone else is `EEXIST`. The init rollback removes only paths this run created. `mkdirLeaf` stays strict by default, so the installer still refuses a directory that appears between its check and its `mkdir`; `verax install --force` over an existing code or state directory is not changed in this round.
- R17-7: an empty or whitespace-only `--key`, `--effect-key`, `--witness-key` or `--checkpoint-key` file is `verify-key-empty: <flag>`.
- R17-8: a pinned effect, witness or checkpoint key that had no row of that class reports `source: "none"` and the "no … rows" note.
- R17-9: `policyFromSnapshot` compares `loaded.hash` with the requested `policyHash`. A mismatch is `approve-policy-missing` for a spend.
- R17-10: a zero-byte or whitespace-only `checkpoints.jsonl` is `checkpoint-unreadable`. Only a missing file starts a chain. The witness records the last checkpoint hash in `witness-status.jsonl` and the empty file is compared with that hash.
- R17-11: a first argument that starts with `--` and is not `--inventory` (the flag `main()` reads) is `unknown option: <arg>`, exit 64.

Corrections made at the gate: the first version of the R17-6 fix made `mkdirLeaf` accept any existing directory, which
would have let the installer use a directory another user planted in `ProgramData` between the root check and the
`mkdir` (the R3 race); the lenient case is now opt-in for `init --force` and requires the running user's ownership. Tests
that encoded the old prompt, the old policy-snapshot trick (a file named for one hash holding another policy, which
R17-9 now refuses), or a bare `--env-file` that Node itself consumes before the CLI runs were rewritten.
