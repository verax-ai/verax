# R9 findings — independent red team by variant

Independent of R8. R8 had three highs. This round takes each class those rounds already hit and looks for another instance the fix did not touch: `packages/*/src`, `scripts/`, and `.github/workflows/`. Product code was not changed. Tests were not executed (the task forbids commands). Each provable row has an `it` in `tests/attack-r9.test.ts` that asserts the safe behaviour, which the current tree does not implement.

No critical findings. No high findings. Four medium findings. One low finding.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R9-1 | medium | The brain, holding a policy that allows `message.send` | `memory.put` stops at 1 MiB per tenant. `message.send` appends to `outbox.jsonl` with no total. Two 600_000-byte bodies both store. After install, that file is the service account's disk. The per-request HTTP cap does not reset the total. | `packages/body/src/tools/message.ts:42` | `R9-1 a tenant outbox cannot grow without a cap` |
| R9-2 | medium | Whoever already has a system group or a system login named `verax` | The plan sets `createdGroup` because `useradd` has no `-N`. It does not pass `-U`, and it does not record a uid or a gid. Uninstall then deletes any `verax` whose uid is 1–999 with nologin and home `/`, and any `verax` group whose gid is 1–999. A marker that records uid 999 and gid 999 still deletes live uid 480 and live gid 480. Darwin compares the recorded ids. Windows compares the recorded SID. | `packages/body/src/install.ts:1558`, `packages/body/src/install.ts:1568`, `packages/body/src/install.ts:4232`, `packages/body/src/install.ts:4241` | `R9-2 Linux does not claim or delete the verax group without an explicit create and a recorded id` |
| R9-3 | medium | The operator, reading uninstall's report | A tool that exits non-zero and prints nothing is treated as "already gone". `userdel` in that shape still prints `removed: account verax` and uninstall exits 0. The login is still there, and the code directory, including the marker, is already gone. | `packages/body/src/install.ts:4201` | `R9-3 a failed delete with no output is not treated as the account already being gone` |
| R9-4 | medium | A local non-admin who can leave one file in the code tree with a different DACL | The post-install read-back of the code tree is `package.json` only. The service starts `node_modules/@verax-ai/body/dist/cli.js`. `icacls /reset /T /C` continues after a file it could not reset. That entrypoint is not in the list, so its DACL is not read. | `packages/body/src/install.ts:3104` | `R9-4 the code ACL read-back includes the service entrypoint` |
| R9-5 | low | An operator reading doctor on an enforcing host | `init_t` is a warning. A service domain that could not be read is `ok`, with the detail "service domain is unknown". Enforcing was already established. Absence of the label is reported as success. | `packages/body/src/install.ts:2764` | `R9-5 an enforcing host with an unknown service domain is not reported ok` |

## Classes

| class | instances already fixed | other places searched | result |
| --- | --- | --- | --- |
| absence read as safety | NULL DACL (`windowsUserCanWrite`); unsigned effect and unsigned checkpoint (`verify-ledger.ts`, `checkpoints.ts`); missing owner (`sddlOwner` returns null and the object is writable); missing `getenforce` still reads `/sys/fs/selinux/enforce` | `selinuxMode` when both probes fail; `linuxSelinuxCheck` when the domain cannot be read; `toolAlreadyAbsent` on empty output; `serviceAclFiles` for the code tree; `indexStatement` when the index cannot be read; POSIX mode bits without an ACL | R9-3, R9-4, R9-5. A failed `getenforce` plus a failed enforce-file read still means "not present", which is the right answer on a host with no SELinux. The index line already says removed records cannot be checked. POSIX ACLs on a root-owned file were not shown: a non-root caller cannot attach one, and `posixEntryUntrusted` is not injected. |
| a claim recorded before the fact | Linux and macOS markers are written after `useradd` / `dscl -create`. Windows `createdAccount` is after `New-LocalUser`. | The Linux marker's `createdGroup` flag against the `useradd` argv; `rememberCreatedAccount` setting `linuxGroup` whenever `useradd` of `verax` returns 0 without `-N`; Windows SID stamped in `stampAccountSid` only after create | R9-2. The marker is no longer before `useradd`. It still claims the group when `useradd` did not pass `-U` or `--user-group` and no `groupadd` is in the plan. Rollback then `groupdel`s `verax` with no gid check (`install.ts:3238`). |
| trust what the attacker supplies | Effect key is the pinned key or one key for every row, and the trust note says it was not pinned. Token ACE is a SID. `VERAX_INVOKING_HOME` must match getent/dscl. `inputs.confirm` is an environment variable. | `release.yml` `steps.version.outputs.version` inside `run:`; `mcp-registry.yml` version reads; spend arguments; `SUDO_USER` as a chown name after getent has resolved that same name | Not filed. On `workflow_dispatch` the workflow file and the checkout are the same ref, so a caller who can change `package.json` can change the workflow. The confirm input, which is not part of the commit, stays in `env:`. `mcp-registry.yml` reads the version inside the script. |
| names instead of identities | Root ACE and token grant use SIDs. `verax-svc` is `Get-LocalUser` then a SID. Windows uninstall compares `accountSid`. Darwin uninstall compares `accountUid` / `accountGid`. | `linuxUserVerdict`, `linuxGroupVerdict`, `chown verax:verax`, `User=verax`, `stat -c %U` for an existing code or state directory | R9-2. `markerFlags` parses `accountUid` and `accountGid` and `executeUninstall` receives them. The Linux verdicts do not take them. `linuxOwnedByUs` still accepts the owner name `root` or `verax`; a name that is neither is refused, and a pre-existing login named `verax` is still refused before that check. |
| check then act | Root lock is the first Windows op. Private temp refuses a path that already exists. Tarball bytes are hashed again after the copy. | `applyPrivateTemp` between `existsSync` and `mkdirSync`; `applyLockRoot` on `EEXIST`; ancestor ACL versus the object ACL | Not filed. `mkdirSync` on a name that appeared in that window throws, and the install does not keep the directory. `EEXIST` on a new Windows root is a refusal. The ancestor mask still ignores add-file and add-subdirectory on a parent; that is the rule R8 stated, and a sibling file is not the Node binary. |
| platform assumptions | `/opt/verax-node` instead of a user-owned `/usr/local`. PowerShell 5.1 collections are wrapped in `@()`. The batch SDDL reader base64-encodes the path list. System32 PowerShell, not a PS7 module path. | `useradd` versus `USERGROUPS_ENAB`; `selinuxMode`'s `/bin/cat`; `ConvertTo-Json` of one path; `windowsSddlArgv` quoting | R9-2 is this class as well as the name class: without `-U`, whether `useradd` creates the group is `login.defs`, and the marker still says `createdGroup`. `/bin/cat` is only the fallback after `getenforce`. One path in the batch reader is still one JSON object. `windowsSddlArgv` is a single-quoted `-LiteralPath` and is only the lock-root read-back. |
| error path skips the invariant | A failed `useradd` / `dscl` / `New-LocalUser` does not set the rollback flag. Rollback deletes `verax-svc` only after the create script returned 0. | `toolAlreadyAbsent`; `ownerOnly` swallowing `chmod`; `resetOk` when `icacls /reset` fails on an empty temp; `linuxSelinuxCheck` | R9-3. Empty stdout and stderr on a non-zero status is success. `chmod` failure in `ownerOnly` is after `writeFileSync` already passed `mode: 0o600`. An empty private temp treats a failed `/reset` as success because there is no child to reset; the owner and grant results are still required. |
| enumerated deny-lists | Spend text uses one Unicode class, not a list of controls. Root and object ACLs trust SIDs, not English names. | `TERMINAL_CONTROL_CLASS` on the spend fields and on `heldLine`; `SDDL_SID` and `TRUSTED_WRITER_SIDS`; `serviceAclFiles` as a one-file list | R9-4 is the list that names one file and not the entrypoint. The spend class and the SID allow-list were not reopened: an unknown ACE type or an unknown right still fails closed. |

## R9-1 the outbox has no tenant total

**Invariant the memory fix claims.** One tenant cannot store past a fixed cap through the body. The default cap is 1 MiB. The HTTP body cap is one request, not the directory.

**What was tried.** `message.send` twice, same principal, each `text` 600_000 bytes. Each row alone is under 1 MiB. Together they are over it. `memory.put` takes `withMemoryQuotaLock` and sums the tenant directory first. `message.send` only `appendFileSync`s `outbox.jsonl`.

**Expected.** The second call is an error. The outbox file stays within 1 MiB.

**Actual.** Both calls return `isError: false` and `{ queued: true }`. Nothing reads the file size.

**Fix.** The same per-tenant cap, held across the size check and the append. A second send must observe the first row.

## R9-2 the Linux group is a name

**Invariant the account removal claims.** Uninstall and rollback delete `verax` or the `verax` group only when this install created that account, and only that uid and gid.

**What was tried.**

The plan. `linuxAccount.exists` is false, so the plan runs `useradd --system --no-create-home -d / --shell /usr/sbin/nologin verax`. There is no `-U`, no `--user-group`, and no `groupadd`. The marker write that follows sets `createdGroup: true` and does not set `accountUid` or `accountGid`. `useradd` creates the group only when `USERGROUPS_ENAB` is yes. When it is no, `useradd` can return 0 and leave a pre-existing `verax` group untouched. The comment on the marker says the group was created anyway.

The verdict. Darwin's `darwinUserVerdict` and `darwinGroupVerdict` take the ids in the marker. `linuxUserVerdict` and `linuxGroupVerdict` do not take `accountUid` or `accountGid`, even though `markerFlags` parses both and `executeUninstall` has them. A marker with `accountUid: 999` and `accountGid: 999`, a live user `verax:x:480:480::/:/usr/sbin/nologin`, and a live group `verax:x:480:` still takes the remove branch: 480 is in 1–999, the shell is nologin, and the home is `/`.

Rollback. `rememberCreatedAccount` sets `linuxGroup` when `useradd` of `verax` returns 0 and the argv has neither `-N` nor `--no-user-group`. `rollbackCreatedThisRun` then `groupdel`s `verax` and does not call `linuxGroupVerdict`.

On a host where `USERGROUPS_ENAB` is yes, a pre-existing group makes `useradd` fail, the marker is not written, and rollback does not `groupdel`. The delete of a stranger's group is the other setting, plus any later uninstall that trusts the shape.

**Expected.** `useradd` passes `-U` or `--user-group`, or the plan has a `groupadd` of `verax`. Uninstall does not `userdel` or `groupdel` when the live id is not the id in the marker.

**Actual.** The argv has neither flag. Both deletes run.

**Fix.** Pass `-U` (or `groupadd` and then `-g`). Record the uid and the gid the create actually produced. Uninstall and rollback delete only when the live id is that id. A system range, a nologin shell, and home `/` stay necessary and are not sufficient.

## R9-3 empty output means the account is gone

**Invariant the report claims.** `removed:` is a delete that returned 0, or a tool whose text says the object was already absent. A delete that failed is not `removed`, and the process does not exit 0.

**What was tried.** A Linux marker with `createdUser: true` and `createdGroup: false`. `getent passwd verax` is `verax:x:480:480::/:/usr/sbin/nologin`, so the shape check says remove. `userdel` returns status 1 with empty stdout and empty stderr.

**Expected.** Uninstall exits non-zero. The report does not contain `removed: account verax`.

**Actual.** `toolAlreadyAbsent` is true because the trimmed output is empty. `runUninstallTool` returns null. The report says `removed: account verax` and the exit code is 0. The code directory has already been removed, so the marker that said `createdUser` is gone and the login is still there. The next install sees a `verax` it did not record and refuses.

**Fix.** Empty output is not "already absent". Keep the phrases that name a missing object. A non-zero status with no text is a failure.

## R9-4 the entrypoint is not in the ACL list

**Invariant the read-back claims.** After install, the code tree's DACL matches the directory grant, including the file the service executes.

**What was tried.** `serviceAclFiles(root, "code")`. The scheduled task and the systemd unit start `node_modules/@verax-ai/body/dist/cli.js`. The list is `node_modules/@verax-ai/body/package.json` and nothing else. State still lists `key.pem`, `verax.env`, and every file in `keys`.

**Expected.** The returned list includes `node_modules/@verax-ai/body/dist/cli.js`.

**Actual.** It does not. `windowsResetInheritArgs` passes `/C`, so a file `icacls` could not reset is skipped and the walk continues. Doctor's `install-code-acl` file rows are this list.

**Fix.** Include the entrypoint. A file the reset skipped has to be one of the paths the read-back opens.

## R9-5 unknown domain is success

**Invariant the doctor line claims.** On an enforcing host, a service domain other than an entrypoint domain is visible. `init_t` is already a warning.

**What was tried.** `getenforce` prints `Enforcing`. `systemctl show -p MainPID` prints `0`, which `serviceMainPid` rejects, so no label is read.

**Expected.** The level is not `ok`. The detail still says the domain is unknown.

**Actual.** The level is `ok` and the detail is `SELinux is Enforcing; service domain is unknown`.

**Fix.** Unknown is a warning, the same way `init_t` is. Do not report `ok` for a label that was not read.

## Checked and solid

1. **SDDL after R8.** `NO_ACCESS_CONTROL` is a NULL DACL. An empty `D:` or `D:P` is not. A missing `D:` is untrusted. An owner that is not Administrators, SYSTEM, TrustedInstaller, or the service SID keeps implicit `WRITE_DAC` unless a non-inherit-only OWNER RIGHTS ACE says otherwise. `OA` / `XA` / `ZA` are allows. Unknown ACE types and unknown rights fail closed. `IO` does not apply to the object. A deny does not hide a later allow.
2. **Effect and checkpoint binding.** A bound effect still needs the decision's `effectHash`, or the fixed `duplicate-effect` hash, or a `:threw` class whose receipt verifies. The receipt's canonical row has to equal the row on disk, so the class is inside the signature. Checkpoint rows that do not verify are problems. A key carried by the file is the in-ledger case the trust note already names.
3. **Spend text and the approve line.** `TERMINAL_CONTROL_CLASS` is the one class on `payee`, `reference`, and `currency`, and `heldLine` escapes that class. No second field is interpolated raw.
4. **Memory quota.** `withMemoryQuotaLock` covers the readdir and the write. This round did not reopen it. R9-1 is the other writer.
5. **Account create versus the marker.** The Linux marker op is after `useradd`. The macOS marker op is after `dscl -create`. Windows writes `createdAccount` after the account script and stamps `accountSid` from that script's stdout. An existing `verax` login with `createdByUs` false is still refused. R9-2 is the group flag and the id the verdict does not read.
6. **Token principal and home.** The token ACE is a SID. `VERAX_INVOKING_HOME` is kept only when it is the getent or dscl home. `USERNAME` is not an icacls principal.
7. **Workflows.** `inputs.confirm` is compared from the environment in `release.yml` and `mcp-registry.yml`. No `pull_request_target`. Actions that publish are pinned by commit. `pack-smoke.yml` and `install-e2e.yml` interpolate step outcomes and matrix values that the workflow file itself names (`success`, `failure`, `skipped`, `cancelled`, and the matrix list). Those are not a package version. `release.yml` still writes `v="${{ steps.version.outputs.version }}"` inside five `run:` blocks. That version is the `package.json` of the ref being checked out, and the workflow file of a `workflow_dispatch` run is that same ref, so it was not given a second row.
8. **Private temp and the root lock.** A temp path that already exists is refused. A new Windows root that already exists is refused. npm's environment is not the caller's, and the registry is `https://registry.npmjs.org/`.
9. **SELinux label versus the trust check.** `posixEntryUntrusted` still runs before `linuxSelinuxNodeRefusal`. `bin_t` and `usr_t` remain the only entrypoint types. A missing `getenforce` still reads the enforce file. R9-5 is the doctor line when that mode is enforcing and the domain was not read.
