# R8 findings — independent red team

Independent of R7. R7 had one high. This round attacks the surface added since that pass (SDDL by SID, the batch reader, the SELinux gate, account removal, the `/opt/verax-node` remedy, pack-smoke and the platform report), then one more pass over the rest of the product. Product code was not changed. Tests were not executed (the task forbids commands). Each provable row has an `it` in `tests/attack-r8.test.ts` that asserts the safe behaviour, which the current tree does not implement.

No critical findings. Three high findings. One low finding.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R8-1 | high | A local non-admin who owns a directory or a file | `D:NO_ACCESS_CONTROL` is a NULL DACL. Windows grants everyone full control. The parser sees no ACEs and reports admin-only. `planInstall` accepts that string as the Verax root and as the Node binary. | `packages/body/src/install.ts:759`, `packages/body/src/install.ts:941` | `R8-1 a NULL DACL is refused and an empty DACL is not` |
| R8-2 | high | A local non-admin who owns the Node binary or one of its ancestors | With no OWNER RIGHTS ACE, the owner keeps implicit `WRITE_DAC` (`0x40000`), which this check already counts as changing the object. The owner SID is never read. An admin-only allow list on a user-owned file is reported admin-only, and `planInstall` runs that Node. | `packages/body/src/install.ts:753`, `packages/body/src/install.ts:941` | `R8-2 a non-admin owner without an OWNER RIGHTS ACE can still change the object` |
| R8-3 | high | Whoever already has a login or a group named `verax`, or a macOS account named `_verax` | `install.json` records `createdUser` and `createdGroup` before `useradd` or `dscl -create` returns. A failed create does not clear that claim when the Linux code directory already existed, or on macOS where the marker sits outside the code directory. Uninstall then `userdel` / `groupdel` / `dscl -delete` an account this run did not create. | `packages/body/src/install.ts:1507`, `packages/body/src/install.ts:1526`, `packages/body/src/install.ts:3110` | `R8-3 the install marker does not claim an account before that account is created` |
| R8-4 | low | An enforcing SELinux host whose `getenforce` binary is absent | A missing or failing `getenforce` is treated as "no SELinux". The label check does not run. A root-owned `lib_t` Node is installed. The trust check still refuses a user-writable file. | `packages/body/src/install.ts:2581`, `packages/body/src/install.ts:2639` | `R8-4 a missing getenforce still refuses a non-entrypoint label when the kernel is enforcing` |

## R8-1 NULL DACL

**Invariant the check claims.** `windowsUserCanWrite` is true when a principal other than Administrators, SYSTEM, or TrustedInstaller can change the object. Text that is not a real DACL is untrusted.

**What was tried.** The SDDL Windows emits for a NULL DACL, which the owner of a file can set because the owner holds `WRITE_DAC`:

`O:BAG:SYD:NO_ACCESS_CONTROL`

The same string in lower case, and with a space after `D:`. `daclBody` finds `D:`, then `aceInners` finds no parentheses, so the DACL is an empty allow list. An empty protected DACL (`O:BAG:SYD:P`) was kept beside it: that one denies everyone and must stay closed. A SACL with no `D:` section (`O:BAG:SYS:AU`) has no DACL at all, which is the same NULL DACL in the security descriptor, and that string already fails closed.

**Expected.** `windowsUserCanWrite` is true for `NO_ACCESS_CONTROL`, on the object and on an ancestor. `planInstall` refuses it as the root and as `nodeIcacls`. `O:BAG:SYD:P` stays false.

**Actual.** `windowsUserCanWrite` is false. Both plans return `ok: true`.

**Fix.** Before treating an empty ACE list as "nobody can write", honour the `NO_ACCESS_CONTROL` control flag as a NULL DACL. A DACL section that is absent stays untrusted. An empty DACL that is present and is not `NO_ACCESS_CONTROL` stays a deny-all.

## R8-2 implicit owner WRITE_DAC

**Invariant the check claims.** The same write mask the ACE walker uses (`WRITE_DAC` is in both `OBJECT_WRITE_MASK` and `ANCESTOR_REPLACE_MASK`) decides whether a non-admin can change the object.

**What was tried.** A file a standard user creates, then locks to Administrators and SYSTEM while remaining the owner. Windows prints:

`O:S-1-5-21-100-200-300-1001G:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)`

There is no `OW` ACE. The owner's implicit rights are `READ_CONTROL | WRITE_DAC`. `WRITE_DAC` is enough to put a write ACE back and replace the bytes. The same SDDL with an `OW` ACE of `GR` was kept beside it: that ACE replaces the implicit grant, and read is not a write. An Administrators owner with the same allow list was kept as the closed case.

**Expected.** The user-owned string is writable for the object and for an ancestor. `planInstall` refuses it as `nodeIcacls`. The Administrators owner and the `OW`+`GR` string stay not writable.

**Actual.** All three strings are not writable. The plan returns `ok: true`.

**Fix.** Read the owner with `sddlOwner`. When the DACL has no `OW` ACE and the owner is not Administrators, SYSTEM, or TrustedInstaller, the object is writable. An `OW` ACE suppresses the implicit grant; only that ACE's rights count, and inherit-only still does not apply to the object.

## R8-3 account removal follows a marker written too early

**Invariant the removal claims.** Uninstall and rollback delete `verax`, the `verax` group, or `_verax` only when this install created that account.

**What was tried.**

Linux. `planInstall` with `linuxAccount.exists === false` writes `/opt/verax/install.json` with `createdUser: true` and `createdGroup: true`, and the next op is `useradd`. `useradd` is what creates the login and, unless `-N` is passed, the group. Execute records `created.linuxUser` only after `useradd` returns 0, and rollback deletes the code directory only when this run's `mkdir` created it. A code directory that already existed (a repair, a root-owned leftover) is left in place, marker included. `useradd` then fails because the group `verax` already exists, or because a `verax` login appeared between `id` and `useradd`. Rollback does not `userdel`. The marker still says both flags. `runUninstall` reads the marker and runs `userdel verax` and `groupdel verax`.

A fresh Linux install, where this run created `/opt/verax` and `useradd` fails, still removes that directory in `rollbackCreatedThisRun`. That path does not keep the marker. The leak is the directory that was already there.

macOS. The marker is `/Library/Verax/install.json`, which is not under `/Library/Verax/code`. The plan writes `createdUser: true` before `dscl -create /Users/_verax`. Rollback removes the code directory, the state directory, and an account whose `dscl -create` returned 0. It does not remove the marker. A `dscl -create` that fails because `_verax` appeared after `id -u` leaves `created.darwinUser` false, so rollback does not delete the user, and uninstall does, because the marker says `createdUser`.

Windows writes `createdAccount: true` after `New-LocalUser`, and rollback calls `net user verax-svc /delete` only when that script returned 0. A failed create does not delete a stranger. A failure after the marker still deletes the account this run created and does not delete `install.json`. A `verax-svc` created by someone else before the next install is then `createdByUs`. That window is the same class and is not a separate row: the plan itself does not claim the account before the create script.

**Expected.** The marker write that sets `createdUser`, `createdGroup`, or `createdAccount` is ordered after the create command, or it does not set those flags. A failed create leaves no claim for uninstall to honour.

**Actual.** On Linux the marker op is before `useradd` and both flags are true. On macOS the marker op is before `dscl -create /Users/_verax` and `createdUser` is true.

**Fix.** Write the marker, or set `createdUser` / `createdGroup` / `createdAccount`, only after the create command returns 0. On rollback, delete the marker when the account is removed or the create did not happen. Uninstall keeps trusting the marker.

## R8-4 getenforce missing

**Invariant the gate claims.** When SELinux is enforcing, install refuses a Node whose type is not `bin_t` or `usr_t`.

**What was tried.** `getenforce` exits 127. The kernel enforce flag is `1` and `stat -c %C` on the Node prints `lib_t`. `selinuxMode` maps any non-zero status to "no SELinux", and `linuxSelinuxNodeRefusal` returns null.

**Expected.** The refusal names `lib_t`. A probe of `/sys/fs/selinux/enforce` through the same exec is enough to see mode 1.

**Actual.** The function returns null. Doctor's `linuxSelinuxCheck` would say "SELinux is not present".

**Fix.** A missing `getenforce` is not Disabled. Read the enforce flag. When it is `1`, run the label check. Permissive and Disabled stay unchecked. This does not by itself let a user replace the binary; `posixEntryUntrusted` still runs first.

## Checked and solid

1. **SDDL allow, deny, and inherit.** `OA` / `XA` / `ZA` are allows, so a conditional ACE is treated as maybe true. `OD` / `XD` are denies and grant nothing; a deny does not hide a later allow, so the walker fails closed. `IO` does not apply to the object. `AU` / `AL` / `ML` and the other SACL types in a DACL are ignored. An unknown ACE type or an unknown right fails closed. A SID with an extra dash (`S-1-5-32-544-`) or a leading zero (`S-1-5-32-0544`) is not the Administrators SID in the trusted set, so a write ACE on it is refused. `CO` and `CG` are not trusted writers. `BA`, `SY`, and the TrustedInstaller SID still are.
2. **Conditional text.** `aceInners` and `aceFields` track parentheses and keep a condition as one field. A `)` or an `S:` inside a quoted condition either fails the ACE closed (unclosed `(`) or still leaves the account SID in field 6. No shape turned a Users write into an Administrators-only DACL while remaining a string Windows would grant.
3. **Batch SDDL reader.** `windowsSddlBatchArgv` puts the path list in base64 inside one single-quoted PowerShell string. The alphabet has no quote, `$`, or backtick, so a path does not become script. `Get-Acl -LiteralPath` takes the decoded string. `parseSddlBatch` looks up each requested path on the parsed object; a missing key is status 1, which the trust walk refuses. Two paths that differ only by case collapse in a PowerShell hashtable, and on NTFS they are the same file, so one path cannot borrow another's admin SDDL. A command line that is too long fails the process, and every path then fails closed.
4. **SELinux label versus the trust check.** `runInstallBody` runs `posixEntryUntrusted` on the resolved Node and its ancestors before `linuxSelinuxNodeRefusal`. A `bin_t` label on a user-writable file is still refused. `resolveTrustPath` walks the symlink chain before `stat -c %C`. A label change after the check, on a root-owned not-group-writable file, needs root. `bin_t` and `usr_t` remain the only entrypoint types.
5. **`/opt/verax-node`.** The remedy hard-codes that directory and tells the operator to `chown` it to root and clear group and other write. The trust walk does not trust the path because it is under `/opt`. `ancestry` plus `posixEntryUntrusted` refuses a path whose own mode is group or other writable or whose owner is not uid 0, including `/opt` itself when a system gives that directory to a user. The same check refuses a user-owned `/usr/local`.
6. **Account races that do not delete.** `rememberCreatedAccount` runs only after the tool returns 0. A failed `useradd`, `dscl -create`, or `New-LocalUser` does not set the rollback flag, so rollback does not delete a login that appeared and made the create fail. The hole is the marker that was written first (R8-3), not the rollback flag.
7. **Windows `net user /delete`.** The account script is earlier in the plan than `install.json`. Rollback deletes `verax-svc` only when that script succeeded. It does not delete an account the script failed to create.
8. **Pack-smoke and the platform report.** `packages/body/package.json` `files` is `dist` only. `scripts/pack-smoke.ts` and `scripts/platform-report.ts` are not in the published package. `taskkill` in the smoke script and in `desktop.ts` is the supported way the product stops a process tree; it is not a new listener. `resultOf` maps only the conclusion `success` to a success row; `skipped`, `cancelled`, and `failure` are failed. `claimsForJob` keeps the Windows plant and race claims off Linux, macOS, and pack-smoke. Job names in the workflows match the platforms they run on (`ubuntu` to Linux, `macos-13` and `macos-15-intel` to x64, other macOS to arm64). The evidence steps mark a skipped pack-smoke outcome as not success. `docs/PLATFORMS.md` is not in the tree; the generator refuses a row with no run URL.
9. **R1–R7 boundaries opened again and not refiled.** Effect binding, checkpoint signatures, spend control characters, the memory cap's missing lock (still R7-2), the English-only root ACE list (still the R7 fix, and R8-1 is the NULL DACL beside it), token principal from the SID, an existing `verax` login refused when the marker does not say `createdUser`, and npm's private temp. No second hole showed in those paths.
