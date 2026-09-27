# R24 findings

Round R24 read the desktop on `fix/pre-launch-attack`. Two high findings and one medium, all in the desktop launcher. Closed for 0.4.0.

| id | severity | description | status |
| --- | --- | --- | --- |
| R24-1 | high | The launcher only stopped children on SIGINT and SIGTERM. SIGHUP, a crash, or an outright kill left the issuer and the body listening on 127.0.0.1 after the `[::1]` forwarders (held by the launcher) were gone. | fixed |
| R24-2 | high | `ensureDesktopDirectory` judged the leaf only. An ancestor another user can replace, or an intermediate link, lets that user swap the state directory for their own after the check. | fixed |
| R24-3 | medium | `--state` accepted a UNC or device path, so the dev token, the issuer key, and the ledger were written where that path's ACL check runs. | fixed |

## Fixes

- R24-1: `stopAll` also runs on SIGHUP (every platform: on Windows Node raises it when the console window is closed), SIGBREAK (Windows), `uncaughtException`, and `unhandledRejection` (then exit 1), and on `process` `exit`. `killTree` is synchronous (`spawnSync` on Windows, `process.kill` elsewhere), so the exit handler can call it. Child stdout and stderr kept for readiness are capped at the last 64 KiB. The launcher sets `VERAX_DESKTOP_PARENT_PID` on the issuer and the body. `watchDesktopParent` (`packages/body/src/desktop-parent.ts`) polls that pid every 2s with `process.kill(pid, 0)` and exits when it is gone; it is a no-op when the variable is unset. The issuer script and `main` both call it. The panel is vite preview and the browser is not this repo: they have no watch. `stopAll` kills that tree when the launcher handles a signal, a crash, or exit. An outright kill of the launcher does not run `stopAll`; the issuer and the body then exit on the poll. Without them the panel has nothing to proxy.
- R24-2: before the leaf check, for a new directory and for an existing one, and for the browser profile the same way, refuse `desktop-dir-refused:<dir>` plus a line naming the ancestor when (a) an intermediate component is a link, or the real path differs from the path as given after `realpathSync.native` (case-insensitive on Windows; 8.3 names expanded on the way; a missing leaf is the real path of the parent plus the leaf name), or (b) an ancestor can be replaced by another user. POSIX uses `posixOthersCanReplace` with the operator's uid judged as the root case, so a directory the operator owns is kept or refused on mode and the sticky bit: a non-sticky 0777 ancestor is refused, a 1777 ancestor is kept. Windows uses `windowsUserCanWrite(..., { ancestor: true })`, the installer's ancestor mask (`ANCESTOR_REPLACE_MASK`: delete-child, WRITE_DAC, WRITE_OWNER, DELETE, GENERIC_ALL). Add-subdirectory (`0x4`) is not in that mask, which is why `C:\` can grant `LC` to Authenticated Users: it does not let another principal move an existing child away. What it does allow, creating a missing intermediate directory first, is caught by a second ancestor check that runs after `mkdir`. DELETE_CHILD (`0x40`) on another SID is refused even when the owner is SYSTEM. A leaf owner or leaf DACL hook that does not also set `windowsAncestorDacl` does not read ancestor ACLs from the machine.
- R24-3: `parseDesktopArgs` on Windows returns `desktop-state-unc` for `\\`, `//`, `\\?\` (including `\\?\UNC\`), and `\\.`. Tests pass `win32` as the platform argument so the check is the Windows one on every host.

## Found at the gate

- The leaf DACL check passed the directory owner as the one principal allowed to write. In an elevated shell a new directory is owned by Administrators, so the operator's own full-control entry counted as someone else and the desktop refused its own state directory (windows-full on e94c1f7). The check now passes the invoking SID; Administrators and SYSTEM were already trusted writers.
- SIGHUP was registered on POSIX only. It is now registered on every platform, with SIGBREAK added on Windows.
- The ancestor check ran before `mkdir` only. A missing intermediate directory another principal creates in that window would be theirs. The check runs again after `mkdir`.
- `killTree` returns for a pid of 0 or 1. A test's fake child had pid 1 and reached `stopAll`; on POSIX `kill(-1)` signalled every process of the test user and ended the whole test run. Tests with fake children now pass a `kill` hook.
- On the gate machine the Windows TEMP folder grants Modify to four foreign SIDs and full control to an AppContainer capability. The desktop refuses a state directory under it, which is the R24-2 rule doing its job. Windows test directories now live under the profile directory, so tests that start the CLI as a child (no hook) measure the real ancestor ACLs.
- Found on the Windows runner after F32: the ancestor walk started one PowerShell per directory, plus one for the leaf owner and one for its DACL, and under the full test load `Get-Acl` hit the 30 s spawn timeout, so the desktop refused its own state directory with "the directory ACL could not be read". The leaf and the ancestors are now read with the installer's batch reader (one PowerShell for all ancestors, one for the leaf), and the leaf owner comes from the same SDDL. A Windows test grants Everyone delete-child on a real parent directory and runs with no ACL hook.
- The UNC check had a branch for `\\?\` and `\\.\` that the `\\` test already covered; it is removed.
- Two tests were corrected: one refused an add-subdirectory DACL for a different reason (no owner in the SDDL), and the parent-watch test exited on the first check, so removing the 2 s poll left it passing.

## Known limits

- On macOS `/tmp` and `/var` are root-owned links, so `--state /tmp/x` is refused as "is a link". A home directory path is not.
- A path refused by the check after `mkdir` leaves the directories that `mkdir` created.
