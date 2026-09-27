# R21 findings

Round R21 read the F28 changes on `fix/pre-launch-attack`. R21-1 is a gap left by F28. Two high findings. One medium.

| id | severity | description | status |
| --- | --- | --- | --- |
| R21-1 | high | Attach mode held `[::1]` on the body port and the panel port, and did not hold the issuer port. | fixed |
| R21-2 | high | The elevated installer's PowerShell loaded modules from the user's Documents folder. | fixed |
| R21-3 | medium | `ensureTokenParent` chowned a root-owned token folder by path. | fixed |

F28 held `[::1]` for the ports `verax desktop` binds, and in attach mode it held `[::1]` on the body port. The panel port is claimed with the other ports this run binds. The issuer port was not. Attach mode still sends the browser to `http://localhost:<issuerPort>`, the panel's issuer URL. Another local user listening on `[::1]:<issuerPort>` received the passkey ceremony on the real origin. The running issuer already holds `127.0.0.1` on that port, so that address is not required to be free.

## Fixes

- R21-1: in attach mode the desktop claims `[::1]` for the issuer port with the same hold used for the body port. A taken port is `desktop-port-busy:issuer:<port>:ipv6`, before any child starts. `127.0.0.1` on the issuer port is left to the running issuer. If the host cannot bind the IPv6 loopback, the desktop continues without that hold, as it does for the body port.
- R21-2: `systemToolEnv("win32")` sets `PSModulePath` to `<system root>\System32\WindowsPowerShell\v1.0\Modules`. PowerShell 5.1 otherwise puts `%USERPROFILE%\Documents\WindowsPowerShell\Modules` first, and `-NoProfile` does not change that list. With this value, the module path PowerShell reports has no entry under the user profile or My Documents. Every PowerShell spawn in the install path, the desktop directory-owner lookup, approve, doctor, and the CLI elevated gate already goes through `systemToolEnv` (`defaultExec` when no env is passed, or an explicit `systemToolEnv` on the plan and on `restrictToOwnerWin32`). The elevated gate's own tools are `net` and `whoami`; they use the same env. No PowerShell spawn was left on the caller's environment.
- R21-3: on POSIX, `ensureTokenParent` opens a root-owned token directory with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`, `fstat`s the descriptor, and requires the same dev/ino as the earlier `lstat`. It then `fchownSync`s that descriptor to the invoking uid and `fchmodSync`s it to `0700`. A symlink swapped in between the lstat and the open is `refusing: <dir> dev/ino mismatch`, and the link target is not changed. The by-path `chown` and `chmod` argv is not run.
