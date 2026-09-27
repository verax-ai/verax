# R23 findings

Round R23 read the desktop on `fix/pre-launch-attack`. Two high findings in `packages/body/src/desktop.ts`. Both are closed for 0.4.0.

| id | severity | description | status |
| --- | --- | --- | --- |
| R23-1 | high | Attach mode joined a body it did not supervise. If that body died, another local user could bind `127.0.0.1:<bodyPort>` and the panel proxy would hand them the operator session. | closed for 0.4.0 by removing attach |
| R23-2 | high | An existing state directory that others could write was tightened and then trusted. A planted `dev-issuer` link could supply `jwks.json` as `VERAX_JWKS_PIN`. | fixed |

## Fixes

- R23-1: 0.4.0 does not attach. When `desktopMode` returns `attach` (a live lock names `--body-port` and that pid is the listener on `127.0.0.1`), `runDesktop` exits 1 with `desktop-body-running:<bodyPort>` and one line telling the operator to use the panel of the desktop that started that body, or to stop it first. `verax unlock` is for a dead lock only. Nothing is spawned and no `[::1]` port is claimed. `desktopMode` still returns `attach` so callers can tell that case from `desktop-body-locked` and from a dead lock, which stays `spawn`. Attach is planned to return in a later release, with supervision of the attached body.
- R23-2: an existing directory is refused with `desktop-dir-refused:<dir>` and a line that it was writable by others and to use a new directory, when POSIX `mode & 0o022` is non-zero, or on Windows when `windowsUserCanWrite` reports a DACL write for a SID other than the owner (passed as `svcSid`). That helper is the installer's. It treats Administrators, SYSTEM, and TrustedInstaller as not an other writer, and its write mask includes write, append, delete-child, WRITE_DAC, WRITE_OWNER, plus write-EA, write-attributes, DELETE, GENERIC_ALL, and GENERIC_WRITE. The directory is not chmod'd and `restrict` is not applied. A directory with only owner access keeps the previous path, including a chmod of remaining group or other read/execute bits to `0700`. `dev-issuer` inside the directory is also refused when `lstat` shows a symlink or junction. A failed SDDL read is refused with a line that the ACL could not be read.
