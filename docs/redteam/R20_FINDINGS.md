# R20 findings

Round R20 read the F27 changes (desktop, proxy, install, cli) in council mode. The tree under review was `fix/pre-launch-attack` at `de516d2`. Two high findings. One medium.

| id | severity | description | status |
| --- | --- | --- | --- |
| R20-1 | high | `verax desktop` hands the browser `http://localhost:<port>` after F27, and bound those ports only on 127.0.0.1. | fixed |
| R20-2 | high | Install and uninstall took `ProgramData` and `ProgramFiles` from the shell. | fixed |
| R20-3 | medium | `successText` put the token path inside a PowerShell single-quoted string with `'` left as itself. | fixed |

R20-1 came from the F27 change to localhost origins. Before that change the browser origins were `http://127.0.0.1:<port>`, which does not match a WebAuthn RP ID of `localhost`, so F27 switched the page, the issuer URL, the redirect, and the body audience to `http://localhost:<port>`. Chromium resolves `localhost` to `[::1]` first. Another local user listening on `[::1]:<port>` received the page. The origin was still `http://localhost:<port>`, so a passkey ceremony run there was valid for the real issuer and could be relayed.

## Fixes

- R20-1: for the issuer, body, and panel ports, the desktop holds `[::1]:<port>` and pipes each connection to `127.0.0.1:<port>`. `desktopPortFree` checks `[::1]` as well. A taken `[::1]` port is `desktop-port-busy:<name>:<port>:ipv6`, before any child starts. If the host cannot bind the IPv6 loopback (`EADDRNOTAVAIL` or `EAFNOSUPPORT`), the desktop continues without that hold. The forwarders stop with the children. Attach mode applies the same `[::1]` check to the body port: a listener that is not the forwarder this process opened is a refusal.
- R20-2: on Windows the installer and uninstaller read `ProgramFilesDir` from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` and `ProgramData` from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, through System32 PowerShell (already in `WIN32_TOOLS`). The roots are read without expansion and the drive comes from the machine's SystemRoot. `%SystemDrive%` is the only variable expanded; any other unexpanded variable is a refusal. A shell value that differs is `refusing: ProgramData in this shell is <x>, the machine says <y>` (and the same for `ProgramFiles`). The root and each ancestor must not be a junction or symlink, and the path on disk must be the path as given. Uninstall uses those same roots and refuses, without following, when `Verax` or a child to be removed is a junction or symlink. `windowsSystemRoot` still returns only `C:\Windows` (R13-2); `SystemRoot` and `windir` are not taken as a different directory.
- R20-3: inside the PowerShell single-quoted token path, `'` is written as `''`. Inside the POSIX single-quoted path, `'` is written as `'\''`.
