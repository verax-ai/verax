# R22 findings

Round R22 read the F29 changes on `fix/pre-launch-attack`. R22-1 is a gap left by F29. One high finding. Two medium.

| id | severity | description | status |
| --- | --- | --- | --- |
| R22-1 | high | Attach mode held `[::1]` on `--issuer-port` instead of the issuer named by the body's protected-resource metadata. | fixed |
| R22-2 | medium | Doctor said the evidence copy and the ledger index were ok when the source ledger was corrupt, shorter than its copy, or a closed piece's lines disagreed with the manifest. | fixed |
| R22-3 | medium | A heartbeat time in the future read as live. | fixed |

`verax doctor` is a health check. `verax verify` is the verifier.

F29 claimed `[::1]` on `opts.issuerPort` while attaching. The panel takes its issuer from `authorization_servers[0]` in the body's `/.well-known/oauth-protected-resource` document. When that issuer is `http://localhost:<P>` and P is not `--issuer-port`, `[::1]:<P>` stayed open, which is the R20-1 hole, and nothing checked that a listener was on `127.0.0.1:<P>`.

## Fixes

- R22-1: in attach mode, before any port is claimed, the desktop reads that document from `http://127.0.0.1:<bodyPort>` with a short timeout. A loopback issuer (`localhost`, `127.0.0.1`, or `[::1]`) must already have a 127.0.0.1 listener or the desktop stops with `desktop-attach-issuer-down:<P>`. This run then holds `[::1]:<P>` (`desktop-port-busy:issuer:<P>:ipv6` when that port is taken). P comes from the metadata, not from `--issuer-port`. An issuer on another host is not claimed. Metadata that cannot be read, or that has no `authorization_servers[0]`, is `desktop-attach-issuer-unknown`.
- R22-2: per piece, a corrupt source decisions or effects file fails `evidence-copy` and names the piece and the file (`source ... is corrupt`). A copy with more lines than its source fails `evidence-copy` (`source is shorter than its evidence copy on piece <id>`). A closed piece whose decision lines on disk are not the manifest's `n` fails `ledger-index` (`piece <id> has <lines> decision line(s), the manifest says <n>`). The previous messages for a corrupt copy, a short copy, and an index that does not cover the manifest count stay as they were.
- R22-3: `atMs` must be finite and not later than now plus 60 seconds. Otherwise `heartbeat` fails with `heartbeat time is in the future`. A pulse inside that skew, a live pulse, and a silent pulse keep their existing results.
