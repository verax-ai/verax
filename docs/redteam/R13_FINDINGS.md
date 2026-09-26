# R13 findings — files no round had read, and the R10–R12 fixes

Round R13 ran against d50bcc5 with the same multi-model, file-by-file method as R12 (DeepSeek, OpenAI Codex, xAI Grok
through Cursor, Groq for small files; the threat model as context). Ten files: six that no earlier round had read on its
own (`ledger.ts`, `desktop.ts`, the panel's `session.ts`, `App.tsx`, `BlackBox.tsx`, and `install.ts`) and four that the
R10–R12 fixes had just changed (`approvals.ts`, `proxy.ts`, `verify-ledger.ts`, `server.ts`). Codex ran out of credits
after `install.ts`, so the last four files were read without it.

Two high findings. One medium finding. The policy gate, proxy, verifier, ledger and approvals code produced no high or
critical finding that held after the gate; two of the strongest claims there were measured and did not reproduce (a
retried `_ref` after rotation and an index rebuild does not run again; a manifest with an empty piece list is refused).

| id | severity | attacker | description | file | measured |
| --- | --- | --- | --- | --- | --- |
| R13-1 | high | Another local user while `verax desktop` starts | Desktop did not check that its ports were free, took "something listens on the port" as ready, fetched the issuer's JWKS from that port, read the agent token from a file an earlier run could have left, and missed a child that exited before supervision began. Whoever bound the issuer port first had the body pin their keys; whoever bound the panel port received the operator's passkey session at the registered redirect URI. | `packages/body/src/desktop.ts` | read at the gate; all four models reported it independently |
| R13-2 | high | The agent, before an administrator runs `verax install` | The elevated Windows installer took the Windows directory from `SystemRoot` and accepted any absolute path under a drive root, including `C:\Windows\..\Users\x`, then ran system tools from `<that>\System32`. Whether a user-level variable reaches the elevated process was not measured. | `packages/body/src/install.ts` | read at the gate |
| R13-3 | medium | The agent | The installer accepted any `200` on `/healthz` as the service, so a listener placed on the port first made the install report success while the service could not bind. | `packages/body/src/install.ts` | read at the gate |

## Fixes

- R13-1: desktop proves each port is free by binding it before spawning; readiness comes from the child's own
  "listening" line; the JWKS is pinned from a file the issuer writes in the state directory on this start (no network
  fetch); the stale agent token and JWKS file are removed before the issuer starts; exit watchers are attached right
  after spawn.
- R13-2: the Windows directory must be exactly `C:\Windows` (any other drive letter could be a data drive where a user
  can create `\Windows\System32`, and the trust check itself runs PowerShell from there). System32 and every tool the
  installer runs pass the same administrator-only DACL check as `node.exe`, ancestors included. `ProgramData` and
  `Program Files` are judged by the ancestor rule, because stock `ProgramData` lets users create folders.
- R13-3: the installer refuses a port that is already taken, writes a nonce into the service's state directory before
  start, and accepts `/healthz` only when it returns that nonce.

Two corrections were made at the gate: the first version refused stock `C:\ProgramData` (checked as an object rather
than as an ancestor), which would have stopped every real Windows install, and it accepted `X:\Windows` on any drive.
Both are pinned by tests.

Known limit: Windows installed anywhere other than `C:\Windows` is refused by the installer.
