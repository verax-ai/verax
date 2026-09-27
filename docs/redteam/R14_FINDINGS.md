# R14 findings — the R13 fixes and the files around them, with a fifth reader

Round R14 ran against 830496d with the multi-model, file-by-file method of R12 and R13 (DeepSeek, OpenAI Codex, xAI Grok
through Cursor, Gemini, and Anthropic's Claude Fable as a fifth reader; the threat model as context). Seven files:
`approvals.ts`, `proxy.ts`, `verify-ledger.ts`, `server.ts`, `install.ts`, `desktop.ts` and `scripts/dev-issuer.mjs`.
Codex read the first three; for the other four its place was taken by OpenAI GPT-5.6 through Cursor. On `dev-issuer.mjs`
two readers failed to answer, so that file had three.

One critical finding and one high finding, both in the elevated installer. Seven medium findings. `server.ts` and
`dev-issuer.mjs` produced nothing above low that held after the gate. The most repeated claim in `approvals.ts`
(a string or negative `amountMinor` skipping the daily cap) does not hold: the policy refuses such a request before it can
be held.

| id | severity | attacker | description | file | measured |
| --- | --- | --- | --- | --- | --- |
| R14-8 | critical | The agent, before or during an elevated `verax install` on Linux or macOS | The installer, as root, ran `chown <user>:` and `chmod` on `~/.verax` and `~/.verax/agent.token`, and wrote the token there. The user owns `~`, so the agent can replace `~/.verax` with a symbolic link at any time; `chown` and `chmod` follow a link given on the command line, and the root write follows a link at the file. A link to `/etc` hands `/etc` to the user. On Windows the elevated install wrote and changed the ACL of the token file in the profile, the same class where unprivileged links are available. | `packages/body/src/install.ts`, `packages/body/src/init-local.ts` | read at the gate; two readers reported the same lines. Not run end to end. |
| R14-9 | high | The agent, between two elevated commands | The README told the operator to run `verax install` and `verax approve` elevated. On Windows the default global npm prefix is under the user's profile and the user has full control of it (measured on a Windows 11 machine), so the agent can change the `verax` JavaScript and the next elevated command runs it as Administrator. The installer already refused a Node the account can rewrite, but not its own code. | `packages/body/src/install.ts`, `approve-cli.ts`, `README.md` | the npm prefix ACL was measured; one reader |
| R14-3 | medium | The agent | An approved retry was checked against the `_inputs` it carried, not the ones the operator approved: `requestHash` leaves `_inputs` out, so a retry with different inputs, or none, ran the approved arguments after the approved evidence had expired. | `packages/proxy/src/proxy.ts` | four readers; read at the gate |
| R14-10 | medium | Another local user, `verax desktop` with a local body on another port | Attach mode trusted any `200` on `/healthz` at the port it was given while a live process held the lock; the lock does not record the body's port. | `packages/body/src/desktop.ts` | five readers; read at the gate. |
| R14-11 | medium | Another local user | `verax desktop` created the state directory and the browser profile with default permissions. | `packages/body/src/desktop.ts` | three readers. |
| R14-5 | medium | Someone who hands over a ledger copy | `verax verify` skipped a decisions or effects piece that the manifest names and the disk lacks, without saying so. | `packages/proxy/src/verify-ledger.ts` | four readers |
| R14-1 | medium | Operator error | A held spend whose policy rule was removed or renamed was approved with no daily cap. | `packages/proxy/src/approvals.ts` | three readers |
| R14-2 | medium | Crash or I/O failure | The daily cap counted the approvals file, not the ledger: an allow written before a failed status update did not count toward later approvals. | `packages/proxy/src/approvals.ts` | two readers |
| R14-4 | low | Operator timing | The halt flag was read before the admission queue, so a call waiting in the queue ran after a halt. | `packages/proxy/src/proxy.ts` | three readers |
| R14-7 | low | Someone who hands over a ledger copy | Copies of one signed `duplicate-effect` row each counted as bound. | `packages/proxy/src/verify-ledger.ts` | one reader |

## Fixes

- R14-8: no elevated process writes, chowns, chmods or changes the ACL of a path under the user's home. On Linux and
  macOS the token is written by a child process running with the invoking user's uid and gid (checked against
  `SUDO_UID`/`SUDO_GID` with `id`; uid 0 is refused), which refuses a linked or foreign `~/.verax` and creates the file
  with `wx` and mode 0600 from stdin. On Windows the token lives in `%ProgramData%\Verax\agent-token\<SID>\agent.token`,
  owned by Administrators, readable by the invoking SID.
- R14-9: elevated `install`, `uninstall` and `approve` check the directories of the running package and its
  `@verax-ai/*` dependencies with the same trust check as `node.exe` before doing anything else, and refuse code the user
  can change, or code whose directory cannot be found. The README and the CI install jobs install the CLI into an
  administrator-owned prefix (`%ProgramFiles%\verax-cli`, `/opt/verax-cli`) and run it from there.
- Gate (install-root ancestors): before it creates anything, a Linux or macOS install plan checks every ancestor of the
  code root and the state root, and also the directory that holds the systemd unit and `/Library/LaunchDaemons`. Each of
  those directories must be owned by uid 0 and must not be group- or other-writable, unless the sticky bit is set (mode
  1777): only that directory's owner can rename an entry. Otherwise the plan exits with the config code and
  `refusing: <path> can be changed by other users (owner uid <n>, mode <octal>); the service code under it could be replaced`.
  The elevated CLI code check uses the same rule for its ancestors, so a sticky ancestor is accepted there too. Uninstall
  does not run this check.
- R14-3: an approved retry checks validity against the inputs bound to the allow record; a retry that declares different
  inputs is a signed `inputs-changed` deny.
- R14-4: the halt flag is read again inside the admission queue.
- R14-1: a spend whose rule is gone is refused with `rule-missing`.
- R14-2: the approvals row is marked approved right after the allow record is written, and the cap also counts a pending
  row the ledger already resolved as allow.
- R14-5: a missing piece named by the manifest is `missing piece: <path>`.
- R14-7: a repeated signed `duplicate-effect` row is named and counted once.
- R14-10: the body writes `port` into `ledger.lock` once it is listening. `verax desktop` joins that body only when the lock's port is the `--body-port` it was given and the process listening on 127.0.0.1 at that port is the lock's pid (`netstat -ano`, `ss`, or `lsof` through the install tool path). Anything else is `desktop-body-locked:<pid>:<port or unknown>` and exits 1. A lock with no port is that stop until the body is started again.
- R14-11: the state directory and the browser profile are created mode 0700. On POSIX an existing directory with group or other bits is chmod 0700; a symbolic link or another uid is refused. On Windows both directories get an owner, Administrators and SYSTEM ACL whose grants are inheritable, so files already in the state directory keep their access.
- A checkpoint chain check that throws is now named as a problem; the dependency does not throw for any input the
  verifier accepts today, so this has no test.

Corrections made at the gate: the tests for the admission-queue halt and the ledger-counted spend did not reach the code
they named and were rewritten; the service-account ACL check after `icacls` treated the new token folder's
Administrators and user grants as service grants and is now limited to the service's own roots; a refusal when
`ProfileImagePath` cannot be read was removed, because the token no longer lives in the profile; the remedy text and the
README pointed at the user's own `verax` (`$(which verax)`) and used `%ProgramFiles%`, which PowerShell does not expand. After the first push, CI caught three more: `@verax-ai/body` and `@verax-ai/proxy` imported `@cedulon`
packages they did not list, so the CLI installed on its own did not start (a test now compares each package's run-time
imports with its dependencies); the code check resolved dependencies through `package.json`, which the exports map does not
expose, and then judged a path that was not on disk, so it refused a correct root-owned install; and on Windows it started
one PowerShell per path, which made an elevated `approve` take about a minute. Dependencies are now resolved through their
entry point, paths not on disk are left out, and every ACL is read in one process. The desktop's owner ACL was first
applied without inheritance, which left the files already in the state directory with an empty ACL; it is inheritable now.

Known limits: `verax init --local` with an external token path, run as root, still repairs
the ownership of a root-owned token folder in place.
