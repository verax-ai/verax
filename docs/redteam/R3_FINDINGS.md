# R3 findings — installed mode (`install` / `uninstall` / `doctor`)

Independent of R1, R2, and the install CI. Product code was not changed by the red team. Each provable row has a test in `tests/attack-r3.test.ts` that asserts the safe behaviour.

| id | severity | attacker | description | file:line | proof |
| --- | --- | --- | --- | --- | --- |
| R3-1 | high | Local non-admin, before the first install | A directory the attacker creates at `%ProgramData%\Verax` plus an `install.json` that merely contains string `version` and `codeDir` is treated as a previous verax install. The pre-created root is accepted, and the attacker still owns the parent of the state directory. | `packages/body/src/install.ts` `planInstall` root check | `R3-1 a user-written install.json does not authorise a pre-created Verax root` |
| R3-2 | high | The agent, in the elevated install process | The agent-token ACE is `USERNAME` / `USERDOMAIN` from the environment, not the invoking user's SID. `USERNAME=Everyone` grants `Everyone:(R)` on `agent.token`. | `packages/body/src/install.ts` `tokenPrincipalFor` | `R3-2 the agent token ACE is not taken from USERNAME` |
| R3-3 | high | A domain principal named `verax-svc` | The account script and the scheduled task look up the bare name `verax-svc`. Windows name lookup can return the domain account. That principal receives `SeBatchLogonRight`, the state-directory grant, and `Register-ScheduledTask -User`. | `packages/body/src/install.ts` `windowsAccountOps` | `R3-3 verax-svc is the local account, not a bare name lookup` |
| R3-4 | high | The agent, or any keeper of the install environment (`sudo -E`, env_keep) | `VERAX_INVOKING_HOME` is the token directory. It is not checked against the invoking user's passwd or dscl home. | `packages/body/src/install.ts` `linuxHome` | `R3-4 VERAX_INVOKING_HOME cannot move the agent token` |
| R3-5 | high | Whoever already owns a login named `verax` | `id verax` status 0 skips `useradd`. Install then `chown`s the state directory to that existing account. | `packages/body/src/install.ts` `linuxAccount` | `R3-5 an existing Linux verax login that we did not create is refused` |
| W1 | critical | Local non-admin, before or during install | `%ProgramData%\Verax` is created without a lock. `ProgramData` grants Users create-child and CREATOR OWNER full control on new children, so a standard user can plant `state\keys` (or a junction) before the installer tightens the child. Uninstall leaves the root Users-writable. | `packages/body/src/install.ts` `applyLockRoot` | `W1 the root lock is the first op` |

## R3-1 a user-written install.json authorises the root

**Steps.** As a standard user, create `%ProgramData%\Verax` and write `install.json` with `{"version":"0.3.0","codeDir":"...","createdAccount":true}`. Run elevated `verax install`.

**Expected.** Refusal. A marker counts only when the `Verax` directory is owned by Administrators or SYSTEM and its DACL does not grant write to Users, CREATOR OWNER, Everyone, or Authenticated Users. Otherwise `refusing: ... was not created by verax install`.

**Actual (before the fix).** `ourMarker` accepts any JSON object whose `version` and `codeDir` are strings. The pre-created root is accepted. The parent is never locked.

**Fix.** `runInstall` reads the owner and the DACL through the injected exec and passes them to `planInstall`. An existing root is accepted only when the marker parses, the owner is Administrators or SYSTEM, and the DACL is not user-writable.

## R3-2 USERNAME is the token principal

**Steps.** In the elevated install process, set `USERNAME=Everyone` and leave `USERDOMAIN` empty.

**Expected.** The token grant is the invoking user's SID (`*S-1-...:(R)`), from `whoami /user`. `USERNAME` and `USERDOMAIN` are not icacls principals. Well-known group SIDs `S-1-1-0`, `S-1-5-11`, and `S-1-5-32-545` are refused. The profile directory comes from `ProfileList\<SID>\ProfileImagePath`; a different `USERPROFILE` is refused.

**Actual (before the fix).** `winPrincipal` builds `DOMAIN\user` or the bare `USERNAME`.

**Fix.** `tokenPrincipalFor` emits `*SID:(R)`. `runInstall` resolves the SID with `whoami /user` and the profile with the ProfileList key.

## R3-3 bare verax-svc hits the domain

**Steps.** On a domain-joined machine where a domain account `verax-svc` already exists, run elevated `verax install`.

**Expected.** Every lookup after create uses the local account's SID from `Get-LocalUser`. `Register-ScheduledTask -User` is that SID. No `NTAccount('verax-svc')`.

**Actual (before the fix).** `NTAccount('verax-svc')` and `-User 'verax-svc'`.

**Fix.** The account script and the task script take `$sid` from `Get-LocalUser`. icacls rewrite at execute uses the same cmdlet.

## R3-4 VERAX_INVOKING_HOME relocates the token

**Steps.** Elevated install with `SUDO_USER=runner` and `VERAX_INVOKING_HOME=/tmp/not-the-user`.

**Expected.** The token path is the home `getent passwd` or `dscl` returns. A different `VERAX_INVOKING_HOME` is refused, and the sentence names both paths.

**Actual (before the fix).** `linuxHome` and `darwinHome` return `VERAX_INVOKING_HOME` as soon as it is non-empty.

**Fix.** The passwd or dscl home is the plan home. `VERAX_INVOKING_HOME` is kept only when it is that path.

## R3-5 existing Linux user verax is reused

**Steps.** A machine already has a login `verax` that this install did not create. Run root `verax install`.

**Expected.** Refusal: `verax already exists and was not created by verax install`. Do not `chown` the state directory to it.

**Actual (before the fix).** `execute` runs `id verax` and, on status 0, skips `useradd`. Later ops still `chown verax:verax`.

**Fix.** `runInstall` records `linuxAccount: { exists, createdByUs }` from `id verax` and the marker flag `createdUser`. `planInstall` refuses when `exists && !createdByUs`. The silent skip in `execute` is gone. The marker records `createdUser: true` when this install runs `useradd`.

## W1 the Windows root is never locked

Measured on this machine: `icacls C:\ProgramData` has `BUILTIN\Users:(CI)(WD,AD,WEA,WA)` and `CREATOR OWNER:(OI)(CI)(IO)(F)`. A directory the installer creates under ProgramData lets any standard user create children and own them.

**Actual (before the fix).** `applyPrivateTemp` creates `ProgramData\Verax` through `mkdirNewChain` and never locks it. The state directory is created, then owned and locked in later processes. Between those calls a standard user can create `state\keys` and keep a handle. Uninstall leaves the root Users-writable.

**Fix.** The first plan op is `lock-root`, before `private-temp`. A missing root is created and immediately `icacls /setowner *S-1-5-32-544` plus `/inheritance:r` for Administrators and SYSTEM. A child that appears in that fresh root is named in the refusal and the directory we created is removed. An existing root is accepted only under the R3-1 rule. Empty npmrc files are written with `flag: "wx"`. `doctor` and the post-lock read-back fail a Users, CREATOR OWNER, Everyone, or Authenticated Users write ACE on the root. The Windows install CI prints `icacls $env:ProgramData\Verax` and fails if those principals appear.

## Checked and solid

- Symlinks and junctions on the Windows state root are refused at plan time (`reparsePath` / `fsutil reparsepoint`). Hardlinks are not reparse points.
- `npmSpawnEnv` replaces the environment. `npm_config_*`, `NODE_OPTIONS`, `HOME`, and the caller's `PATH` are not copied. npm flags include `--ignore-scripts`, `--userconfig`, and `--globalconfig` pointing at empty files in the private temp. Registry `resolved` URLs must start with `https://registry.npmjs.org/`.
- `--from-tarballs` re-hashes the private-temp copy and refuses a mismatch (`stageTarballCopies`).
- System tools are absolute paths under `SystemRoot\System32` or the fixed Linux/macOS directories. `systemToolEnv` does not copy the caller's `PATH`. `PATHEXT` is a fixed `.EXE` list.
- `--force` skips only the "state already exists" refusal. It does not skip the reparse check or the "account exists and was not ours" check.
- The service unit sets `User=verax`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, and `ReadWritePaths` to the state directory only. The launchd plist sets `UserName` to `_verax`.
- The token file plan removes inheritance before the user grant. `doctor` prints secret names, not secret values. The installed body listens on `127.0.0.1`.
- Windows `verax-svc` that already exists without `createdAccount` in the marker is refused.
- Uninstall removes the fixed unit, plist, code directory, and state directory. It deletes the Windows account only when the marker says `createdAccount`.
