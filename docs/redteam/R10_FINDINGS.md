# R10 findings — independent red team

Independent of R1–R9. `docs/redteam/*` and `tests/attack-*.test.ts` were not opened until the promise list and the breaks below were already written down from the code. Product code was not changed. Tests were not executed (the task forbids commands). Each provable row has an `it` in `tests/attack-r10.test.ts` that asserts the safe behaviour, which the current tree does not implement.

No critical findings. Two high findings. One medium finding.

| id | severity | attacker | description | file:line | proof | status |
| --- | --- | --- | --- | --- | --- | --- |
| R10-1 | high | Whoever can hand `verify` a ledger directory | A signed effect whose class ends with `:threw` is bound to any decision with that ref, including a deny whose `effectHash` is null and whose subject is a different tool. Both keys can be pinned. `ok` is true. | `packages/proxy/src/verify-ledger.ts:540` | `R10-1 verify does not bind a :threw effect to a decision that did not throw that class` | new; disagrees with R7 §3 and R9 "Checked and solid" §2 |
| R10-2 | high | Another local user, before any operator passkey exists; also the agent that holds the dev issuer's `--out` token | The dev issuer's default scope keeps `verax:audit` after it strips `verax:approve`. No passkey is required. A body that verifies that issuer with `VERAX_JWKS_URL` (desktop, not `verax install`) serves `/api/ledger` for that scope: every tenant's decisions, inputs, and spend snapshots. | `scripts/dev-issuer.mjs:102` | `R10-2 a token minted with no passkey does not carry verax:audit` | new. R4 and R6 closed this only for `VERAX_JWKS_FILE` |
| R10-3 | medium | Whoever can hand `verify` a ledger directory | `ledger-manifest.json` piece paths are `path.join`ed and not confined to the directory. `../real/decisions.jsonl` is read, the directory's own `decisions.jsonl` is not, and a valid outside ledger is `ok: true`. | `packages/proxy/src/verify-ledger.ts:126` | `R10-3 verify does not follow a manifest piece outside the directory` | new |

## Promises read before the code

Taken from `README.md`, `docs/STATUS.md` (capability matrix, not the historical record), `docs/THREAT_MODEL.md`, `server.json`, `SECURITY.md`, and the three package READMEs. A paragraph in the historical record is not a promise of this tree.

1. Every `tools/call` passes a fail-closed policy and leaves a signed decision before anything runs. A refusal is recorded the same way as an allow. The policy sees the tool name and the scopes, not the argument text.
2. A call that ran leaves an effect bound to that decision by `effectHash`. The row is what the body was told.
3. A call the policy will not decide alone is held until an operator on this machine approves it. There is no auto-approve and no remote approver. The approver id is in the signed record by hash. Parallel approvals of one request leave one allow.
4. `spend` is capped, always defers, and is re-checked against today's approved total at approval time. The body does not move money.
5. Memory and inbox live under a tenant key of SHA-256 of `{ iss, sub }` plus `tenant` or `org` when present. Another tenant's id is a signed deny with no body.
6. One `_ref` runs once. A retry is judged by the policy in force now. A restart mid-run answers `outcome-unknown` instead of running the approved call again.
7. Rate and daily counters are per body and fail closed when they cannot be read. A deny that cannot be appended is HTTP 507.
8. `message.send` reaches only hosts the policy names. The shipped body queues; it does not open a network connection for that tool.
9. `verax halt` denies further calls. A revoked `jti` is refused before a record is written.
10. `verax verify` reads a directory with no body and nothing on the network, and states signatures, chain, effect binding, and which key answered. Exit 0 only when it verifies. Checking the key in the files proves they agree with each other, not that the key was trusted. A thrown call may carry a different hash: the effect class is `<subject>:threw`. An empty directory is not success. Rolling the checkpoint file back to an older valid prefix, together with the records after it, is detected only by a checkpoint held elsewhere.
11. `verax install` puts code and state where the agent's own user cannot read them, under `verax-svc` / `verax` / `_verax`. The agent token is the only credential left in the invoking user's profile. It does not delete or take over an account this install did not create. An administrator or root is outside the model.
12. A stdio downstream child runs as the body and can read the signing keys. The `trust: same-user` field records the operator's acceptance and does not close that. An HTTP child is not followed across a redirect. A tool the policy does not name is denied before the child is called.
13. Local mode (`VERAX_JWKS_FILE`) does not honour `verax:audit` or `verax:approve` over HTTP. `verax init --local` is not a boundary against a shell as the same user. The development issuer is not a production authorization server and exits when `NODE_ENV=production`.
14. The panel's audit doors (`/api/ledger`, contest, agents) require `verax:audit`. A brain token is not that key. Approval over HTTP requires `verax:approve` and the `requestHash` the operator saw.
15. Loopback binds refuse a `Host` that is not `127.0.0.1`, `localhost`, or `::1` on the listen port. A browser `Origin` that is not on the allow-list is refused.

## R10-1 a `:threw` row binds to the wrong decision

**Invariant the verifier states.** The comment in `verify-ledger.ts` says a thrown call relaxes only the hash, and the effect is `<subject>:threw`. The decision writer stores that subject on `effectClass` so a decision and an effect can be held to the same word. A deny stores `effectHash: null` because nothing ran. R7 and R9 called "class ends with `:threw` and some decision has that ref" solid. That is wider than the comment, and it is false.

**What was tried.** A policy with no rules. `memory.get` is a signed `deny` / `no-rule`. Then `appendEffect` writes a row the effect key really signs:

- class `spend:threw` on that ref
- class `memory.get:threw` on a second deny of `memory.get`

`verifyLedger` is called with both the record key and the effect key pinned.

**Expected.** `ok` is false. `effectsBound` is 0. A deny did not throw, and `spend:threw` is not `memory.get:threw`.

**Actual.** `effectClass.endsWith(":threw")` and `refler.has(ref)` skip the hash check. The signature covers the row, so the row is bound. `problems` stays empty. `ok` is true. Pinning the keys does not save it: the signatures are valid, and the two files still describe different events.

**Fix.** Bind a `:threw` row only when a decision with that ref has `decision: "allow"` and the effect class is that decision's subject plus `:threw`. Anything else is orphaned.

## R10-2 audit without a passkey

**Invariant the doors state.** `/api/ledger` hands out every tenant's decisions, the inputs that name their principals, and the approval snapshots that carry spend arguments. The scope for that door is `verax:audit`. A brain token does not hold it. Local mode answers 403 when the token does. The dev issuer's own comment says a session without a passkey is read-only and that approve is minted only after a passkey.

**What was tried.** `scripts/dev-issuer.mjs` with a fresh state directory and no `operator-credentials.json`. The default scope is `verax:read verax:memory verax:audit`. `agentScope` removes `verax:approve` and leaves `verax:audit`. That string is what `--out` writes at startup, and what `GET /authorize` plus `POST /token` mint when no operator is enrolled (`dev-issuer.mjs` around the 302 that runs before the passkey branch).

On a body whose issuer is that process and whose keys come from `VERAX_JWKS_URL`, `server.ts` applies the audit 403 only when `config.jwksFile` is set. Desktop starts the body that way. `GET /api/ledger` then requires `verax:audit` and returns the ledger.

`verax install` is not this path. It uses `verax init --local` (`verax:read verax:memory`) and `VERAX_JWKS_FILE`, which refuses the scope. After a passkey is enrolled, `/authorize` does not mint a code until `/authorize/verify` succeeds. The `--out` file is still written on every start, passkey or not.

**Expected.** A token written for the agent, and a code exchanged with no passkey, do not include `verax:audit`.

**Actual.** Both do. Another user on the machine can complete the code flow against `127.0.0.1` while the issuer has no operator. The agent that is given the `--out` file can call `/api/ledger` on a desktop body. Host checking stops a public web page; it does not stop a local user.

**Fix.** Drop `verax:audit` in `agentScope`, the same way `verax:approve` is dropped. Mint audit only on the passkey session (`grantApprove`). Do not put it in the file `--out` writes.

## R10-3 the manifest names a file outside the directory

**Invariant `verax verify` states.** It reads a state directory. Nothing on the network. The files in that directory are what `VERIFIED` is about.

**What was tried.** A directory `real` whose `decisions.jsonl` is one signed deny, which verifies on its own. A directory `wrap` whose `decisions.jsonl` is an unsigned `allow` with ref `lie`, and whose `ledger-manifest.json` sets the piece's `decisions` to `../real/decisions.jsonl`.

**Expected.** `verifyLedger(wrap)` is not `ok`. A piece path that leaves the directory is not that directory's ledger.

**Actual.** `decisionFiles` does `join(dir, p.decisions)` and keeps the path when the file exists. `join` resolves `..`, so the outside deny is the ledger and the local `lie` line is never parsed. `ok` is true. An absolute path is the same join rule. On Windows a UNC target would be a network read, which the command says it does not do.

**Fix.** Resolve each piece path and refuse it unless it stays under the directory after normalization. A refused path is a problem and `ok` is false.

## Checked and solid

1. **Policy gate.** Default is deny. A `spend` rule that is not `mode: "approve"` is refused at load. Unknown tools are `no-rule` and do not run. The policy does not read argument text; that limit is stated, not a hole in the gate.
2. **Operator approval of spend.** `approvePending` checks the snapshot hash against the defer, expires, then the daily budget, under one lock. HTTP approval requires `verax:approve`, refuses that scope in local mode, and rejects a stale `requestHash`. `--from-script` skips the typed amount; after install the state directory is not writable by the agent, and an elevated shell left open for the agent is outside the model.
3. **Tenant files.** Memory ids match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` and the resolved path has to stay under that tenant. `audit.explain` denies a ref whose inputs principal is a different tenant, and denies when the principal is missing. Spoken `tenant-mismatch` is `not-found` on the brain string only.
4. **Install accounts, as far as this round could push them without being root.** A pre-existing `verax` / `verax-svc` / `_verax` that the marker does not claim is refused. Linux `useradd` passes `-U`. When the marker has `accountUid` / `accountGid`, a different live id is not removed. Darwin compares both ids. Windows compares the SID. R9's "useradd does not pass `-U`" and "the verdict ignores the recorded uid" do not match this tree. What remains: if the marker claims the account and records no uid, `linuxUserVerdict` still deletes on the system-id / nologin / home `/` shape. Replacing that uid is an administrator. Not filed.
5. **Effect binding other than R10-1.** A non-throw row whose hash is not the decision's is orphaned (`duplicate-effect-verify.test.ts` already pins that). `duplicate-effect` has to carry the fixed refusal hash and a signature. The receipt's canonical row has to equal the on-disk row, so a class change that is not re-signed does not survive. R10-1 is the case the signature does not save, because the class really was signed and the wrong decision still accepts it.
6. **Checkpoints.** A loaded row with a bad signature is a problem. Dropping a middle row breaks `prevCheckpointHash`. Dropping the newest row and the records after the previous checkpoint is the rollback the README already names; an external checkpoint is what detects it. Not refiled.
7. **Loopback and the browser.** `loopbackHostDecision` and the issuer's copy allow only `127.0.0.1`, `localhost`, and `::1` on the listen port. A present `Origin` has to be listed. DNS rebinding sends the attacker's host name, which is denied. A cross-origin page does not receive a loopback `Host`.
8. **Downstream.** Prefix and child tool names are restricted. Built-in names are reserved. HTTP redirects are `redirect: "error"`. Schemes other than `http:` and `https:` are refused. The body's bearer is not copied into the child env or the child headers. A stdio child can read `keys/*.pem`; STATUS already says the trust ack does not close that. Not refiled.
9. **Witness.** The listen token is 16 random bytes in a mode `0600` file. `/sign` and `/checkpoint` check it. The body will store a `same-org` answer without checking the signature first; `verify` then rejects a forged signature under the pinned or first effect key. Stealing the port requires the witness to have released it, at which point the token does not sign anything. Not filed as high.
10. **Local install boundary.** `verax init --local` and a shell as that user are stated as not a boundary. `verax install` is the boundary this round did not find a way through for a non-admin: state mode `0700`, token only in the invoking profile, npm `--ignore-scripts`, registry pinned to `registry.npmjs.org`.
11. **Outbox cap.** `message.send` stats `outbox.jsonl` under the tenant lock and stops at `messageQuotaBytes()` (default 1 MiB). R9-1's "nothing reads the file size" does not match this tree.
12. **WebAuthn replay.** The sign-in challenge is deleted inside the synchronous expected-challenge callback. Counter `0` is accepted again because those authenticators do not increment; the challenge is not. R4 already said so. Agree.
