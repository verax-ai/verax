# Verax

The body an agent asks before it acts.

Listed on: [npm](https://www.npmjs.com/package/@verax-ai/body) · [Glama](https://glama.ai/mcp/servers/verax-ai/verax) · [MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.verax-ai/verax) · [Zenodo](https://doi.org/10.5281/zenodo.22811593)

Verax is an MCP server that sits between an agent and its tools. Every tool
call passes a policy gate and leaves a signed decision record before anything
runs; every call that ran leaves an effect row that is reconciled against its
record afterwards. A refusal is recorded the same way as an approval. A call
the policy will not decide alone is held until an operator on this machine
approves it. The ledger stays on the machine the body runs on, and the body
opens only when its authorization is configured: there is no default token.

**Break it, and we pay.** USD 100 for each valid report of a way for the
agent's account to get a refused call allowed, run a call with no decision
record, or change the service's code, keys or ledger. The budget is USD 500
in total. Terms: [SECURITY.md](SECURITY.md#break-it-and-we-pay).

By [VERAX Teknoloji](https://verax-ai.com). Sister projects:
[Conarium](https://github.com/dogrucanemek-alt/conarium) ·
[Tugra](https://github.com/dogrucanemek-alt/tugra) ·
[Cedulon](https://github.com/dogrucanemek-alt/cedulon). Decision records use
the Cedulon record format.

## See it run

```sh
npx @verax-ai/body demo
```

![verax demo in a terminal: an allowed memory write, a signed refuse, and a payment held until the operator answers y](docs/demo.svg)

The recording is the output of one run in a terminal where the approval
question was answered `y`. That run took about a second; it is played back
slowly here so it can be read.

What it prints, without a terminal to answer the approval question:

```text
verax demo

memory.put / memory.get
  allowed; two signed records

message.send -> ops@blocked.test
  refused egress-blocked (signed)
  ref 6c6e4925-b769-4a8b-8fc4-e2443613a5b6

spend 100 minor USD sample-merchant
  held
  no terminal to ask, so it stays held (run this in a terminal to be asked)

audit.explain of the refuse
  finding none
  trust-root own-key
  chain and signatures read back

records  5
effects  3
ledger   removed on exit (run with --keep to keep it and check it with verax verify)

Not shown here: data masking arrives with a downstream server such as Conarium; statement reconciliation needs a real statement (verax reconcile).
```

Node 22.6 or newer, `@verax-ai/body` 0.2.1 or later. The command records an
allowed memory write and read, a
signed refuse of a message to a host off the policy list, and a payment held
for the operator on this machine (approved when the terminal answers `y`).

`--keep` leaves the temporary ledger on disk. `verax verify <dir>` reads it
back without a body, as in [Read the ledger back without us](#read-the-ledger-back-without-us).

### The same rules, animated

Four short episodes show the same gate, with characters in place of a
terminal. They are sample scenarios: the scenes are drawn in three.js and the
voices are generated with ElevenLabs.

Episode 1, "$1,850": a payment is held until a person approves it on a phone,
and changing one cent in the record breaks its signature.

https://github.com/user-attachments/assets/772ae1c4-2697-47a0-a228-36f0508b0d93

Episode 2, "No rule, no way through": a call with no rule is refused, the same
call under a new name is refused again, and both refusals are signed.

https://github.com/user-attachments/assets/4fb86627-3310-4f10-b1a9-059d8fcffb28

Episode 3, "The red lever": an operator halts the body, every later call is
refused and signed, and a call that was already running is not cut off.

https://github.com/user-attachments/assets/8d19eed9-3359-46b3-bd77-f2b1b1c4dd75

Episode 4, "Who approved?": a held spend waits for `verax approve` on the
machine, the agent cannot approve it, and the approver's operator id goes into
the record.

https://github.com/user-attachments/assets/0b8aade4-a970-4b63-835e-4837e2a39cc9

## Connect your agent

Elevated `verax install` and `verax approve` run a copy of this program that only an administrator can change; a copy your account can change is refused. On Windows an elevated CLI `approve` is the way to approve until the passkey panel is released. It has to be run from a separate administrator account, not this account elevated, because a same-user elevated shell inherits that user's environment variables and PowerShell profile, which the agent can set. Clear `NODE_OPTIONS` in that shell (`Remove-Item Env:NODE_OPTIONS`). Start that other account's PowerShell with `-NoProfile` (an elevated shell otherwise runs your `$PROFILE`, which your account can change):

```powershell
npm install -g --prefix "$env:ProgramFiles\verax-cli" @verax-ai/body
& "$env:ProgramFiles\verax-cli\verax.cmd" install
```

On Linux and macOS, with a root-owned Node (the distribution's `/usr/bin/node`, or `/opt/verax-node/<dir>/bin/node`; the installer prints those steps when the Node it was started from can be changed by your account). Do not start an elevated command with `env node`:

```sh
sudo npm install -g --prefix /opt/verax-cli @verax-ai/body
sudo /usr/bin/node /opt/verax-cli/lib/node_modules/@verax-ai/body/dist/cli.js install
```

The command installs `@verax-ai/body` from the npm registry into an administrator-owned directory after signature checks, runs that Node, and keeps the ledger under a service account. On Windows the agent token is `%ProgramData%\Verax\agent-token\<your SID>\agent.token` (Administrators and SYSTEM have full control, your SID can read the file and read-execute the directory). On Linux and macOS a child process running as your uid writes `~/.verax/agent.token` from its stdin. It prints the Claude Code line that reads that file. Port 8787 taken? `verax install --port 8797`. Node must be the all-users installer from nodejs.org on Windows; a Node your account can rewrite is refused. On macOS the remedy extracts the official tarball as root into `/opt/verax-node` (root:wheel, not group- or other-writable). On Linux the same place, `/opt/verax-node` (root:root), which SELinux labels `usr_t`. On SELinux systems install requires Node labelled `bin_t` or `usr_t` (distribution Node is; a tarball under `/usr/local/lib` is not) and prints the one-line fix. The service then runs in `unconfined_service_t`. The service account and the file permissions are the boundary.

Approve a held call with `verax approve`. The passkey panel (`verax desktop`) is not released yet. On Windows run the approve from a separate administrator account, not this account elevated, in a `-NoProfile` PowerShell after `Remove-Item Env:NODE_OPTIONS`: `& "$env:ProgramFiles\verax-cli\verax.cmd" approve`. Linux and macOS, naming the root-owned Node: `sudo /usr/bin/node /opt/verax-cli/lib/node_modules/@verax-ai/body/dist/cli.js approve` or `sudo /opt/verax-node/<dir>/bin/node /opt/verax-cli/lib/node_modules/@verax-ai/body/dist/cli.js approve`. Uninstall the same way, with `uninstall` in place of `approve`.

To try it in your own user, which is not a boundary:

```sh
verax init --local ~/.verax
verax serve --env-file ~/.verax/verax.env
```

```sh
claude mcp add --transport http verax http://127.0.0.1:8787/mcp --header "Authorization: Bearer $(cat ~/.verax/local-issuer/agent.token)"
```

The token can read and write memory through the gate; it cannot approve. The shipped policy refuses `spend` until you add a rule for it; a call your policy holds waits for `verax approve` on this machine. See docs/THREAT_MODEL.md.

### With Conarium

`@verax-ai/body` 0.2.2 and later accepts `--with-conarium`. 0.2.1 does not
carry the flag. The flag has `npx` download `@conarium-ai/core` from npm and
run it as a child process; that needs a network.

Conarium masks the rows, and its sample policy denies its `public.secrets`
table. Verax puts each call through the same gate as its own tools, keeps a
signed record and a hash of the answer, and refuses a downstream tool the
policy does not name before the child sees the call. When Conarium answers
with an error, the body tells the caller that it did, not what it said.

What it prints, without a terminal to answer the approval question:

```text
verax demo

memory.put / memory.get
  allowed; two signed records

message.send -> ops@blocked.test
  refused egress-blocked (signed)
  ref 6c6e4925-b769-4a8b-8fc4-e2443613a5b6

spend 100 minor USD sample-merchant
  held
  no terminal to ask, so it stays held (run this in a terminal to be asked)

conarium.query customers
  allowed; masked by Conarium before the rows left it
  measured [MASKED_PII] on every email and card

conarium.query public.secrets
  allowed by this gate; Conarium answered with an error and no rows
  recorded as a failed call

conarium.list_tables
  refused no-rule (signed)
  refused by this gate; the downstream server never saw the call

audit.explain of the refuse
  finding none
  trust-root own-key
  chain and signatures read back

records  8
effects  5
ledger   removed on exit (run with --keep to keep it and check it with verax verify)

Not shown here: a real database (these are Conarium's sample rows); statement reconciliation needs a real statement (verax reconcile).
```

## What ships

| Package | What it is |
| --- | --- |
| [`@verax-ai/body`](https://www.npmjs.com/package/@verax-ai/body) | The MCP server and the `verax` command: serve, `install`, `uninstall`, `init`, `doctor`, `approve`, `operator`, `reconcile`, `witness`, `halt`, `resume`, `unlock` (`desktop` is not released yet). |
| [`@verax-ai/proxy`](https://www.npmjs.com/package/@verax-ai/proxy) | The decision proxy the body is built on: policy, signed records, ledger, `explain`, reconcile. |
| [`@verax-ai/inventory`](https://www.npmjs.com/package/@verax-ai/inventory) | The roster document a body serves and the panel lists, with its strict parser. |

The three packages are published together and carry the same version; the
capability matrix in [`docs/STATUS.md`](docs/STATUS.md) names the current one,
and it is the version on npm. The body is also listed in the MCP registry as
`io.github.verax-ai/verax`. What that version carries, what it does not,
and the test holding each row up are in the capability matrix at the top
of [`docs/STATUS.md`](docs/STATUS.md).

## Read the ledger back without us

A ledger only the vendor's running service can read is evidence a buyer
rents, not evidence they hold. `verax verify` reads a state directory on
its own — no body listening, nothing on the network — and states four
things separately, because they fail separately:

```
$ verax verify ./verax-state
ledger        ./verax-state
decisions     6
effects       4 (4 bound to a decision, 0 with none)
signatures    6 verify, 0 do not
chain         unbroken
verified with the key carried in these files
              verified against the key carried in the records themselves: this
              shows the files are internally consistent, not that the key was
              ever trusted. Pin a key you hold to check that.

VERIFIED
```

That last pair of lines is the point. Checking a ledger against the key
lying next to it proves the files agree with each other and nothing more —
anything able to write the ledger could write that key too. Pass
`--key <public.pem>` to verify decision records against a copy you hold, and
the answer says `a key you supplied` instead. Effects are signed with a
separate key. A `self` row is checked under the effect key: `--effect-key <public.pem>`
when you pin it, otherwise one key taken from the first `self` row. A `same-org`
row is checked under the witness key: `--witness-key <public.pem>` when you pin it,
otherwise one key taken from the first `same-org` row. Pinning `--effect-key` while
a `same-org` row is present requires `--witness-key` as well, and pinning
`--witness-key` while a `self` row is present requires `--effect-key` as well;
otherwise the result is not verified. Each of those lines says the
same thing: the files agree with each other, not that the key was ever yours.
Checkpoints are signed by the witness key. Every checkpoint row is checked under one key: `--checkpoint-key <public.pem>` when you pin it, otherwise one key taken from the checkpoint file, with the same note that agreement is not trust. The tail counts only checkpoints whose signatures verified. Someone who can rewrite the files can still roll that file back to an older valid prefix together with the records after it; only a checkpoint held elsewhere detects that. `--json` prints
the same result for a
pipeline; the exit code is 0 when it verifies and 1 when it does not, and a
directory with no ledger in it is never quiet success.

Records are COSE_Sign1 with algorithm `-19` (Ed25519, RFC 9864), not the
older polymorphic `-8` (EdDSA). Some COSE libraries do not know `-19` yet:
as of go-cose 1.3.0 and pycose 1.1.0 both reject it, and support is tracked
in [go-cose#224](https://github.com/veraison/go-cose/issues/224) and
[pycose#126](https://github.com/TimothyClaeys/pycose/issues/126).
`verax verify` does not depend on either library.

### Verifiers other than ours

[`test-vectors/`](test-vectors/README.md) is a frozen set of ledgers, each with
the verdict and the stage a verifier should report. Two people have run the set
at `vectors-v1` with verifiers of their own and posted the results:

- Tymofii Pidlisnyi (Agent Passport System), with a runner in the APS
  conformance suite: a partial, stage-by-stage comparison across all 16
  vectors, not a whole-ledger verdict
  ([run](https://github.com/mirjak/audit-bof-preparation/issues/9#issuecomment-5972115527)).
- Roberto Locatelli (cryptovalid-opencore), with clean-room checkers written
  from the drafts, the RFCs and the vector README: with the checkpoint verified
  under the witness key, 16 of 16 verdicts and 15 of 16 first failing stages.
  One of those matches came from a rule added after reading the vector, as the
  run itself states
  ([run](https://github.com/mirjak/audit-bof-preparation/issues/9#issuecomment-5979503944)).

A matching run shows that another verifier reads these encodings and reaches
the same verdict at the same stage. It is not an independent audit of the body.

## Install

```sh
npm install -g @verax-ai/body
verax --help
verax doctor
```

On an account where every process is elevated (the built-in Administrator, or `EnableLUA=0`), a command from a user-writable npm prefix is refused; use the administrator-owned copy at `%ProgramFiles%\verax-cli`.

Node 22.6 or newer. The body speaks MCP over Streamable HTTP at `/mcp` on
`VERAX_BIND` (default `127.0.0.1:8787`) and needs an issuer, a JWKS URL, an
audience, a state directory and a policy file before it listens; `verax
doctor` names what is missing. The variables and the run steps are in
[`packages/body/README.md`](packages/body/README.md).

## Tools

The policy decides which of these a token's scopes may call;
`packages/proxy/policy/default.json` denies what it does not name.

| Tool | Description |
| --- | --- |
| `memory.get` | Reads one memory item behind the gate, stored per tenant. |
| `memory.put` | Writes one memory item behind the gate, stored per tenant. |
| `audit.explain` | Reads a decision back from the signed ledger, with its chain, its signatures and its findings. |
| `message.read` | Reads the inbox. |
| `message.send` | Writes to the outbox; reaches only hosts the policy allow-lists. |
| `spend` | Authorizes a payment and records it, under a cap, a payee list and a daily limit from the policy; held for an operator when the policy says so. The body does not move money. |

## What the body does beyond the gate

Each line below is a row in the capability matrix in
[`docs/STATUS.md`](docs/STATUS.md), where it is stated against a version,
with what it does not do and the test that fails when it stops being
true.

- Approval: a held call is approved with `verax approve` on this
  machine. On Windows that runs from a separate administrator account. The
  passkey panel (`verax operator`, `verax desktop`) is not released yet. The
  approver's operator id is bound into the signed record by hash.
- Witness: `verax witness` signs effect rows from a second process and writes
  durable checkpoints; without it the witness class stays `self`.
- Halt and revoke: `verax halt` turns every further call into a signed deny;
  a revoked token id is refused before any record is written.
- Reconcile: `verax reconcile` matches recorded spends against a card
  statement export and names the matched, ghost and authorized-but-unpaid
  rows.
- Tenant key: memory and inbox are stored under a key derived from the
  token's issuer and subject; another tenant's id is answered with a signed
  deny.
- Bounds: rate and daily counters, a disk-low refusal (HTTP 507) when a deny
  could not be recorded, and an egress allow-list; counters that cannot be
  read fail closed.
- Doctor and heartbeat: `verax doctor` names what is missing or stale before
  the first call finds out.

### Watch for silence (unreleased tree)

The running body pulses even while idle (10 s by default;
`VERAX_HEARTBEAT_EVERY_MS`, minimum 1,000 ms). Start rows in `starts.jsonl`
record gaps from the previous beat; `verax verify <stateDir>` summarizes
them offline. Start rows are unsigned in v1.

```sh
verax watch ./verax-state --max-silence 30s
verax watch ./verax-state --once
verax watch --url https://host/healthz --token-file ./audit.token --once
verax watch ./verax-state --on-silence exec --exec "node isolate.mjs"
```

An unreadable, stale or far-future beat is silence. A local watch halts by
default; recovery never resumes it. An operator must use the existing
resume path. Remote watch reports silence and cannot halt remotely. Tokens
are read only from files; HTTPS is required except on loopback. An exec
command runs once per silence episode with `VERAX_WATCH_REASON` in its
environment, without a shell. Quote executable/arguments containing spaces.
`--once` exits 0 live, 3 silent or 2 on usage errors. Continuous watch prints
one JSON line per silence episode and recovery, polling at `max-silence/3`.
Run it where the operator chooses; a same-host watcher shares that host's
trust and is not independent evidence if both ledger and watcher vanish.

## Connect a client

The body listens on `http://127.0.0.1:8787/mcp` by default. A client
configuration looks like this; the token comes from your issuer.

```json
{
  "mcpServers": {
    "verax": {
      "url": "http://127.0.0.1:8787/mcp",
      "headers": { "Authorization": "Bearer <token from your issuer>" }
    }
  }
}
```

## Status

What the tree carries and what stays unproven is stated, item by item, in
[`docs/STATUS.md`](docs/STATUS.md). Nothing in this repository is a claim
beyond that file, and a paragraph there is not a release. The threat model is
in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md); how to report a
vulnerability is in [`SECURITY.md`](SECURITY.md).

## What else is in the tree

- `apps/panel` is the account-for screen: the records list, the black box and
  the status view, read from the signed ledger. Private; it is not published.
  The panel session uses the code flow; the access token stays in memory and
  is dropped on refresh. Vite may still attach `VERAX_DEV_TOKEN` from
  `.env.local` to `/api` when the request has no Authorization header
  (desktop MCP brains and tests).
- `scripts/dev-issuer.mjs` is development only; not a production
  authorization server. It serves `GET /authorize` (PKCE S256) and
  `POST /token`, writes a token to `--out`, and never prints one. It listens
  on `VERAX_DEV_ISSUER_PORT` (default 8790). `NODE_ENV=production` exits.
- `scripts/demo-box.mjs` is development only: one process that starts the
  dev issuer and the body on loopback with a temporary ledger, mints itself a
  short-lived token through the issuer's code flow, and speaks MCP over stdio
  for a sandbox that cannot hold a token of its own, such as a directory's
  build check. The body is not changed by it: every call still passes the
  gate and is recorded, `spend` is always held, and no operator is there to
  approve it. `NODE_ENV=production` exits. Not a deployment.

## Developing

```sh
npm ci
npm test            # guards, typecheck, build, unit and cost suites, panel
npm run pack:smoke  # pack the three packages and install them elsewhere
```

CI runs the suite as a non-root user on Linux and again on Windows, plus the
proxy performance check. Releases go out from the Actions tab:
`release.yml` publishes the three packages with npm trusted publishing and a
provenance attestation, then `mcp-registry.yml` updates the registry record
once npm answers for the new version. Neither runs on push.

Tested on every release on the platforms listed in docs/PLATFORMS.md, each row linked to its CI run.

## License

Apache-2.0.
