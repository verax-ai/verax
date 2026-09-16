# Verax

The body an agent asks before it acts.

Verax is an MCP server that sits between an agent and its tools. Every tool
call passes a policy gate and leaves a signed decision record before anything
runs; every call that ran leaves an effect row that is reconciled against its
record afterwards. A refusal is recorded the same way as an approval. A call
the policy will not decide alone is held until an operator on this machine
approves it. The ledger stays on the machine the body runs on, and the body
opens only when its authorization is configured: there is no default token.

By [VERAX Teknoloji](https://verax-ai.com). Sister projects:
[Conarium](https://github.com/dogrucanemek-alt/conarium) ·
[Tugra](https://github.com/dogrucanemek-alt/tugra) ·
[Cedulon](https://github.com/dogrucanemek-alt/cedulon). Decision records use
the Cedulon record format.

## What ships

| Package | What it is |
| --- | --- |
| [`@verax-ai/body`](https://www.npmjs.com/package/@verax-ai/body) | The MCP server and the `verax` command: serve, `doctor`, `approve`, `operator`, `reconcile`, `witness`, `halt`, `unlock`, `desktop`. |
| [`@verax-ai/proxy`](https://www.npmjs.com/package/@verax-ai/proxy) | The decision proxy the body is built on: policy, signed records, ledger, `explain`, reconcile. |
| [`@verax-ai/inventory`](https://www.npmjs.com/package/@verax-ai/inventory) | The roster document a body serves and a galaxy draws, with its strict parser. |

The body is also listed in the MCP registry as `io.github.verax-ai/verax`.

## Install

```sh
npm install -g @verax-ai/body
verax --help
verax doctor
```

Node 22.6 or newer. The body speaks MCP over Streamable HTTP at `/mcp` on
`VERAX_BIND` (default `127.0.0.1:8787`) and needs an issuer, a JWKS URL, an
audience, a state directory and a policy file before it listens; `verax
doctor` names what is missing. The variables and the run steps are in
[`packages/body/README.md`](packages/body/README.md).

## Tools

The policy decides which of these a token's scopes may call;
`packages/proxy/policy/default.json` denies what it does not name.

- `memory.get`, `memory.put`: memory behind the gate, stored per tenant.
- `audit.explain`: a decision read back from the signed ledger, with its
  chain, its signatures and its findings.
- `message.read`, `message.send`: an inbox and an outbox; `send` reaches only
  hosts the policy allow-lists.
- `spend`: authorizes a payment and records it, under a cap, a payee list and
  a daily limit from the policy; held for an operator when the policy says so.
  The body does not move money.

## What the body does beyond the gate

- Approval: a held call is approved with `verax approve` on this machine, or
  from the panel after a passkey sign-in (`verax operator`); the approver's
  operator id is bound into the signed record by hash.
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

- `apps/panel` is a 2D account-for rail beside a three.js galaxy fed from the
  signed ledger. Private; it is not published. The panel session uses the
  code flow; the access token stays in memory and is dropped on refresh. Vite
  may still attach `VERAX_DEV_TOKEN` from `.env.local` to `/api` when the
  request has no Authorization header (desktop MCP brains and tests).
  Relative frame-time checks live in `apps/panel/perf`; they are not an
  absolute smoothness claim.
- `packages/galaxy` turns an inventory document into the galaxy the panel
  draws. Private.
- `scripts/dev-issuer.mjs` is development only; not a production
  authorization server. It serves `GET /authorize` (PKCE S256) and
  `POST /token`, writes a token to `--out`, and never prints one. It listens
  on `VERAX_DEV_ISSUER_PORT` (default 8790). `NODE_ENV=production` exits.

## Developing

```sh
npm ci
npm test            # guards, typecheck, build, unit and cost suites, panel
npm run pack:smoke  # pack the three packages and install them elsewhere
```

CI runs the suite as a non-root user on Linux and again on Windows, plus the
panel and proxy performance checks. Releases go out from the Actions tab:
`release.yml` publishes the three packages with npm trusted publishing and a
provenance attestation, then `mcp-registry.yml` updates the registry record
once npm answers for the new version. Neither runs on push.

## License

Apache-2.0.
