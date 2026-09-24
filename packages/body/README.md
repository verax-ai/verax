# @verax-ai/body

The body an agent asks before it acts. An MCP server that puts every tool
call through a policy gate, writes a signed decision record before anything
runs, and keeps that ledger on the machine it runs on. A refusal is recorded
the same way as an approval.

Part of [Verax](https://github.com/verax-ai/verax) by
[VERAX Teknoloji](https://verax-ai.com). What the code carries and what stays
unproven is stated in
[`docs/STATUS.md`](https://github.com/verax-ai/verax/blob/main/docs/STATUS.md);
nothing here is a claim beyond that file.

## Install

```sh
npm install -g @verax-ai/body
verax --help
```

Node 22.6 or newer. `@verax-ai/proxy` and `@verax-ai/inventory` install with it.

## Configure

The body opens only when its authorization is configured; there is no default
token. It speaks MCP over Streamable HTTP at `/mcp` and refuses a call whose
Bearer token the configured issuer did not sign.

| Variable | Required | Meaning |
| --- | --- | --- |
| `VERAX_ISSUER` | yes | Issuer the agent's token must carry. |
| `VERAX_JWKS_URL` | one of | Where the body fetches the keys that verify that token. Set this or `VERAX_JWKS_FILE`, not both. |
| `VERAX_JWKS_FILE` | one of | Path to a JWKS JSON file read once at start, instead of fetching `VERAX_JWKS_URL`. Accepted only with a loopback bind. |
| `VERAX_AUDIENCE` | yes | Audience the token must name, so a token minted for something else is refused. |
| `VERAX_STATE_DIR` | yes | Directory the ledger, keys and approvals live in. It stays on this machine. |
| `VERAX_POLICY_FILE` | yes | Policy the gate applies. `@verax-ai/proxy` ships `policy/default.json`, which denies what it does not name. |
| `VERAX_BIND` | no | `host:port` to listen on. Default `127.0.0.1:8787`; anything but loopback needs `VERAX_TLS_TERMINATED=1`. |
| `VERAX_INVENTORY_FILE` | no | Roster document the body serves. The format is `@verax-ai/inventory`. |
| `VERAX_DOWNSTREAM` | no | Path to a JSON document naming MCP servers to put behind this gate: one `{ prefix, command?, args?, cwd?, env?, url?, headers?, timeoutMs?, trust? }` or an array of them. Each child names exactly one way in — `command` to spawn it over stdio, or `url` to reach one already running over Streamable HTTP, with `headers` for its own bearer. A stdio child requires `"trust": "same-user"` (it runs as the same user as the body and can read the signing keys); an HTTP child does not ask for that field and must not carry it. This is a breaking change: existing stdio documents do not open until the field is added. A path and not the JSON itself, because the document may name a key in `env` or `headers`. Their tools are served as `prefix.childName` and need an exact policy rule under that name; a named child that cannot be opened stops the body. |

`verax doctor` names what is missing. A misconfigured body exits with code 78
before it listens.

## Run

```sh
verax            # serve MCP at http://127.0.0.1:8787/mcp
verax doctor     # check the configuration this process would run with
```

Point an MCP client at `http://127.0.0.1:8787/mcp` with a Bearer token from
your issuer. The tools the body offers are `memory.get`, `memory.put`,
`audit.explain`, `message.read`, `message.send` and `spend`. The policy
decides which of them a token's scopes may call, and a call can be held
until an operator on this machine approves it.

Other commands: `install`, `uninstall`, `approve`, `operator`, `reconcile`,
`witness`, `halt`, `unlock`, `desktop`. `verax install` needs an elevated
shell and is the boundary against an agent that has a shell as your user;
`verax init --local` is not that boundary. `verax --help` lists them.

## License

Apache-2.0.
