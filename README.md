# Verax

The accountable agent body. Design intent, not yet a claim:

- any brain that speaks MCP can drive it;
- every tool call passes a gate and leaves a signed decision record before
  anything runs;
- every call that ran produces an effect row that is reconciled against its
  record afterwards;
- a refusal is recorded the same way as an approval;
- the body opens only when its authorization is configured, with no default
  token.

Status: skeleton. What the tree carries and what stays unproven is stated
in `docs/STATUS.md`. Nothing in this repository is a claim beyond that file.

`scripts/dev-issuer.mjs` is development only; not a production
authorization server. It serves `GET /authorize` (PKCE S256) and
`POST /token`, writes a token to `--out`, and never prints one.
It listens on `VERAX_DEV_ISSUER_PORT` (default 8790).
`NODE_ENV=production` exits.

`apps/panel` is a 2D account-for rail beside a particle presence.
The panel session uses the code flow; the access token stays in
memory and is dropped on refresh. Vite may still attach
`VERAX_DEV_TOKEN` from `.env.local` to `/api` when the request has
no Authorization header (desktop MCP brains and tests).
Relative frame-time checks live in `apps/panel/perf`; they are not
an absolute smoothness claim.

License: Apache-2.0.
