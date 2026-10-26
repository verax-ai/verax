# Verax body

The body an agent asks before it acts.

Verax is an MCP server that sits between an agent and its tools. Every tool call passes a policy gate and leaves a signed decision record before anything runs; every call that ran leaves an effect row that is reconciled against its record afterwards. A refusal is recorded the same way as an approval. A call the policy will not decide alone is held until an operator approves it. The ledger stays on the machine the body runs on, and the body opens only when its authorization is configured: there is no default token.

## This image

The image installs the published [`@verax-ai/body`](https://www.npmjs.com/package/@verax-ai/body) package from npm on `node:24-slim`. It is for trying Verax or for running it on a server behind a TLS-terminating proxy.

It is not the isolated install. Under `verax install` the boundary is a separate OS account the agent cannot read; here it is the container and whoever controls the Docker host.

- Tags: `latest`, and one tag per release that matches the npm version of `@verax-ai/body`.
- Built for `linux/amd64` and `linux/arm64`, each on its own architecture (releases up to 0.7.0: `linux/amd64` only).
- Runs as the `node` user, not as root.
- The ledger, keys and approvals live in the volume `/var/lib/verax` (`VERAX_STATE_DIR`).
- Listens on `0.0.0.0:8787` (`VERAX_BIND`) and speaks MCP over Streamable HTTP at `/mcp`.
- Without `VERAX_ISSUER`, `VERAX_JWKS_URL` and `VERAX_AUDIENCE` it refuses to start, with exit code 78.

## Run

The body accepts a call only with a Bearer token that your OIDC issuer signed. Replace the issuer, its JWKS URL and the audience below with yours, and mount a policy file:

```sh
docker volume create verax-state
docker run -d --name verax -p 8787:8787 \
  -v verax-state:/var/lib/verax \
  -v "$PWD/policy.json:/etc/verax/policy.json:ro" \
  -e VERAX_ISSUER=https://issuer.example \
  -e VERAX_JWKS_URL=https://issuer.example/jwks \
  -e VERAX_AUDIENCE=https://verax.example/mcp \
  -e VERAX_POLICY_FILE=/etc/verax/policy.json \
  -e VERAX_TLS_TERMINATED=1 \
  veraxai/verax serve
docker logs verax    # ends with: listening 0.0.0.0:8787
```

- An MCP request to `/mcp` without a valid token gets `401`.
- The default policy is [`packages/proxy/policy/default.json`](https://github.com/verax-ai/verax/blob/main/packages/proxy/policy/default.json) in the repository; it denies what it does not name.
- Any bind other than loopback needs `VERAX_TLS_TERMINATED=1`. Set it only with a TLS-terminating proxy in front of the container.
- The token must carry `iss`, `aud`, `sub`, `iat`, `exp` and `jti`. The other variables are listed in the [package README](https://github.com/verax-ai/verax/blob/main/packages/body/README.md#configure).

Check the ledger offline:

```sh
docker exec verax verax verify /var/lib/verax
```

A fresh volume holds no decisions yet, so it reports `NOT VERIFIED` until the first call is recorded.

[`examples/docker-oidc`](https://github.com/verax-ai/verax/tree/main/examples/docker-oidc) runs the whole shape on one Docker host with Compose: Caddy terminating TLS, a stand-in OIDC issuer, this image, and an agent making three calls.

## Limits

- Someone with root on the Docker host can stop the body or rewrite its state. See [docs/THREAT_MODEL.md](https://github.com/verax-ai/verax/blob/main/docs/THREAT_MODEL.md).
- What the record can and cannot show is stated in [docs/STATUS.md](https://github.com/verax-ai/verax/blob/main/docs/STATUS.md). No third-party audit has been performed.

## Links

- Source and documentation: https://github.com/verax-ai/verax
- Security policy: https://github.com/verax-ai/verax/blob/main/SECURITY.md
- Site: https://verax-ai.com
- Source archive on Zenodo: https://doi.org/10.5281/zenodo.22811593

License: Apache-2.0.
