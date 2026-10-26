# Verax behind TLS with an OIDC issuer (Docker Compose)

One Docker host runs four things: Caddy terminating TLS with its own local CA,
a stand-in OIDC issuer, the published `veraxai/verax` image, and an agent that
gets a token from the issuer and calls Verax over MCP. It is the shape of a
customer deployment, small enough to run on a laptop.

> **The issuer in `idp/` is NOT for production.** It signs a token for anyone
> who holds the shared secret, and its signing key lives only as long as the
> process. In a real deployment, point `VERAX_ISSUER`, `VERAX_JWKS_URL` and
> `VERAX_AUDIENCE` in `docker-compose.yml` at your own identity provider and
> drop the `idp` service. A token must carry `iss`, `aud`, `sub`, `iat`,
> `exp` and `jti` (see `packages/body/README.md`).

## Run it

From this directory (on Git Bash for Windows, set `MSYS_NO_PATHCONV=1` first so
container paths such as `/var/lib/verax` are not rewritten):

```sh
mkdir -p secrets ca
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > secrets/idp_client_secret
sudo chown 1000:1000 secrets/idp_client_secret   # Linux host, unless you are uid 1000

# TLS and the issuer first; Caddy creates its local CA on start.
docker compose up -d --build caddy idp
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ca/root.crt
sudo chown 1000:1000 ca/root.crt                 # Linux host, unless you are uid 1000

# The body trusts that CA to fetch the issuer's keys over https.
docker compose up -d body
docker compose logs body          # ends with: listening 0.0.0.0:8787

# The agent: token from the issuer, then three tool calls over TLS.
docker compose --profile agent run --rm agent
```

The issuer, the body and the agent run as `node` (uid 1000) and read the secret
and the CA through bind mounts. Docker Desktop on Windows and macOS lets them
read those files whoever owns them; on a Linux host the files must belong to
uid 1000. Without the two `chown` lines, run as root on an EC2 `t3.small`
(Ubuntu 24.04, Docker 29.1.3, Compose 2.40.3) on 26 October 2026, the issuer
and the agent stopped with `EACCES` on `/run/secrets/idp_client_secret`, the
body ignored `/ca/root.crt`, and nothing was recorded.

The agent prints what happened. With the shipped policy:

- `memory.put` and `memory.get` are allowed and the note is found;
- `message.send` is refused with `denied:no-rule:<decision id>`, and the
  refusal is a signed record like the others;
- a request to `https://verax.localhost/mcp` without a token gets `401`.

Then check the record:

```sh
docker compose exec body verax verify /var/lib/verax
```

It ends with `VERIFIED`: three decisions, three valid signatures, an unbroken
chain. That verifies against the key the records carry. To check against a key
you hold, copy `/var/lib/verax/keys/record.public.pem` out when the body is
first installed and pass it with `--key`.

`VERAX_IMAGE` selects the image (default `veraxai/verax:latest`), and
`VERAX_POLICY_FILE` a policy inside the container.

## Clean up

```sh
docker compose --profile agent down -v
```

`-v` removes the ledger volume with everything recorded in it.

## What this does not show

- A real identity provider, key rotation at the issuer, or scopes beyond the
  two the agent asks for (`verax:read verax:memory`).
- Anything outside this one host: the ledger, the keys and the CA all live in
  Docker volumes and directories on it. Someone with root on the host can stop
  the body or rewrite the state; see `docs/THREAT_MODEL.md`.
