# @verax-ai/anchor-service

A small Transparency Service that speaks the same `POST /register` route
`verax anchor` and `verax witness` already use. Callers present a bearer
token; the service appends the checkpoint hash to an RFC 9162 log and returns
a COSE receipt. The receipt shows that this checkpoint hash was registered by
the time of the receipt. It does not show that the ledger is complete, and
the operator still chooses what to send.

Private workspace package. Not published.

## Run

```sh
verax-anchor-service
```

Or from the workspace: `node --experimental-strip-types packages/anchor-service/src/cli.ts`.

## Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `VERAX_ANCHOR_SVC_TOKENS` | yes | JSON file mapping SHA-256 hex of a token to an owner id. The service never stores a token itself. |
| `VERAX_ANCHOR_SVC_SIGNING_KEY` | yes | Ed25519 private key PEM file used to sign receipts. |
| `VERAX_ANCHOR_SVC_STORE` | yes | Append-only JSONL path for log leaves (`leaf_hash`, `owner_id`, `at_ms`). One writer per store. |
| `VERAX_ANCHOR_SVC_PORT` | no | Listen port (default `8798`). Use `0` for an ephemeral port. |
| `VERAX_ANCHOR_SVC_HOST` | no | Listen host (default `127.0.0.1`). |
| `VERAX_ANCHOR_SVC_RATE` | no | Max authenticated registrations per owner per minute (default `60`). |

Missing or unreadable required values exit 64 with one sentence on stderr. A
second start on a store that is already held also exits 64, naming the store.

Only one running service holds a given store (exclusive lock beside the file
for the process life). A stale lock from a dead process is taken over. After
a failed store write every later `POST /register` answers `503`
`{"error":"store-unavailable"}` until the process is restarted. On start, a
torn last line (no terminating newline) is dropped and the file truncated to
the last full line, with one line on stderr.

Token file example:

```json
{
  "ab…64 hex digits…": "tenant-a"
}
```

where the key is `sha256(token)` as lowercase hex.

## Pinning the public key

Export the matching public key once and give it to callers:

```sh
# from the private key the service signs with
openssl pkey -in service.private.pem -pubout -out service.public.pem
```

Callers pass that file as `verax anchor … --service-key service.public.pem`
or `VERAX_ANCHOR_SERVICE_KEY`, and readers use
`verax verify --anchor-key service.public.pem`. A receipt is only meaningful
under the key the reader holds; the receipt itself names no key.

## Route

`POST /register` with `Content-Type: application/json` and
`Authorization: Bearer <token>`:

```json
{"capsule_id": "<64 lowercase hex>"}
```

Answer:

```json
{"receipt_b64":"…","entry_hash":"…","leaf_index":0,"tree_size":1}
```
