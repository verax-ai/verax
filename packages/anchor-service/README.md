# @verax-ai/anchor-service

A small Transparency Service that speaks the same `POST /register` route
`verax anchor` and `verax witness` already use. Callers present a bearer
token; the service appends the checkpoint hash to an RFC 9162 log and returns
a COSE receipt. The receipt shows that this checkpoint hash was registered by
the time of the receipt. It does not show that the ledger is complete, and
the operator still chooses what to send.

Private workspace package. Not published.

## Deployment

Listen on loopback only, behind a TLS-terminating reverse proxy. The service
speaks plain HTTP and does not terminate TLS itself. The proxy must enforce
TLS to clients, limit request size and rate at the edge, and must not log the
`Authorization` header (or any bearer token). Run exactly one instance per
store on one host with one pid namespace and a local file system: the lock
file only distinguishes holders inside that deployment shape.

## Run

```sh
verax-anchor-service
```

Or from the workspace: `node --experimental-strip-types packages/anchor-service/src/cli.ts`.

## Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `VERAX_ANCHOR_SVC_TOKENS` | yes | JSON file mapping SHA-256 hex of a token to an owner id. The service never stores a token itself. Regular file only; not a symlink. On POSIX, mode must not grant group/other read or write. On Windows, the operator must restrict the ACL to the service account before start; the service refuses symlinks and non-files. |
| `VERAX_ANCHOR_SVC_SIGNING_KEY` | yes | Ed25519 private key PEM file used to sign receipts. Same path rules as the token map. |
| `VERAX_ANCHOR_SVC_STORE` | yes | Append-only JSONL path for log leaves. Each line is versioned with `index` and `prev` (SHA-256 of the previous line). Regular file only; not a symlink. One writer per store. |
| `VERAX_ANCHOR_SVC_PORT` | no | Listen port (default `8798`). Use `0` for an ephemeral port. |
| `VERAX_ANCHOR_SVC_HOST` | no | Listen host (default `127.0.0.1`). |
| `VERAX_ANCHOR_SVC_RATE` | no | Max authenticated registrations per owner per minute (default `60`). |
| `VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS` | no | Max time to receive request headers (default `10000`). |
| `VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS` | no | Max time for the whole request including body (default `30000`). |
| `VERAX_ANCHOR_SVC_KEEP_ALIVE_TIMEOUT_MS` | no | Idle keep-alive timeout (default `5000`). |
| `VERAX_ANCHOR_SVC_MAX_CONNECTIONS` | no | Max concurrent TCP connections (default `64`). |

Missing or unreadable required values exit 64 with one sentence on stderr. A
second start on a store that is already held also exits 64, naming the store.

Only one running service holds a given store (exclusive lock directory beside
the file for the process life). Under the one-host / one-pid-namespace /
local-filesystem deployment above, a quiet lock whose named process cannot
still be the writer is taken over by at most one waiter. The lock records pid,
start time, token and (on Linux) boot id; that is enough only inside that
deployment shape — a dead holder whose pid was reused in another pid namespace,
or a store on a volume shared across namespaces, is outside what the lock can
decide. A stale takeover uses a gate directory named
`<store>.lock.takeover`. If a process dies while holding that gate, later
starts refuse with a sentence that names the gate path. Before removing the
gate by hand, confirm no takeover is in progress (no other `verax-anchor-service`
on that store, and the gate's age is past any in-flight start). After a failed
store write, or after the process loses its lock, every later authenticated
`POST /register` answers `503` `{"error":"store-unavailable"}` until the
process is restarted (unknown tokens still get `401`, unknown routes `404`).
On start, a torn last line (no terminating newline) is dropped and the file
truncated to the last full line, with one line on stderr. A blank line that is not that torn tail, a repeated
`(owner_id, leaf_hash)`, a broken prev-hash chain, or an old unversioned store
refuses to start.

Durability: after each append the service `fsync`s the store file. After
creating a new store it also `fsync`s the file and, where the platform allows,
the parent directory. The service assumes a local file system that honors
`fsync` for durability of those writes; it does not claim durability on
network file systems or volumes that ignore flush.

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
