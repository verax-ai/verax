# Remote halt — design, not built

Status: design only. Nothing in this document is in the tree.

## What exists

- `POST /api/halt` already stops the body for any operator session (a token
  carrying `verax:audit` or `verax:approve`). Stopping is the safe
  direction, so it is never refused for its signature: an HTTP halt with the
  operator's passkey carries the assertion into the signed control record; a
  halt without one is still written and the answer says what was refused.
  Resuming needs `verax:approve` and, when a passkey is registered, the
  assertion.
- `verax watch --url https://host/healthz --token-file <path>` reads the
  heartbeat over audit `/healthz` and, on silence, reports and exits
  non-zero. It does not call `/api/halt`.
- Start rows are signed by the record key and chained (unreleased), so a
  restart and the gap before it can be read back and checked.

So the gap is not that a remote party has no way to halt. It is that the
remote watcher does not use it, and that a halt it sent would carry no
signature naming the watcher.

## Proposal

1. **Watcher key.** `verax watch --url ... --watcher-key <private.pem>` holds
   an Ed25519 key. The operator registers its public key in the state
   directory (`watchers.json`, written by `verax operator add-watcher
   <public.pem> --name <id>` from an operator shell), the same way
   operator credentials are registered. The body never holds the private
   key.
2. **Signed halt.** On silence the watcher sends `POST /api/halt` with its
   audit token and `{ watcher: { id, atMs, nonce, reason, sig } }`, where
   `sig` covers `verax-remote-halt-v1\n` + canonical `{ id, atMs, nonce,
   reason, action: "halt" }`. The body checks the signature against
   `watchers.json`, a clock window of 60 s, and that the nonce is unused
   (kept beside `halt-history.jsonl`). A valid one writes the halt with `by:
   "watcher:<id>"`, `via: "http"`, and the signed request goes into the
   control record exactly as a passkey assertion does today, so `verax
   verify` can check it later. An invalid one still halts (stopping is
   never refused), and the answer and the record say the signature was
   refused.
3. **No remote resume.** A watcher key can only stop. Resume stays with the
   operator: `verax:approve` and the passkey. A stolen watcher key can
   therefore stop the body, which is a denial of service the operator can
   undo, and nothing more.
4. **What silence means.** The watcher's trigger is a stale or missing
   heartbeat over `/healthz`. If the body is down, the halt cannot be
   delivered; the watcher reports that and retries each poll. Once it is
   delivered the switch persists across restarts, as every halt does.

## What this does not do

- It does not halt a body the watcher cannot reach. A host that is off or
  cut from the network is not stopped by anything sent to it. What remains
  is the record: the next signed start row names the gap, and with
  automatic anchoring the last checkpoint before the gap is held by a
  second party.
- It does not make the watcher independent of the operator. Whoever
  registers the watcher key chooses who can stop the body.
- It does not change the threat model for an administrator or root on the
  body's host: they can remove `watchers.json` or the switch. That is
  detected through the signed control records and anchors, not prevented.

## Tests it would need

- A watcher key not in `watchers.json` halts unsigned and the record says
  the signature was refused.
- A replayed nonce or an `atMs` outside the window is refused as a
  signature, not as a halt.
- `verax verify` checks the watcher signature on the control record and
  fails when it was changed.
- A watcher key cannot resume.
