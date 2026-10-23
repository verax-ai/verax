# Threat model

A sketch of who is assumed hostile. Nothing here is measured.

## the brain is hostile

The MCP client is an untrusted program. It may send any tool name, any
arguments, any replay, and any social prompt. A grant is a signed
decision, not a mood. A refusal is recorded the same way. Prompt
injection through tool results is not filtered by policy. Policy reads
arguments in two places, `spend` (currency, cap per call, payee list,
daily limit) and the recipient host of `message.send` (egress
allow-list); otherwise it sees tool name and scopes only.

## a brain with a shell

The brain is assumed to speak MCP only. An agent that also has a shell or
file tool running as the same OS user as the body can read the state
directory: the keys, the local issuer key, the policy and the ledger. It
can then mint tokens, edit the policy and rewrite the ledger with the
body's own keys. Local mode does not honour `verax:approve` or
`verax:audit` over HTTP, and `verax approve` asks for a terminal, but
neither is a boundary. With the operator door on (0.6.0), such a shell can
also add its own passkey to `operator-credentials.json` and approve through
the door: in local mode the door is not a boundary either.

Since 0.6.0 the operator door is a second listener, off unless the operator
names an origin for it, bound to loopback (`127.0.0.1:8788` unless moved),
with the TLS endpoint in front of it the operator's. A shell on the same
host reaches it like any local port. It cannot sign in, approve or resume
without an assertion from an enrolled passkey's authenticator, and it
cannot enrol without the pairing code `verax operator enroll` prints at the
machine; the pairing file holds only the code's hash. What it can do there
is spend an open code's five tries, so the operator asks for another, and
keep the door's 32 sign-in slots busy, which delays a sign-in. Whoever
terminates TLS in front of the door can read the summaries it serves.

`verax install` puts the code and the state directory out of that shell's
reach on Windows, Linux, and macOS. The body runs as the dedicated local
user `verax-svc` on Windows, as the `verax` system user on Linux, or as
the hidden `_verax` user on macOS. On Windows the agent token is
`%ProgramData%\Verax\agent-token\<SID>\agent.token`, owned by
Administrators, with read for the invoking user's SID. On Linux and macOS
the elevated install does not write, chown, or chmod anything under the
invoking user's home; a child with that user's uid and gid writes
`~/.verax/agent.token`. Elevated commands refuse to run when the verax
code they loaded can be changed by that user. On Windows the supported way
to approve is a passkey: through the operator door (0.6.0) when an origin
is named for it, or the panel. An elevated CLI `approve` stays as a
fallback and has to be run from a separate administrator account, not the
agent's own account elevated, because a same-user elevated shell inherits
that user's environment variables and PowerShell profile, which the agent
can set. Clear `NODE_OPTIONS` in that shell (`Remove-Item Env:NODE_OPTIONS`).
The code check does not see a preload that already ran. Start that other
account's copy from a PowerShell opened with `-NoProfile` (Run as
administrator). An administrator, or root, is outside this model: they can change the ACL,
the task, the unit, or the launch daemon. An elevated terminal the operator
leaves open for the agent is also outside it.

Outside the model means Verax does not prevent what they do. They can read
the keys, stop the body and the witness, and rewrite or delete the state
directory, and nothing on that host stops them. Because they can read the
keys, signatures do not help against them either: a rewritten ledger can be
signed again and verify. What can detect a rewrite is a copy they do not
control. `verax anchor` (0.4.3) registers each checkpoint's hash with a
Transparency Service someone else runs, and `verax verify --anchor-key`
checks the receipts: a history rewritten before the last anchored checkpoint
no longer matches the hash in that service's log, provided the reader asks
the service or holds a receipt from outside the directory. A rewrite after
the last anchor, and a body that was simply stopped, are not detected that
way. Since 0.5.0 the witness can anchor each checkpoint automatically, and
`verify --require-anchored` names a checkpoint with no receipt. Signed start
rows (also 0.5.0) are for someone who cannot read the record key; they
do not stop an administrator. Moving the key out of a file
(`docs/design/key-custody.md`, not built) would leave an administrator able
to use the key while on the host but not to copy it, and a KMS keeps its own
log of each signature.

`verax init --local` still writes a state directory the same user can
read. That is a way to try the body, not a boundary.

## the tool server is hostile

Code behind `inner` may lie, hang, or write outside the declared effect.
The decision record is the intent; the effect row is what came back.
Reconciliation exists to notice a mismatch, not to prevent the call.

A downstream child can also change a tool's description or schema after the
operator has looked at it, and the brain reads a description as
instructions. Since 0.6.0 the operator can pin a child's definitions; with
pins, a definition that is not the pinned one stops the body at its next
start. A pinned description can still carry an instruction: the operator
saw it when pinning. Tool results and error text are not pinned and reach
the brain on every call. Text a child sends that reaches the operator's
terminal (an error when it attaches, the pin listing) is written with
controls and the characters that draw nothing as escapes; in 0.5.1 an
error at attach reached the terminal of `verax serve` as it was.

## the operator is honest but forgetful

The person who wrote the policy text is not assumed malicious. They are
assumed to forget which rule was in force, which scope was granted, and
which call was denied. The ledger is for that person, not for an
auditor they do not have yet.

They can lose a phone that holds a passkey. Until someone at the machine
runs `verax operator remove`, the passkey's own user verification is what
stands between a finder and an approval. After the removal the body refuses
that passkey, and `verax verify` does not count an approval or a halt or
resume signed with it whose record comes after the removal record in the
ledger, while no record undoes the removal.

## the ledger can be silenced

An operator can skip the publisher, stop the witness process, or delete
the directory. A running body now pulses even while idle; start rows,
signed since 0.5.0, record the gap from the previous beat. `verax watch` can persist a
halt on silence on the same host, or report silence over audit `/healthz`.
The watcher runs wherever the operator puts it and shares that host's
trust. A remote watcher cannot halt the body. Silence is indistinguishable
from "nothing happened" if the only copy and watcher live on the same host
and that host stops or removes both. These local observations are not
independent evidence of uptime or of what happened during a gap.

Since 0.5.0: with `VERAX_ANCHOR_SERVICE` set, `verax witness` registers each
checkpoint it signs with a SCITT Transparency Service someone else runs and
keeps the receipt, and `verax verify --anchor-key <pem> --require-anchored`
names every checkpoint older than the grace that has no receipt verifying
under that key. The grace is counted from the end the checkpoint itself
states, so a checkpoint whose window ends more than a minute after the
reader's clock is named `checkpoint-window-in-future` instead of being left
to come due. This detects; it does not prevent. Whoever can write the
state directory can still stop the witness, roll the ledger back or delete
it. What changes is that a deleted receipt is named instead of passing, and
the service's log keeps the checkpoint hash after the local copy is gone.
Removing the newest checkpoint together with its receipt leaves nothing in
the directory to compare; only asking the service shows it, and `verify`
does not ask it yet. A witness that cannot reach the service writes
`anchor-failed` and keeps signing; the gap shows as unanchored checkpoints.

Since 0.5.0: start rows are signed by the record key and each names the
SHA-256 of the row before it. `verax verify` names a changed gap, a row
removed from the middle, or an unsigned row after a signed one. Rows removed
from the end leave nothing to compare, and anyone holding the record key can
write a valid row; the signature binds the row to the key, not to the truth
of the gap. An operator session can already stop the body with `POST
/api/halt`; `verax watch --url` does not call it, and a signed halt from a
remote watcher is designed in `docs/design/remote-halt.md`, not built.

The no-bypass scan is deliberately conservative: the character sequences `import(` and `require(` may not appear anywhere in packages/body, including strings and comments.

Exception: `src/desktop.ts` may import `node:child_process` to supervise the issuer, body, and panel. That file is still scanned for `import(`, `require(`, `eval`, and `tools/` imports.

Exception: `src/install.ts` may import `node:child_process` to install and remove the body under another account. That file is still scanned for `import(`, `require(`, `eval`, and `tools/` imports.

Exception: `src/watch.ts` may import `node:child_process` to run an operator-configured isolation command once per silence episode. It passes a parsed executable and argv with `shell: false`; heartbeat content is never command input. That file is still scanned for `import(`, `require(`, `eval`, and `tools/` imports.

The directory lock detects an accidental second body on the same state directory. It is not a distributed lock: a lock is never taken over automatically; an operator removes a dead lock with `verax unlock`. A multi-process ledger belongs to the phase 4 witness process. A live pid alone does not make a lock held (since 0.5.0): a lock that names this process but was written before it started, or that records another Linux boot id, is stale. That is the case of a container restarted on the same volume, where the body is PID 1 again. A held lock also beats (since 0.5.0): it is touched every 2 seconds, and the body, `verax unlock` and `verax doctor` call a lock held when they see it move, so a second container that shares the pid cannot have a running body's lock removed. A lock that stays still for five beats is then judged by its pid and start time, and is stale only when that says so too. A lock written by 0.4.8 or earlier does not beat and is judged by its pid alone.

The stdio attach in `packages/body/src/downstream.ts` starts a child through the SDK stdio transport. That source does not write the `child_process` name, so the scan names the transport itself. `listen()` opens it when `VERAX_DOWNSTREAM` names a document, and a stdio child opens only when the document says `"trust": "same-user"` (STATUS, Downstream MCP). A tool that enters through `extraTools` still goes through `createProxy`.

Exception: `src/downstream.ts` may import the SDK stdio client transport (`client/stdio.js`) to start one downstream MCP server. The scan names that import, and the `StdioClientTransport` name, anywhere else in packages/body.

## retention and erasure

Append-only records conflict with a right to erase. Phase 1 payloads are
plaintext. A ledger-piece split lives in the tree. keep/move/drop of
closed pieces and their copies is designed in
`docs/design/ledger-rotation.md` and not applied. Payload sealing and
erasure by destroying a per-subject key are designed in
`docs/design/erasure.md` and not built.

## memory at rest

`memory.get` serves an item only when the bytes on disk match the last signed
memory commit for that tenant and id. The commit file is `memory-commits.jsonl`
at the state directory root. Each line is `{payload, sig}`: the payload is
`{v, seq, tenantKey, id, revision, versionHash, objectPath, putRef, prevCommitHash, ts}`
and the signature is ed25519 over `canonical(payload)` with the record key.
The trust root is the public key in the keys directory (default
`<stateDir>/keys`; set `VERAX_KEYS_DIR` or `keysDir` to keep keys outside
state). A key written inside a commit line is not used. When keys live
inside the state directory, `VERAX_RECORD_PUBKEY_PIN` (the record
public key PEM; parsed and compared as SPKI DER) catches a key
substitution at start.

What this catches (BPM draft T1–T8; `tests/memory-integrity.test.ts` after a
stop, a plain-fs edit, and a start):

- T1 in-place body edit
- T2 newest version deleted (no fall-back to an older file)
- T3 a stored object deleted (not answered as never written)
- T4 two objects swapped between slots
- T5 a well-formed object with no commit
- T6 a genuine object from another tenant copied over this tenant's slot
- T7 an older genuine version written over the newest
- T8 `source` or other envelope metadata changed

### Hardened profile

When the record keys and the signed memory head live outside the state
directory (`VERAX_KEYS_DIR`; optional `VERAX_MEMORY_HEAD_DIR`, otherwise the
keys directory), a writer who can only change state cannot roll the body back
to an earlier commit tip. The head file is
`<headDir>/memory-head-<sha256(canonical stateDir) first 16 hex>.json`,
`{payload:{v:1, stateDirHash, seq, lastHash, ts}, sig}` with the same
ed25519 record signature as a commit line. `tests/memory-integrity.test.ts`
measures this as C1h (restart unchanged), T9h (whole state directory restored
to an earlier copy), and T2h (newest commit line and its object cut). C1h is
accepted; T9h and T2h are refused. `verax doctor` warns when the keys directory is still
inside state: a state-directory writer also holds the key, and this profile
does not apply.

- First use: a head is created on its own only while the commit chain is empty. When the chain has lines and no head exists (for example after the keys directory moved), memory stays closed until the operator runs verax memory rehead <stateDir>, which trusts the chain as it is at that moment.

When keys stay in `<stateDir>/keys`, the head is written there too. T9 and
cutting the newest commit then succeed: the attacker restores or rewrites the
head with the state. The local profile still records T9 as ACCEPTED.

What this does not catch:

- T9 restoring an earlier copy of the whole state directory, including
  `memory-commits.jsonl` and the keys, when the head is not outside state.
  The local profile records T9 as ACCEPTED. The hardened profile (keys and
  head outside) catches it; see T9h.
- An attacker who can write the state directory and also hold the record
  private key. Signatures then verify. Put the keys outside the state
  directory with `VERAX_KEYS_DIR` when the threat is "state yes, keys no".
- Cutting the newest lines off memory-commits.jsonl together with the objects
  they name, when the head is not outside state. Those ids then read as never
  written. The hardened profile catches it; see T2h.
- Availability: one damaged commit line makes every memory read answer memory-integrity-history-unavailable until the chain is repaired. This is deliberate (fail closed).

0.6.1 flat files `<id>.json` have no commit. `memory.get` answers
`memory-integrity-unattested`. The operator command `verax memory reattest
<stateDir>` (body stopped) writes each as revision 1, appends a commit,
updates the signed head, and prints the ids. The body does not reattest on
start.

### Upgrading from 0.6.1

1. With the body stopped, review the old memory contents.
2. Run `verax memory reattest <stateDir>` with the same key and head
   configuration the body will use.
3. Then start the body. The first read of an unre-attested legacy
   record stops the body. `verax resume <stateDir>` lifts the halt as
   the OS user who runs it; `POST /api/resume` asks for a passkey once
   an operator is registered.
4. If the body is already halted, reattest does not lift that halt.
   After reattest, a resume is still required.

On a detected memory integrity failure, Verax stops new gateway calls and
delivers a signed alarm to the configured webhook, retrying until the
receiver accepts it. The detecting `memory.get` still returns the
integrity code. A `_inputs` resolution that sees the same failure opens
the halt, and that call is answered `denied:halted` — the two paths are
not the same reply. The halt switch then refuses later calls. The alarm
is signed by the record key over `canonical(payload)` and is not a tool
an agent can invoke. An `http` webhook other than loopback (`127.0.0.1`,
`[::1]`, `localhost`) is refused at start.

Limits: an attacker who can write the machine can delete the `halted` file
and the alarm outbox; an independent external observer is a later stage
(P4). The alarm signature binds the event to the record key; if that key
is stolen it does not prove the event is truthful. Halt does not unwind a
tool call that has already started.

`audit.explain` still explains the decision record, not the current memory
file. That comparison is later work.

## out of scope: OS compromise

Hermes Agent, SECURITY.md section 2.2 The Boundary: OS-Level Isolation:

> The only security boundary against an adversarial LLM is the operating
> system. Nothing inside the agent process constitutes containment — not
> the approval gate, not output redaction, not any pattern scanner, not
> any tool allowlist.

That sentence applies here. A process that already owns the host is
outside this model.
