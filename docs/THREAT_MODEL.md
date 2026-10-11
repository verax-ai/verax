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
neither is a boundary.

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
to approve is the panel with a passkey. An elevated CLI `approve` stays as a
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
way. Unreleased: the witness anchors each checkpoint automatically, and
`verify --require-anchored` names a checkpoint with no receipt. Signed start
rows (also unreleased) are for someone who cannot read the record key; they
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

## the operator is honest but forgetful

The person who wrote the policy text is not assumed malicious. They are
assumed to forget which rule was in force, which scope was granted, and
which call was denied. The ledger is for that person, not for an
auditor they do not have yet.

## the ledger can be silenced

An operator can skip the publisher, stop the witness process, or delete
the directory. A running body now pulses even while idle; unsigned start
rows record the gap from the previous beat. `verax watch` can persist a
halt on silence on the same host, or report silence over audit `/healthz`.
The watcher runs wherever the operator puts it and shares that host's
trust. A remote watcher cannot halt the body. Silence is indistinguishable
from "nothing happened" if the only copy and watcher live on the same host
and that host stops or removes both. These local observations are not
independent evidence of uptime or of what happened during a gap.

Unreleased: with `VERAX_ANCHOR_SERVICE` set, `verax witness` registers each
checkpoint it signs with a SCITT Transparency Service someone else runs and
keeps the receipt, and `verax verify --anchor-key <pem> --require-anchored`
names every checkpoint older than the grace that has no receipt verifying
under that key. This detects; it does not prevent. Whoever can write the
state directory can still stop the witness, roll the ledger back or delete
it. What changes is that a deleted receipt is named instead of passing, and
the service's log keeps the checkpoint hash after the local copy is gone.
Removing the newest checkpoint together with its receipt leaves nothing in
the directory to compare; only asking the service shows it, and `verify`
does not ask it yet. A witness that cannot reach the service writes
`anchor-failed` and keeps signing; the gap shows as unanchored checkpoints.

Unreleased: start rows are signed by the record key and each names the
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

The directory lock detects an accidental second body on the same state directory. It is not a distributed lock: a lock is never taken over automatically; an operator removes a dead lock with `verax unlock`. A multi-process ledger belongs to the phase 4 witness process. A live pid alone does not make a lock held (unreleased): a lock that names this process but was written before it started, or that records another Linux boot id, is stale. That is the case of a container restarted on the same volume, where the body is PID 1 again. A held lock also beats (unreleased): it is touched every 2 seconds, and the body, `verax unlock` and `verax doctor` call a lock held when they see it move and stale when it stays still for five beats, so a clock that stepped or a second container that shares the pid does not decide it. A lock written by 0.4.8 or earlier does not beat and is judged by its pid.

A spike stdio attach lives in `packages/body/src/downstream.ts` and starts a child through the SDK stdio transport. That source does not write the `child_process` name, so the scan names the transport itself. `listen()` does not open the attach. A tool that enters through `extraTools` still goes through `createProxy`.

Exception: `src/downstream.ts` may import the SDK stdio client transport (`client/stdio.js`) to start one downstream MCP server. The scan names that import, and the `StdioClientTransport` name, anywhere else in packages/body.

## retention and erasure

Append-only records conflict with a right to erase. Phase 1 payloads are
plaintext. A ledger-piece split lives in the tree. keep/move/drop of
closed pieces and their copies is designed in
`docs/design/ledger-rotation.md` and not applied. Payload sealing and
erasure by destroying a per-subject key are designed in
`docs/design/erasure.md` and not built.

## out of scope: OS compromise

Hermes Agent, SECURITY.md section 2.2 The Boundary: OS-Level Isolation:

> The only security boundary against an adversarial LLM is the operating
> system. Nothing inside the agent process constitutes containment — not
> the approval gate, not output redaction, not any pattern scanner, not
> any tool allowlist.

That sentence applies here. A process that already owns the host is
outside this model.
