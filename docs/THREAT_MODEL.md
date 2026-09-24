# Threat model

A sketch of who is assumed hostile. Nothing here is measured.

## the brain is hostile

The MCP client is an untrusted program. It may send any tool name, any
arguments, any replay, and any social prompt. A grant is a signed
decision, not a mood. A refusal is recorded the same way. Prompt
injection through tool results is not filtered by policy; policy sees
tool name and scopes only.

## a brain with a shell

The brain is assumed to speak MCP only. An agent that also has a shell or
file tool running as the same OS user as the body can read the state
directory: the keys, the local issuer key, the policy and the ledger. It
can then mint tokens, edit the policy and rewrite the ledger with the
body's own keys. Local mode does not honour `verax:approve` or
`verax:audit` over HTTP, and `verax approve` asks for a terminal, but
neither is a boundary.

`verax install` puts the code and the state directory out of that shell's
reach on Windows and on Linux. The body runs as LocalService or as the
`verax` system user; the agent token is the only credential left in the
invoking user's profile. macOS is not covered yet. An administrator, or
root, is outside this model: they can change the ACL, the task, or the
unit. An elevated terminal the operator leaves open for the agent is also
outside it. Separate the body from other Windows services running as LOCAL SERVICE.

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
the directory. Coverage proof and a heartbeat belong in a later phase.
Until then this is a known gap: silence is indistinguishable from "nothing
happened" if the only copy lives on the same host.

The no-bypass scan is deliberately conservative: the character sequences `import(` and `require(` may not appear anywhere in packages/body, including strings and comments.

Exception: `src/desktop.ts` may import `node:child_process` to supervise the issuer, body, and panel. That file is still scanned for `import(`, `require(`, `eval`, and `tools/` imports.

Exception: `src/install.ts` may import `node:child_process` to install and remove the body under another account. That file is still scanned for `import(`, `require(`, `eval`, and `tools/` imports.

The directory lock detects an accidental second body on the same state directory. It is not a distributed lock: a lock is never taken over automatically; an operator removes a dead lock with `verax unlock`. A multi-process ledger belongs to the phase 4 witness process.

A spike stdio attach lives in `packages/body/src/downstream.ts` and starts a child through the SDK stdio transport. That source does not write the `child_process` name, so the scan names the transport itself. `listen()` does not open the attach. A tool that enters through `extraTools` still goes through `createProxy`.

Exception: `src/downstream.ts` may import the SDK stdio client transport (`client/stdio.js`) to start one downstream MCP server. The scan names that import, and the `StdioClientTransport` name, anywhere else in packages/body.

## retention and erasure

Append-only records conflict with a right to erase. Phase 1 payloads are
plaintext. A ledger-piece split lives in the tree. keep/move/drop of
closed pieces and their copies is designed in
`docs/design/ledger-rotation.md` and not applied. Payload encryption
and a right-to-erase path are still not designed.

## out of scope: OS compromise

Hermes Agent, SECURITY.md section 2.2 The Boundary: OS-Level Isolation:

> The only security boundary against an adversarial LLM is the operating
> system. Nothing inside the agent process constitutes containment — not
> the approval gate, not output redaction, not any pattern scanner, not
> any tool allowlist.

That sentence applies here. A process that already owns the host is
outside this model.
