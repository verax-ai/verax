# Threat model

A sketch of who is assumed hostile. Nothing here is measured.

## the brain is hostile

The MCP client is an untrusted program. It may send any tool name, any
arguments, any replay, and any social prompt. A grant is a signed
decision, not a mood. A refusal is recorded the same way.

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
the no-bypass scan is deliberately conservative: the character sequences `import(` and `require(` may not appear anywhere in packages/body, including strings and comments.

## retention and erasure

Append-only records conflict with a right to erase. Phase 1 payloads are
plaintext. Known gap, also in `STATUS.md`: payload encryption and
retention policy not designed.

## out of scope: OS compromise

Hermes Agent, SECURITY.md section 2.2 The Boundary: OS-Level Isolation:

> The only security boundary against an adversarial LLM is the operating
> system. Nothing inside the agent process constitutes containment — not
> the approval gate, not output redaction, not any pattern scanner, not
> any tool allowlist.

That sentence applies here. A process that already owns the host is
outside this model.
