# Status

This file states what the tree carries and what stays unproven. A
paragraph here is not a release.

## Phase 0 — workspace skeleton

The tree carries a workspace skeleton: three package stubs
(`@verax-ai/proxy`, `@verax-ai/body`, `@verax-ai/panel`), CRLF and claim
guards, typecheck, and CI workflows that run `npm test` as a non-root
user on Ubuntu and as a smaller claim on Windows.

Nothing in those packages runs. There is no proxy, no MCP listener, no
panel, no signed record, and no ledger. Unproven until a later commit
adds a call path and a test that exercises it.

Known gap: the skeleton cannot refuse a tool call, because no gate
exists yet.
