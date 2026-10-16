# Status

This file states what the tree carries and what stays unproven. A
paragraph here is not a release.

The capability matrix below names a released version; unreleased additions
are stated separately before the historical record. Everything under
[Historical record](#historical-record) is dated: an entry describes the
commit that added it, not the tree today, and an early phase says things
that later phases replaced. Read the matrix first.

## Capability matrix — 0.6.0

Released on npm as `@verax-ai/body`, `@verax-ai/proxy` and
`@verax-ai/inventory` 0.6.0, and in the MCP registry as
`io.github.verax-ai/verax`. `Since` is the earliest published version
whose tree already carried that row's guard, read off the `v0.1.1` tag
and the `0.1.0` release commit, so a customer can tell a capability that
has shipped for three versions from one that landed in this one. `Guard`
names the test that fails when the row stops being true; the row states
what that test covers, not a wider claim.

| Capability | Since | What it does | What it does not do | Guard |
| --- | --- | --- | --- | --- |
| Policy gate | 0.1.0; unknown keys refused 0.5.0 | Every `tools/call` passes a fail-closed policy and leaves a signed decision record before anything runs. A refusal is recorded the same way as an allow. Since 0.5.0 a policy file that carries a key the parser does not know, or a `spend` block on a rule that is not the `spend` tool, does not load; a snapshot already on disk is still read. | Filter prompt injection. The policy reads arguments in two places: `spend` (currency, cap per call, payee list, daily limit) and the recipient host of `message.send` (egress allow-list). Otherwise it sees the tool name and the token's scopes, not the argument text or a tool result. | `policy-fixtures`, `deny-no-effect`, `policy-unknown-keys` |
| Effect record | 0.1.0 | A call that ran leaves an effect row bound to its decision by `effectHash`, including a call that threw. | Stop a tool server from writing outside the effect it declared. The row states what the body was told. | `effect-hash-contract`, `record-and-extract` |
| Operator approval | 0.1.0; one winner 0.1.2; signed HTTP approval 0.4.2; the operator door and the wider display class 0.6.0 | A call the policy holds becomes `defer`; `verax approve` on this machine, or the panel after a passkey sign-in (`POST /api/approve`, which needs `verax:approve`), resolves it. The launcher that opens that panel, `verax desktop`, is not released. On a released install a held call is approved with the CLI at the machine or, since 0.6.0, through the operator door from another device, which is off unless the operator names an origin for it (row *Operator door*). Either way the approver's operator id is bound into the record by hash. Since 0.1.2 four parallel approvals of one request leave one allow and the losers answer `already-resolved`. Since 0.4.2 an HTTP approval requires a passkey assertion when an operator is registered. The challenge is the SHA-256 of a canonical document bound to that defer record, so the assertion cannot be reused for another request. `verax verify` checks each signed approval again against the operator's public key without asking the body. A CLI approval stays unsigned. The panel button asks for a passkey assertion and posts it with the approval. `verax desktop` is still not released. A test produces an assertion with Chromium's virtual authenticator and checks it with the body's verifier. Since 0.6.0 the `verax approve` prompt writes every code point of `DISPLAY_ESCAPE_CLASS` in a held call as an escape: controls and format characters as before, and also the characters that draw nothing (variation selectors, default-ignorable code points, the braille blank, spaces other than U+0020), combining marks, and unassigned, private-use and surrogate code points. In 0.5.1 the prompt escaped only controls and format characters, so a held spend's `reference` could carry text the operator did not see; payee and amount were shown exactly, and the payee list is matched exactly. | Approve without an operator. There is no auto-approve path. A remote approval needs the operator door, an enrolled passkey and an assertion for that request. Sign a CLI approval. Refuse a held call for the characters it carries: the spend gate's refusal class is unchanged, and the prompt shows more without refusing anything new. Release `verax desktop`. Click the panel button in Chromium; the virtual-authenticator test signs on its own page. | `approval-queue`, `admission` (d), `operator-passkey`, `signed-approval`, `webauthn-browser`, `attack-r6` (R6-1b), `operator-door` |
| Operator door | 0.6.0 | A second listener for approving from another device, off unless `VERAX_OPERATOR_DOOR` names an origin: HTTPS, or `http://localhost` for a trial on the machine, a name and not an IP address. `verax install --operator-door <origin>` and `verax init --local --operator-door <origin>` write it, refusing at install an origin the body would refuse at start and a port that is taken. It binds loopback (`VERAX_OPERATOR_BIND`, default `127.0.0.1:8788`); the TLS endpoint in front of it is the operator's. It answers thirteen API routes (sign-in, sign-out, the waiting list, the approval and its challenge, halt and resume and their challenges, enrolment) and its own page (`GET /`, `/door.js`, `/door.css`), and `404` to everything else, `/mcp`, `/api/ledger` and `/healthz` included. Sign-in is a passkey assertion from a credential in `operator-credentials.json` over a challenge the door made for its own origin; a challenge is stateless, good once and for two minutes. A session is a random value the body keeps in memory for ten minutes, so a restart ends every session. A session does not approve: each approval needs an assertion over that request's challenge, and a resume needs one too; a halt is taken unsigned when the passkey does not answer. While no passkey is enrolled every API route but enrolment answers `403 no-operator`; the page loads, because the screen that takes a pairing code comes before anyone is enrolled. Enrolment takes a one-time pairing code from `verax operator enroll` at the machine: good for five minutes and one enrolment, five wrong tries across both enrolment routes end it, and every refusal is one answer, `pairing-refused`. Enrolment asks for no attestation and refuses one. The two listeners take none of each other's tokens. The door answers for its own name or its own loopback address, and refuses an `Origin` that is not its own, and a `POST` without one. Before anything is proved a body is at most 16 KiB, at most 32 are read at once, and one slower than five seconds is dropped; every answer closes its connection. The page loads only its own two files (`default-src 'none'`, `frame-ancestors 'none'`, Trusted Types), keeps the session in memory, writes every value as text, escapes the characters `verax approve` escapes, and lays an agent's text out left to right whatever its script. A held spend is listed with its payee, amount, currency and reference, read by the same function the CLI uses. Install end to end on Windows, Linux and macOS enrols a software passkey through the installed door, signs in and reads the waiting list. | Terminate TLS: the door speaks plain HTTP on loopback. Limit connections or request rate: that belongs at the operator's TLS endpoint, and a caller who keeps the 32 busy can delay a sign-in. Check what device holds a passkey: the pairing code is what vouches for it. Keep a pairing code open against a caller who can reach the door: one who keeps guessing can keep an enrolment from happening, and enrols nobody. Refresh the page by itself: the list is as old as the last request, and an approval for a request that has changed under its reference answers `409 stale`. Have the operator type the amount back, or refuse a spend whose amount cannot be read, as `verax approve` does: the page shows such an amount as unreadable. Hide the summaries from whoever terminates TLS. Protect against the administrator of the host. Reach a body that is off or cut from the network. The door has had code reviews; it has not had an independent attack round, and the page has been driven in Chromium with a virtual authenticator and has not been opened on a phone. | `operator-door`, `operator-door-page-browser`, `webauthn-registration`, `install-e2e`, `init-local` |
| Operator passkeys | 0.6.0 | `verax operator list --state <dir>` prints the enrolled passkeys in the order they were enrolled, each `in use` or `removed`; `verax operator remove --state <dir> --id <id>` takes one out of use. A removal files a mark under `operator-removed/`, named by the SHA-256 of the passkey's id, and deletes nothing: `verax verify` reads earlier approvals back under the public key the credentials file keeps. The body leaves a marked passkey out of the sign-in list, the session check on each request and the lookup behind an approval, so a session it opened ends at its next request. With every passkey removed the credentials file stays, so the body does not go back to approving without one; a new pairing code enrols the next. Removals made at the same moment all hold: each is its own file. The ledger keeps an account of the directory: a new mark becomes one signed deny `passkey-removed`, a mark taken away one `passkey-removal-undone` (subject `verax.operator`, effect class `verax.control`, an inputs row naming the mark), written when the body opens, on the next call that reaches the proxy, before an approval over HTTP, and on a halt or resume. `verax verify` follows that account in chain order: a signature on an approval or a halt or resume that a passkey made after the ledger recorded its removal is `signed-after-removal` and is not verified; one made before still verifies. | Write the record at the instant the command returns. Name who removed it: the record names the mark, and `by` is `unknown`. Say which device holds which passkey; the list gives only the order of enrolment. Stop a signature check that passed before a removal landed from writing its approval; `verify` names that approval. End a token of the development issuer (the panel behind the unreleased `verax desktop`) before it expires. Read a directory that cannot be listed as "no marks": it leaves no passkey in use until it is put right. | `operator-door` (D28–D30, D33, D34), `operator-cli`, `operator-removal-ledger`, `operator-removal-sync` |
| Tenant boundary | 0.1.0; read order fixed 0.1.2 | Memory and inbox live under `tenants/<tenantKey>/`, where the key is SHA-256 of `{ iss, sub }` plus a `tenant` or `org` claim when present. Another tenant's id is answered with a signed deny and no body. `_ref` keys are per tenant. Before 0.1.2 a `memory.get` looked at the foreign record first, so a second tenant writing the same id could hide the caller's own row. | Separate two customers on one host any further: same disk, same process, same operator. Unproven until two live customers share one body. | `tenant`, `concurrency-audit` (V-05) |
| Retry and idempotency | 0.1.0; re-evaluation 0.1.2; crash mark 0.1.3; throw replay 0.1.4 | Eight parallel calls carrying one `_ref` run the tool once and replay the rest. A retry is evaluated against the policy and scopes in force now, not the ones that held when the call was first approved. A run is marked on disk before the tool is called and the mark is removed once the effect is written, so a body that restarts mid-run answers `outcome-unknown` rather than running an approved call a second time. A replay whose recorded effect ends in `:threw` answers `threw:<ref>` with `isError: true`, so the wire says what the ledger says rather than `allowed:`. | Tell a run that reached the tool from one that crashed before it did anything: both answer `outcome-unknown`, so an approved call can end up never running and needing a fresh approval. Protect a ledger with no directory (`MemoryLedger`), where the mark cannot be written. Survive a disk that loses the mark. | `admission` (b), `concurrency-audit` (V-06), `crash-between-allow-and-effect` |
| Rate and daily bounds | 0.1.0; parallel-safe 0.1.2 | Rate and daily counters are taken inside the admission lock, so eight parallel calls under a limit of one write one allow. A counter that cannot be read fails closed. | Bound anything across processes or bodies. The counters are this body's. | `bounds`, `admission` (a), `concurrency-audit` (V-01) |
| Spend authorization | 0.1.0; budget re-check 0.1.2; scoped statement ref 0.4.5; raw statement ref 0.4.6 | `spend` is capped by payee, amount, currency and a daily limit, always defers, and re-checks the daily budget at approval time against today's approved total. The day is UTC unless the spend rule sets `dayOffsetMinutes` (integer, −720..840; 180 is UTC+3). Card CSV reconcile names matched, ghost and authorized-but-unpaid rows. Since 0.4.5 a statement `verax:` ref in the scoped form `<tenantKey>:<_ref>`, which a hold gets when the agent supplies its own `_ref` under a token with an issuer, tenant or org, is read whole; before, it was cut at the colon and the payment read as ghost. Since 0.4.6 a statement that carries the agent's own `_ref` (the form the agent is answered with) reaches that scoped hold when exactly one tenant holds the ref with an authorization; two or more are ghost `ref-ambiguous`. Before, such a row read as ghost and its payment stayed authorized-but-unpaid, while the same row with no ref matched. | Move money. The body records an authorization; a human or another system pays. | `spend`, `reconcile`, `reconcile-tenant-ref`, `concurrency-audit` (V-03) |
| Witness | 0.1.0; automatic anchoring 0.5.0 | `verax witness` is a second process holding its own key. When it answers, the effect row is `same-org` and a durable checkpoint is signed. When it does not, the class stays `self` and the fallback is recorded. Since 0.5.0, with `VERAX_ANCHOR_SERVICE` set, it registers each checkpoint with that transparency service after answering; a failed registration is an `anchor-failed` row, is retried with the next checkpoint, and does not delay the body. | Be a third-party witness. The second process runs on the same host under the same operator, so it is a separate key, not a separate trust domain. `third-party` and `regulated` are type values nothing writes. | `witness-process`, `auto-anchor` |
| Halt and revoke | 0.1.0; resume 0.4.1; signed control records 0.4.2; operator-signed resume and revocation records 0.4.4 | `verax halt` turns every further call into a signed deny. A revoked token id is refused before any record is written. Since 0.4.1 `verax resume` lifts a halt, and the panel's stop switch calls `POST /api/halt` (any operator session, `verax:audit` or `verax:approve`) and `POST /api/resume` (`verax:approve` only; the agent token carries neither). `GET /api/halt` answers whether the body is halted and who halted it. Who and when go to `halt-history.jsonl` beside the switch; the resume line is written before the halt is lifted, so a resume that cannot be recorded leaves the body halted. Since 0.4.2 each history line is also copied into the ledger as a control record (subject `verax.halt` or `verax.resume`, effect class `verax.control`) signed by the body's record key, when the body opens, after `POST /api/halt` or `POST /api/resume`, or on the next call. `verax verify` then reports each halt window and fails on any allow inside one other than these control records. The "who" in that record is what the history line names: the operator session over HTTP, the OS user for the CLI, `unknown` for a switch file made or removed by hand; a halt or resume that lands while the body is reading the switch and the history can also leave one such `via: "file"` record next to its own. Before 0.4.4 the operator does not sign it. A CLI halt is absent from the ledger until the body opens or the next call. The panel reaches an installed body only through `verax desktop`, which is not released, so on an install the switch is the CLI and these doors; since 0.6.0 the operator door, when an origin is named for it, serves the same halt and resume routes to a signed-in passkey (row *Operator door*). Since 0.4.4 a halt or resume over HTTP can carry the operator's passkey assertion. The challenge is the SHA-256 of a canonical document naming the action and the SHA-256 of the newest history line (`GET /api/halt/challenge`, `GET /api/resume/challenge`), so the assertion fits only the line appended after that tail. Once an operator is registered, `POST /api/resume` without a valid assertion is refused (`resume-signature-required`, `control-signature-invalid`) and nothing is written; the panel's resume button asks for the passkey. A halt is never refused for its signature: with none it stops unsigned, and with one that does not verify it stops unsigned and answers `signatureRefused`. The assertion is kept on the history line and copied into the control record, and `verax verify` checks it against the operator public key, requiring that its tail is the line hash of the control record before it and that each challenge is used once (`control signatures signed-verified · signed-failed · unsigned-http · cli · file`; `signed-failed` above zero is not verified). Also since 0.4.4, each change to `revoked-jti.jsonl` is copied into the ledger as a signed deny with subject `verax.revoke` and effect class `verax.control`: `token-revoked` for a jti that appeared, `revoke-removed` for one that is gone from the file, which lets that token in again. The development issuer's `POST /revoke` writes the revoking session's subject and the time on the line; a line without them is recorded as `unknown`, `via: "file"`. These records are denies, so a halt window is unchanged and a verifier from 0.4.3 reads them as ordinary denies. Like a CLI halt, a revocation reaches the ledger when the body opens, after the halt doors, or on the next call that reaches the proxy. | Reach a body it cannot see. Halt is a file on this state directory. Interrupt a tool call that is already running when the switch is pressed. Record a CLI halt or resume in the ledger at the instant the command returns, or carry the operator's own signature on it; `halt-history.jsonl` itself stays a plain append-only file. Make a halt wait for a passkey. Stop someone who can write the state directory from appending an unsigned line or removing a signed one; `verify` names lines as unsigned, it does not say one was required. Halt or resume over the main listener in local mode, where operator scopes are refused; the CLI does it there, and the operator door does when one is named. Record a revocation at the instant `POST /revoke` returns; a call made with the revoked token is refused before the proxy and does not sync. | `halt-cli`, `signed-halt`, `revoke-jti`, `signed-control`, `revoke-sync` |
| Egress allow-list | 0.1.0; mark required 0.5.0 | Under a rule marked `egress: true`, `message.send` reaches only hosts the policy names; an unlisted host is `egress-blocked` and a missing host is `egress-host-missing`. Up to 0.4.8 a `message.send` rule without the mark loads and its host is not checked; since 0.5.0 such a rule does not load, and neither does a host list no rule is marked for. | Restrict what a downstream tool server does once a call is allowed. | `egress`, `attack-r26-egress-unused` |
| Inputs document | 0.1.0 | A `_inputs` declaration is bound into the record by `inputsHash`, on deny as well as allow. `policy.requireInputs` makes a call with no declaration a signed `deny inputs-required`. | Require declarations by default: the flag is off on the shipped policy, so a call with no `_inputs` stores `inputs: []`. | `inputs-binding`, `require-inputs` |
| Ledger rotation | 0.1.2 | The ledger closes into pieces with a chain handoff, a persistent ref index rebuilt from the pieces when it falls short, and lifetime `/healthz` counts. A window that starts inside a piece seeks by timestamp. `/api/ledger` answers at most 5,000 rows, 1,000 when no limit is asked. | Answer an unbounded read. A reader that wants more pages back with `from` / `to`. `inputs.jsonl` rows carry no stamp, so a past window's inputs are still read from the end of a piece. | `ledger-rotation`, `ledger-window`, `jsonl-tail` |
| Portable verification | 0.1.4; approval signatures 0.4.2; inputs rows, checkpoint counts and anchors 0.4.3; every allow held to an effect row and third-party effect rows 0.4.4; non-object index lines named 0.4.5; unknown options refused, `--require-anchored` and `--require-signed-starts` 0.5.0; escaped output, start manifests and the removal order 0.6.0 | `verax verify <stateDir>` reads a ledger directory with no body running and nothing on the network, and states four things separately: how many signatures verify, whether the record chain is unbroken, whether each effect is bound to a decision, and **which key** answered. It also states the tail: every ref in `index.jsonl`, when that file exists, must still be a decision, and a signed checkpoint's covered count is held against the ledger; records after the newest checkpoint are named as not covered. Since 0.4.5 a line of `index.jsonl` that is JSON but not an object (`null`, an array, a number, a string) is named as `index line N is not a JSON object`; before, `null` ended the run with an exception and the others were skipped with nothing named. `--key` pins the record key the reader holds; `--effect-key` pins the effect key for `self` rows, and without it one key taken from the first `self` row is used for those rows. `same-org` rows are checked under the witness key: `--witness-key` when the reader pins one, otherwise one key taken from the first `same-org` row, and that line says agreement is not trust (`witnessTrust` in `--json`). Pinning `--effect-key` when any `same-org` row is present requires `--witness-key` too, and pinning `--witness-key` when any `self` row is present requires `--effect-key` too; otherwise verify does not pass. Every checkpoint row verifies under one witness key: `--checkpoint-key` when the reader pins one, otherwise one key taken from the checkpoint file, and the `prevCheckpointHash` chain is checked. The tail uses only checkpoints that verified. `--json` prints the same result for a pipeline; the exit code is 0 only when it verifies. Since 0.4.2 it also states approval signatures (`signed-verified`, `signed-failed`, `unsigned-http`, `cli`). An HTTP allow that carries an operator assertion is checked again against the operator public key, with user verification and the RP ID hash, and counts only when the allow is for the same request as the defer it resolves and is the first signed allow for that defer; `signed-failed` above zero is not verified. The origin each signature was made at is printed, not judged: the body checked it against the RP origins when it took the approval. The key is `operator-credentials.json` in the state directory unless `--operator-credentials` pins another file, and a key taken from the directory is named as agreement, not trust. A CLI approval is counted and stays unsigned. Since 0.4.3 each record that carries an `inputsHash` must find an inputs row under its ref whose canonical SHA-256 is that hash, and a missing or different row is not verified, because the approver of an approval lives in that row; an inputs row with no record is the crash case and is not named. For each checkpoint that verified, its head must be a record the ledger holds, and the verified records in its window up to that head must be its `receiptCount` ending at the head, with its allow, deny and defer totals, as the decision profile states; a record appended later with a time in the window is not counted. Approval signatures are read only from the inputs row whose hash the allow record signed, so an appended row cannot stand in for it. `test-vectors/` holds 20 frozen ledgers with the first failing stage of each negative, one of them (`valid-anchored`) with a receipt from the public capsule-anchor instance; `verax verify` 0.4.4 and 0.4.3 reach all 20; of the first 17, 0.4.2 reaches 15, missing the inputs and totals checks, and passes `valid-anchored` without reading its receipt. Since 0.4.3 `verax anchor <stateDir> --service <url>` registers each checkpoint with a SCITT Transparency Service someone else runs, sending only the checkpoint hash (`POST /register`), and keeps the RFC 9162 COSE Receipt in `checkpoint-anchors.jsonl`; `--service-key` refuses a receipt that does not verify. `verax verify --anchor-key <pem>` checks every receipt offline: it must name a checkpoint that verified, carry the leaf entry the route defines, and verify over the root its inclusion proof rebuilds. A receipt carries no key id, so without `--anchor-key` the receipts are counted and said to be unchecked. Since 0.4.4 every attested allow is held to an effect row without reading the unsigned `index.jsonl`: an allow with no row is `decision-without-effect`, and one within five minutes of the newest record is reported as `boundary-deferred`, a warning that does not change the verdict. Since 0.4.4 a `third-party` effect row, signed by a downstream server's own key, binds only under a key the reader pins with `--third-party-key` (repeatable); a key equal to the record, effect or witness key is refused, and the row's `resultHash` is not attested. A receipt produced by action-state-group/capsule-anchor verifies in the test suite, and the receipt code reaches the expected result on the in-scope scitt-cose `vectors-ietf126` vectors (`interop/`). Since 0.5.0 an option `verify` does not know is refused instead of dropped, `--require-anchored` names a checkpoint past its grace with no receipt that verifies, and `--require-signed-starts` names a start row that is not signed. Since 0.6.0 every printed line writes the code points of `DISPLAY_ESCAPE_CLASS` that a ledger carries as escapes, each line on its own, so text from the ledger (a ref in the unsigned `index.jsonl`, a prefix in a start row) cannot clear the screen, set the window title or start a line of its own; `--json` stays JSON that parses to the same values. In 0.5.1 a ref placed in `index.jsonl` reached the terminal raw, and one with line breaks printed a `VERIFIED` line above the real `NOT VERIFIED`. Since 0.6.0 each signed start row's downstream manifests are checked (row *Downstream MCP*), and an approval or control signature a passkey made after the ledger recorded its removal is `signed-after-removal` and not verified (row *Operator passkeys*). | Say that a key deserves trust. Checking against the key carried in the records proves the files agree with each other, not that the key was ever yours — the answer says so every time rather than hiding it behind a flag. Notice a ledger that was deleted rather than altered: absence is not a chain break, and a directory with no ledger answers `NOT VERIFIED` rather than passing quietly. Someone who can rewrite the files can roll the checkpoint file back to an older valid prefix together with the records after it; only a checkpoint held elsewhere (published, the witness's own copy, or a Transparency Service's log) detects that; an anchor receipt kept in the same directory can be removed with the checkpoint, and `verify` does not ask the service. Accept an unsigned duplicate-effect row: ledgers written by 0.3.x contain unsigned duplicate-effect rows, and `verify` from this version reports them as unsigned. | `verify-ledger`, `verify-cli`, `signed-approval`, `verify-inputs-totals`, `test-vectors`, `anchor`, `decision-without-effect`, `third-party-effect`, `index-null-line`, `auto-anchor`, `attack-r26-verify-unknown-flag`, `attack-r26-unsigned-starts`, `verify-foreign-text`, `downstream-pins-record` |
| Disk-low refusal | 0.1.0; one answer 0.5.0 | When a deny cannot be appended, the call is refused with HTTP 507 and a `disk_deny_unrecorded` metric, rather than running unrecorded. Since 0.5.0 the 507 is the only write on that response and the connection stays open. | Free disk or rotate for you. | `disk-unrecorded`, `disk-unrecorded-one-answer` |
| Panel | not published | A private app that reads one body's signed ledger: records, black box and status, over a code-flow session whose token stays in memory. The status tab names the products attached behind the gate — prefix, transport and tool count — or says none are; a body too old to answer leaves the section undrawn rather than claiming none. A build of it on sample data is served at `verax-ai.com/panel/?demo=1`; it has no body behind it, asks none for anything, and its `BUILD.json` names the commit it was built from. | Read several bodies. A fleet view is designed in `docs/design/fleet.md` and is not implemented. The published sample is not a deployment and carries no customer ledger; because it has no body, its status tab shows the roster sentence rather than the agents table. | `apps/panel` suite |
| Downstream MCP | 0.1.3; hostile-child bounds 0.1.4; stdio trust ack 0.2.0; `tools` list, message bound and no child schema run 0.5.0; pinned definitions and an escaped start refusal 0.6.0 | `VERAX_DOWNSTREAM` names a document of child MCP servers, each reached either by `command` (stdio, the body spawns it) or by `url` (Streamable HTTP, already running), never both. `listen()` attaches them before the door opens, HTTP `tools/list` publishes their tools as `prefix.childName` carrying the child's own description and schema, and a forwarded call passes the same gate and leaves the same signed decision and effect row under that name. Attach is bounded: the connect and the tool list carry the same timeout as a call, at most 256 tools of at most 64 KiB each are accepted, and a redirect is refused so a child cannot send the body to a host its operator never wrote. Driven against a live Conarium over HTTP: four of its tools appeared behind the gate, one with a rule ran and wrote an effect row, one without a rule was denied `no-rule` and never reached the child. A stdio child does not open unless the document says `"trust": "same-user"`; `verax doctor` names each stdio child. Since 0.5.0 the document may name the child tools to attach (`tools`), one message from a child is at most 10 MiB and a larger one detaches the child (`downstream-message-too-large`), and the body runs no schema a child sends. Since 0.6.0 a spec may carry `pins: "sha256:<digest>"`, naming a manifest `definitions/<digest>.json` beside the document that holds each tool entry as the body parses it. With pins the body checks that the manifest's bytes hash to the digest, that its prefix and selection are the spec's, and that every tool the child lists now has the pinned definition; a tool added, dropped or changed, or a manifest missing, edited or made for another prefix, stops the start with its own code (`downstream-definition-changed`, `downstream-tool-unpinned`, `downstream-tool-missing`, `downstream-manifest-mismatch` and others). The manifest is copied into the state directory before the signed start row is written, and that row names each child's manifest; `verax verify` checks each named manifest is there, hashes to its name and belongs to the row's prefix, and prints which definitions each start ran with. `verax downstream pin --file <doc> --prefix <p>` lists the child once, prints every entry in full with the characters that draw nothing written as escapes, writes the manifest of exactly what it printed after the operator types `yes`, and prints the `pins` line to add; it never edits the document and refuses to start a stdio child from an elevated account. `verax doctor` names a child with no pins, and an `npx` or `uvx` command whose package has no exact version. The downstream part of the tool list is sorted by name and each republished schema has its keys sorted. Since 0.6.0 a start the downstream document stops is one line on stderr, the child's own text in it written as escapes, and exit 78; before, the child's error text reached the terminal raw through Node's uncaught-exception printer, with a stack trace (0.5.1). A document that cannot be read is `downstream-document-unreadable`. | Read a pinned description for meaning: a pinned definition can still carry an instruction, which the operator saw when pinning. Cover tool results and error text: they reach the brain on every call. Follow `notifications/tools/list_changed`: a change is seen at the next start. Protect a document the agent can write (THREAT_MODEL, a brain with a shell). Refuse only the child whose definitions changed: a change stops the whole start, as every attach error does. Merge anything: the child stays its own server in its own process. Match a rule by wildcard: a policy rule names the prefixed tool exactly. Come up half-attached: a child the document names but cannot open stops the body. Refresh a child's tool list while running, or attach one after start. Treat the child's URL as an egress host: egress is for destinations the brain picks, and this one is the operator's document. Publish a child's address: `/healthz` names the prefix, the transport and the tool names to an operator session and nothing else, because a URL can carry the child's token. Mark which ledger rows came from a child — the prefixed subject is the only signal. Isolate a stdio child from the body's keys. The ack does not close that bound; it only writes the operator's acceptance into the document. | `downstream`, `downstream-served`, `downstream-http`, `downstream-visible`, `downstream-trust`, `downstream-tools`, `attack-r26-child-message-bound`, `attack-r26-child-output-schema`, `downstream-pins`, `downstream-pins-record`, `downstream-pins-cli`, `downstream-pins-hardening`, `downstream-pin-backslash`, `stderr-foreign-text`, `apps/panel` suite |
| Local issuer | 0.3.0; under an `npm install -g` layout 0.4.8 | `VERAX_JWKS_FILE` points at a JWKS file the body reads once at start, and only on a loopback bind. `verax init --local` writes one ES256 key, one agent token that can read and write memory, and `verax.env`, and `verax serve --env-file` loads that file before the body listens. | Be an authorization server: one key, one agent token, one machine, no refresh, no login. A leaked token file is a working credential until it expires or is revoked with the existing jti revoke. Hold against an agent that has a shell as the same OS user; see THREAT_MODEL, a brain with a shell. | `init-local`, `jwks-file` |
| Demo | 0.2.1; with Conarium 0.2.2; under an `npm install -g` layout 0.4.8; the amount question printed 0.5.1 | `verax demo` starts a loopback body with a temporary ledger, records an allow, a signed refuse and a held spend through the real `/mcp` path, and can leave the directory for `verax verify`. In a terminal it asks whether to approve the spend and, after `y`, for the amount; from 0.4.0 to 0.5.0 it read that amount without printing the question, so `y` followed by Enter ended in `approve-amount-mismatch`. `--with-conarium` (0.2.2) has `npx` download `@conarium-ai/core` and run it as a child: the gate allows `conarium.query`, Conarium masks the customer rows or refuses `public.secrets`, and a downstream tool with no rule is refused before the child sees the call. | Show a real database: the rows are Conarium's samples. Run `--with-conarium` with no network. Verify Conarium's own audit chain. Reconcile a card statement (needs a real statement). | `demo`, `demo-conarium` |
| Isolated install | 0.4.0 | `verax install` (elevated) refuses a Node that a standard user can change (on macOS the remedy extracts the official tarball as root into `/opt/verax-node`, root:wheel and not group- or other-writable; on Linux the same place, root:root, which SELinux labels `usr_t`), installs `@verax-ai/body` from the npm registry into an administrator-owned directory after `npm audit signatures`, writes `MANIFEST.sha256` from those bytes, puts the state directory under the dedicated local user `verax-svc` on Windows, the `verax` system user on Linux, or the hidden `_verax` user on macOS, writes the agent token only in the invoking user's profile, and registers an autostart task, systemd unit, or launch daemon that runs that Node. `verax doctor` reports the code directory, a `MANIFEST.sha256` mismatch by file name, a state ACL or mode that is wider than that account, an owner other than Administrators or SYSTEM on Windows or other than the service account on Linux and macOS, and whether autostart is present. `verax approve` with no state directory uses that installed state when it exists. A state directory the process cannot read exits 77 instead of a stack trace. After a crash the ledger lock is stale and is never taken over automatically (THREAT_MODEL, directory lock). The service's restart attempts fail with `ledger-locked-stale` until an administrator runs `verax unlock <stateDir>`. On SELinux systems install requires Node labelled `bin_t` or `usr_t` (distribution Node is; a tarball under `/usr/local/lib` is not) and prints the one-line fix; the service then runs in `unconfined_service_t`; isolation is the service account and file permissions. Since 0.4.1 every `node_modules` directory on a module search path of npm or the installed body (each ancestor up to the drive root, for example a user-made `C:\node_modules`) is judged as an object when it exists, and so is `Program Files\WindowsPowerShell\Modules`, which PowerShell 5.1 puts in front of the pinned `PSModulePath`; the elevated CLI's code list carries the same ancestors, and an elevated command refuses a set `NODE_PATH`. `scripts/optional-require-guard.mjs` fails when a production package try-requires a name the shipped tree does not contain, outside a reviewed list whose packages the body is checked not to load. Since 0.4.2, on macOS and Linux, a path these checks judge is also refused when an extended ACL lets a user other than its owner, root or (macOS) the admin group write it: one `ls -lde` on macOS, and on Linux `ls -ld` then `getfacl` for paths that show `+`; the refusal names the writer. On Linux a path that shows `+` when `getfacl` cannot be run is refused (install acl or remove the ACL). The same check runs for the desktop directory and the code it launches. Since 0.6.0 `verax install --operator-door <origin>` turns the operator door on for the service (row *Operator door*). Since 0.6.0 a stderr that cannot be written no longer stops the body: launchd gives the installed body a file for stderr, and on a disk that stops taking writes the failure arrived as a stream error that ended the process on its first line; the line is lost and the body keeps answering. An error the CLI does not expect is written as its name and message and its stack frames, escaped, and exits 1 (a downstream start refusal exits 78); the process ends by itself, or after three seconds if a listener it opened is still up. | Protect against an administrator or root. Keep a line a full disk refused: it is dropped. Cover `verax demo`, which starts its body without `main()`. Read a macOS deny entry as a reason to refuse; deny entries are ignored. Stop the operator's own elevated terminal from being driven by the agent if the operator leaves an elevated shell open to it. Close the gap between the check and the load: a user can create `C:\node_modules` after the check; what keeps a planted module from loading is the guard, not the check. | `install`, `install-e2e`, `module-search-trust`, `optional-require-guard`, `attack-r25-acl`, `stderr-unwritable`, `stderr-foreign-text` |
| Heartbeat and watch | 0.4.7; signed start rows 0.5.0 | The running body rewrites `heartbeat.json` every 10 seconds, idle included, and appends a `start` row naming the gap since the last beat, unsigned up to 0.4.8 and signed by the record key since 0.5.0. `verax watch <stateDir>` treats an absent, stale or future beat as silence and by default halts the body through the existing halt switch. | Attest uptime or a measured outage; tell silence from nothing happened when one host stops both the only copy and its watcher; tell a start row whose signature was taken off from one written before signing, unless the reader passes `--require-signed-starts`; halt from a remote watcher. | `heartbeat-watch`, `watch-exec`, `signed-starts` |
| Ledger lock | 0.5.0 | A held lock is touched every 2 seconds and records that beat. The body, `verax unlock` and `verax doctor` watch a lock for five beats: one that moves is held, whatever pid it names; one that does not is judged by its pid and start time, so the lock a restarted container left under PID 1 is stale instead of held. A still lock under a live pid is `lock-not-beating` and only `verax unlock --force` removes it. | Decide in under about 10 seconds that a lock is stale. Keep a body frozen for longer than five beats from losing its lock to an operator in another container. Cover the witness's listen file or the unreleased desktop launcher. | `stale-lock-pid-reuse`, `attack-r26-lock-ownership` |
| Key custody check | 0.5.0 | `verax doctor` opens the record key as the user who runs it. When that works and the session is not elevated, or when it is refused but that user owns the file, `key-custody` fails: an agent running as that user can sign records as the body. | Move the key out of a file. Judge an elevated session, which is outside the model. Tell apart an owner whose rights an OWNER RIGHTS entry narrowed. | `key-custody-doctor`, `attack-r26-key-custody-owner` |

What stays unproven for every row above: none of it has run against a
paying customer's production traffic. The pilot drills in
`tests/pilot-drills.test.ts` are tests, not a live body.

## Heartbeat and watch — since 0.4.7

The running body atomically rewrites `heartbeat.json` every 10 seconds,
including while idle. `VERAX_HEARTBEAT_EVERY_MS` sets the interval (minimum
1,000 ms). Rows also pulse it; `atMs`, `pid`, `lastDecisionN` and
`lastEffectN` remain, with `startedAtMs` and `beat: "timer" | "row"` added.
The timer is unref'd, stops on shutdown, and writes no ledger rows.
`verax doctor` treats a stale pulse as a stopped body or an unavailable
pulse, rather than an idle ledger.

Before startup control records or the first pulse overwrite the previous
beat, the body appends one `action: "start"` row to `starts.jsonl`, naming
`atMs`, `prevBeatAtMs`, `gapMs` and `pid`. With no readable previous beat,
both previous-beat and gap are null. `verax verify <stateDir>` reads these
rows with no body running and reports their count, largest gap and each
start with a missing previous beat (`starts` in `--json`). These rows are
unsigned in v1, separate from the signed halt control history; the summary
does not verify their authenticity. A gap is time since the last observed
beat, not a measured outage, and wall-clock changes can affect it.

`verax watch <stateDir> [--max-silence 30s] [--once]` checks the heartbeat.
An absent or unreadable beat, a beat older than the threshold, or one more
than 60 seconds in the future is silence. The default `--on-silence halt`
uses the existing halt switch and history (`by: "verax-watch"`, `via: "cli"`),
so subsequent calls are signed denies and a restart stays halted. Recovery
reports do not resume the body; the existing operator resume path applies,
including the required passkey assertion for HTTP resume when registered.
CLI resume retains its existing unsigned OS-user semantics.

`verax watch --url https://host/healthz --token-file <path> [...]` reads
`heartbeat.atMs` with an audit token from a file, never from argv. HTTPS
is required except on loopback; redirects are refused. A remote watcher
cannot halt the body: default silence handling reports it and exits
non-zero. Remote halt is out of scope.

`--on-silence exec --exec "<command>"` instead runs an operator-configured
command once per silence episode, with the reason in `VERAX_WATCH_REASON`.
It splits quoted executable/arguments and spawns with `shell: false`;
there is no shell expansion, pipe or redirect interpretation. Use an
executable script runner (for example `powershell.exe -File ...` on Windows)
for a site's own network isolation script. Command stdout is discarded so
watch stdout remains JSON lines. Failed commands are reported, and are not
retried until a recovery and a new silence episode.

`--once` exits 0 live, 3 silent and 2 on usage errors. Otherwise it polls
every `max-silence/3`, printing one JSON line for each silence episode and
each recovery. The watcher runs where the operator puts it; on the same
host it shares the operator's trust. It is not an installed external service.
Silence on a single-host ledger still cannot be told from nothing happened
if that host removes or stops both the only copy and its watcher. Start
rows are unsigned in v1; a remote watcher cannot halt. No uptime or gap
activity is attested by these observations.

Guards: `heartbeat-watch`, `watch-exec`; published in 0.4.7 and listed in the matrix.

## A child's output schema is not run — since 0.5.0

Until this change the MCP client the body uses compiled every `outputSchema`
a child listed and ran it on the child's own result, inside the body. A
backtracking `pattern` in such a schema held the body's event loop past the
call's timeout: 7.9 seconds at 31 characters, about twice that for each
further character (R26, measured with SDK 1.32.1). The body now sends
`tools/list` and `tools/call` as plain requests and runs no schema a child
sends. It does not republish `outputSchema`, before or after.

## One message from a child is bounded — since 0.5.0

The bounds on a child's tools were applied after its answer had been read
and parsed, and a `tools/call` answer had none. Measured with SDK 1.32.1: an
HTTP child that answered `tools/call` with 50 MiB was accepted whole, and a
50 MiB `tools/list` was read whole before `downstream-tool-too-large`
refused it. A stdio child was already cut at the MCP client's own 10 MiB
read buffer, with no name for it (`Connection closed`). One message from a
child is now at most 10 MiB on either transport: a line on stdio, an HTTP
response body, or one event of an event stream. A larger one is counted as
it arrives and refused at the bound: the attach stops with
`downstream-message-too-large:<prefix>`, a call answers
`downstream-call-failed:<prefix>.<tool>:downstream-message-too-large`. The
child is then detached: its session is closed, calls waiting on it end at
once, and later calls answer the same without reaching it until the body
restarts. A whole `tools/list` answer is one message, so a child whose list
is over 10 MiB does not attach, whatever its `tools` selection. The bound
is not configurable. The count restarts at an empty line only for a
successful answer whose media type is exactly `text/event-stream`; an error
answer, and a JSON answer whose content type merely mentions that name, are
read whole by the client and counted whole. An event stream that ends its
lines with a bare CR is counted as one message.

Guard: `attack-r26-child-message-bound`. Published in 0.5.0.

## Downstream tools list — since 0.5.0

A downstream entry may carry `tools`, a list of the child's own tool names.
Only those are attached: they enter the registry, appear on `tools/list` as
`prefix.childName` and are held to the 64 KiB bound. The rest of the child's
list is not attached and not held to that bound. The whole list is still
read against the MCP tool shape first, so an entry that is not a well-formed
tool stops the attach even when it is not selected; and a field that shape
does not know is dropped before the 64 KiB count and is not kept. A name
the child does not offer
stops the attach with `downstream-tool-missing:<prefix>.<name>`, as any
half-attach does. A list that is empty, longer than 256, repeats a name or
holds a name outside the child-name pattern is `downstream-tools-invalid`.
Without `tools` the attach is unchanged.

The list is how an operator puts a large child behind the gate for the few
tools it writes rules for. Driven against REA (`rea-agents` 6.3.0, 139 tools,
one advertising 87 KB) on 11 October 2026: without a list the attach stopped
at `downstream-tool-too-large:rea.compare_web_captures`. With
`["analyze_javascript_application", "capture_process_scenario"]` and one
rule for the first, `tools/list` showed those two. The static analysis ran
and left an allow and an effect row. The process capture, which asked to run
`/bin/sh`, was refused `denied:no-rule` and REA never saw it. `verax verify`
reported every signature valid.

Not done: the list is not a rule. A listed tool still needs a policy rule
to run, and the list does not narrow a tool's arguments.

Guards: `downstream-tools`; published in 0.5.0.

## Stale lock after a container restart — since 0.5.0

A container restarted on the same volume runs the body as PID 1 again,
and the lock its last run left names PID 1. Up to 0.4.8 that pid counted
as alive, so the body refused with `ledger-locked:1` rather than
`ledger-locked-stale`, and `verax unlock` run in a new container (also PID
1) answered `still-running:1`; the lock could only be deleted by hand.
Measured on `veraxai/verax:0.4.7`. A lock is now held only when its pid is
alive, it does not name this process with a start time before this
process started, and, on Linux, it does not record a different boot id
(written into the lock from `/proc/sys/kernel/random/boot_id`). The body
then refuses with `ledger-locked-stale:1` and `verax unlock` removes the
lock; measured in a container built from this tree. The same rule judges
the witness's listen file and the doctor and desktop checks. A lock is
still never taken over automatically.

That rule read a pid and a wall clock, and two states defeated it (R26):
a lock naming this pid with a start time in the future, left behind when
the clock stepped back between runs, was read as this process's own; and
two containers on one volume, both running the body as PID 1, each read
the other's lock as its own leftover, so `verax unlock` in the second
removed the lock of the running first. A held lock is now touched every
2 seconds and records that beat (`beatMs`) in the lock file. The body,
`verax unlock` and `verax doctor` watch such a lock for five beats: a
lock that moves is held, whatever pid it names. No time is compared,
only a change. Stillness alone does not make a lock stale, because a
live body can miss its beats while a long synchronous call holds it: a
lock that does not move is then judged by its pid and start time as
before, and is stale only when that says so too. Deciding that a lock is
stale therefore takes about 10 seconds; a live one is seen within a
beat. A lock from 0.4.8 or earlier records no beat and is judged by its
pid alone. In both cases a start time that is not a finite number does
not count as a live holder, and neither does a lock that names this
process's own pid with a start time that has not come yet. A lock that
names another live pid is held whatever start time it states: after a
clock step backwards a running body's lock reads as written in the
future, and calling it stale would let `verax unlock` take it. Does not:
protect a body in another container that is frozen for longer than five
beats while an operator there runs `verax unlock` under a pid that reads
as dead or as the caller's own; that body loses the lock and its next
append stops with `ledger-lost-lock`. Does not: tell a frozen body from
a dead one whose pid another live process now has. Such a lock is still
under a live pid; `verax unlock` refuses it as `still-running` and names
it `lock-not-beating`, `verax doctor` warns, and `verax unlock --force`
removes it with `reason: "not-beating"` in `unlocks.jsonl`. `--force`
does not remove a lock that moves. The witness's listen file and the
unreleased desktop launcher do not use the beat.

Guard: `stale-lock-pid-reuse`. Published in 0.5.0.

## Automatic anchoring — since 0.5.0

`verax witness` reads `VERAX_ANCHOR_SERVICE` (https; http only on a
loopback address) and, optionally, `VERAX_ANCHOR_SERVICE_KEY` (a file
holding the service's public key) once at start. A value that is set but
unusable stops the witness with exit 64 rather than letting it run without
anchoring. After it answers a checkpoint request, the witness registers every
checkpoint in the directory not yet anchored at that service, the same
`POST /register` with the checkpoint hash and nothing else that `verax
anchor` sends, and appends the receipt to `checkpoint-anchors.jsonl`. With
the key, a receipt that does not verify is not kept. Registrations run one at
a time and never before the answer, so a slow or absent service does not
delay the body. A failure is an `anchor-failed` row in `witness-status.jsonl`
and is retried with the next checkpoint. `witness.listen.json` names the
service, and `verax doctor` reports what the running witness was started
with: anchoring, not anchoring, or checkpoints still pending with the last
failure. `/healthz` reads the witness class from the last signed or fallback
row, past checkpoint and anchor rows.

`verax verify --anchor-key <pem> --require-anchored [--anchor-grace-ms N]`
names `checkpoint-not-anchored <hash>` for every verified checkpoint whose
window ended more than the grace ago (default ten minutes) and has no
receipt verifying under that key, so a receipt deleted from the directory no
longer passes quietly. `--require-anchored` without `--anchor-key` does not
verify.

This detects; it does not prevent. Someone who can write the directory can
still stop the witness or remove the newest checkpoint together with its
receipt; that leaves nothing local to compare, and `verify` does not ask the
service. The witness is started by the operator, so the variable comes from
wherever the operator starts it; `verax install` does not start a witness.

Guard: `auto-anchor`. Published in 0.5.0.

## Signed start rows — since 0.5.0

A body started by `verax serve` writes v2 start rows: the v1 fields plus
`v: 2`, `prevStartHash` (SHA-256 of the previous line in `starts.jsonl`, or
null) and `sig`, an Ed25519 signature by the record key over
`verax-start-v2` and a newline followed by the canonical row without `sig`.
`verax verify` checks them under the pinned `--key`, else the key the
records carry, and says which. A signature that does not verify, a
`prevStartHash` that is not the line before, or an unsigned row after a
signed one is a problem, and the ledger does not verify. So is a row that
carries `v`, `sig` or `prevStartHash` and is not a well-formed v2 row,
a line that no longer parses included: it is named `signed start row is
malformed`. Any other line that is not a start row is a problem as well
(`starts.jsonl line N is not a start row`): every line of the file is a row
the body wrote, and telling a tampered signed row from other damage by the
fields it still shows is a guess the writer of the file can defeat. Up to
0.4.8 such a line was a warning and the ledger verified. A line of spaces
is such a line. A signed row is accepted in one spelling, the one the body
writes: a line that parses to the same row through a second copy of a key,
padding or an escape is a problem, and so is a signature spelled with
characters base64 skips. A `starts.jsonl` that is there and cannot be read
is a problem; only a file that is not there is nothing. Unsigned rows
before the first signed one, written by an earlier version, are counted
and named as unsigned. With no records and no `--key`, signed rows are
counted and not checked. `starts` in `--json` gains `signed`,
`signedVerified`, `startKey` and `problems`; `unsigned` is now true only
when some row is unsigned.

To chain a start the body needs the line before it. It read the whole of
`starts.jsonl` for that on every start: measured, a 300 MiB file took 874 ms
and grew the process from 64 to 608 MiB, and at 700 MiB the read threw and
the body did not start. Only the end of the file is read now, and both
sizes take 2 ms. `verax verify` still reads the file whole, and one it
cannot read does not verify.

A signed row with `v`, `prevStartHash` and `sig` taken off reads as one
written before signing, and a reader cannot tell the two apart (R26). The
default therefore stays: such a file is counted, named `unsigned (not
verified)`, and verifies. `verax verify --require-signed-starts` is for a
reader who knows the ledger was written by a body that signs its starts:
every unsigned row is `start-row-unsigned: starts.jsonl line N`, a line that
cannot be read is `start-row-unreadable`, a ledger with no start row is
`start-rows-missing`, signed rows with no record key to check them under are
`start-rows-not-checked`, and the ledger does not verify. A ledger that
began under 0.4.8 or earlier keeps its unsigned rows and does not pass under
this flag. A file emptied before the body's next start begins a new chain
that passes: like rows removed from the end, that leaves nothing to compare.

Rows removed from the end leave nothing to compare. Whoever holds the
record key can write a valid row: the signature says the body's key wrote
it, not that the gap is true. A signed halt from a remote watcher is
designed in `docs/design/remote-halt.md` and not built.

Guards: `signed-starts`, `attack-r26-unsigned-starts`; `heartbeat-watch`
reads a real body's signed rows back. Published in 0.5.0.

## Key custody check — since 0.5.0

`verax doctor` opens `<stateDir>/keys/record.private.pem` as the user who
runs it. When that works and the session is not elevated, `key-custody`
fails: an agent running as that user can sign records as the body. Local
mode (`VERAX_JWKS_FILE` set) is named in the line. An elevated session that
can open it is a warning, since an administrator is outside the model. A
key the user cannot open and does not own is `ok`. A key the user cannot
open but owns fails too (R26): an owner that has shut itself out gives
itself read again with one `chmod` or `icacls`. The owner is the file's uid
on POSIX, compared with the effective uid, and the owner SID on Windows,
compared with the user's SID and the groups its token holds enabled, since a
group may own a file there. A caller refused the file's security descriptor
is read as not its owner; an owner whose own rights were narrowed by an
OWNER RIGHTS entry to rewriting the ACL without reading it is not told
apart. When the owner cannot be read the line is a warning. On Windows that read starts PowerShell once, and only when the open
was refused. Moving the key out of a file is designed
in `docs/design/key-custody.md` and not built; Windows CNG on 26H2 has no
Ed25519 (measured), AWS KMS does.

Guards: `key-custody-doctor`, `attack-r26-key-custody-owner`. Published in 0.5.0.

## Unrecorded disk deny answered once — since 0.5.0

When a deny cannot be appended the body answers HTTP 507 itself. The MCP
transport then wrote its own answer to the same response: the second header
write threw, its adapter printed the stack on stderr and destroyed the
socket. The client still read the 507, but the connection that carried it
was closed under it and each such deny left a stack trace. The transport's
writes after the body's answer are now dropped, so the 507 is the only
write and the connection stays open.

Guard: `disk-unrecorded-one-answer`. Published in 0.5.0.

## Unknown policy keys refused — since 0.5.0

Up to 0.4.8 the policy parser dropped a key it did not know, so a misspelt
control loaded without a word and the policy was weaker than the file read:
`requireInput` for `requireInputs` let a call with no `_inputs` through,
and `dailyMax` written inside `spend` set no daily cap. The parser now refuses an unknown key on the document
(`policy-unknown-key:<key>`), on a rule (`policy-rule-unknown-key:<id>:<key>`),
in `spend` (`policy-rule-spend-unknown-key:<id>:<key>`) and in `limits`
(`policy-limits-unknown-key:<key>`), and the body does not start. The shipped
policy carries only known keys. A policy file that holds comments or notes
under keys of its own stops loading after this change; move them out of the
file. Snapshots already in `<state>/policies/` were stored as the file was
written, under the hash of the document without the extra keys; they are
still read, so the cleaned policy starts on the same state directory and the
panel and `verax approve` still find the historical policy.

A `spend` block is read on the `spend` tool only. On any other rule it set
no cap and stayed out of the policy hash, so two files that read differently
shared one hash (R26). The parser now refuses it
(`policy-rule-spend-not-spend-tool:<id>`); a snapshot already on disk is
still read. `verax reconcile --channel card` took statement descriptors from
the stored document, where such a block on another rule could add a
descriptor the hash did not cover; it now takes them from the parsed spend
rule only.

The gate reads the host of `message.send` only under a rule that carries
`egress: true`, and only such a rule reads the top-level `egress` list. A
rule without the mark sent anywhere, with a list in the file or without one,
while the tool's own description says a host is reached only when the
policy lists it (R26). The parser now refuses a rule for a tool whose host
the gate reads, today `message.send`, that does not carry the mark
(`policy-rule-egress-unmarked:<id>`), approve mode included, and a list no
marked rule for such a tool reads (`policy-egress-unused`); an empty list
is a list. A mark on a tool with no host reader refuses every call to it
and keeps no list. A mark on the `spend` rule is refused
(`policy-rule-egress-on-spend:<id>`): the gate decides a spend by payee and
amount before it looks at a host. A
marked rule in a document with no list loads and reaches no host. A
snapshot already on disk is still read. A policy with an unmarked
`message.send` rule stops loading after this change: add `egress: true` to
the rule and name the hosts it may reach in `egress`.

Guards: `policy-unknown-keys`, `policy-snapshot-unknown-keys`,
`attack-r26-egress-unused`. Published in 0.5.0.

## Historical record

The entries below are dated and kept as written. "this commit" in a
heading means the commit that added that phase. Where an entry
contradicts the matrix above, the matrix is the current statement.

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

## Phase 1 — proxy (this commit)

The tree carries `@verax-ai/proxy`: a fail-closed policy, a signed
decision record on every call, an effect row on allow (including a
throw), and a file/memory ledger. `defer` is a Cedulon decision kind
and is never produced; there is no approval queue.

Known gaps:

- all witnesses are self in phase 1; reconciliation is conditional by
  construction
- explain does not call `signCheckpoint` itself. `verax witness`
  writes a durable signed checkpoint to `checkpoints.jsonl`. Without
  that file, window-coverage stays notApplicable and balanced ignores
  that code. With a covering checkpoint the finding is evaluated.
- a successful allow hashes what the proxy dispatched
  (`{ tool, arguments }`); whether the tool did that is the witness's
  job (phase 4), not the tool's self-report. The ToolResult hash lives
  as `resultHash` on the Verax ledger line, not on Cedulon's EffectRow
- an allow whose inner throws still writes a row (`<tool>:threw`); the
  effect hash is `sha256({ tool, arguments, threw: true })`, so
  `effect-mismatch` is intentional, not silent
- ledger backends: file (phase 1); obsigna daemon planned, not wired.
  One FileLedger per directory: a second instance throws
  `ledger-locked:<pid>` (dead holder: `ledger-locked-stale:<pid>`).
  The directory lock is not a distributed lock: a lock is never taken
  over automatically; an operator removes a dead lock with
  `verax unlock`. A multi-process ledger belongs to the phase 4
  witness process. Operator unlock is recorded in unlocks.jsonl, not signed.
  Token checks on append/close are best effort; single writer by construction.
  `close()` drops the lock; the body calls it on SIGINT/SIGTERM.
  The `unlink-failed` unlocks.jsonl row is written when unlinkSync
  throws.
- record and effect keys live in the same process; independence is a
  declaration, not a separate witness
- downstream third-party effect rows bind by a reader-pinned signature and
  matching decision ref/effectHash; the receipt covers the exact effect row,
  not resultHash. Party independence remains an explicit deployment statement.
  A one-row receipt states no audit window or path, so it cannot show that
  no call is missing; `explain` stays conditional and names both.
- duplicate-effect retry and late-event semantics are not designed
- reconciliation has no time limit: `verax reconcile` takes the window it is given, and nothing marks a decision as overdue when no effect row has arrived
- no-bypass: export map only in this commit; CI scan + runtime
  registry land with the body; compiled-JS and foreign-binding paths
  are not covered
- payload encryption not designed; ledger-piece and evidence-copy
  keep/move/drop designed in `docs/design/ledger-rotation.md`, not
  implemented
- `spend` / `pay` are denied as `spend-not-wired`

## Phase 1 — body (this commit)

The tree carries `@verax-ai/body`: Streamable HTTP on Node `http`, a
resource-server Bearer check (`jose`, ES256/EdDSA), four tools, and
`verax doctor`. A missing issuer/jwks/audience pair exits 78 without
`listen`. Unauthenticated calls increment `metrics.json` and do not
write a decision record.

Known gaps:

- field names not yet aligned with Tugra
- no-bypass: CI scan + runtime registry; compiled-JS and foreign-binding
  paths are not covered
- the development issuer is not a production authorization server. It
  now serves local `GET /authorize` (PKCE S256) and `POST /token`.
  `NODE_ENV=production` still exits. It listens on
  `VERAX_DEV_ISSUER_PORT` (default 8790)
- payload encryption not designed; ledger-piece and evidence-copy
  keep/move/drop designed in `docs/design/ledger-rotation.md`, not
  implemented
- memory items are not bound to the decision that read them (question 3
  is "not tracked yet")
- company effect is not connected (Talamus, question 4)
- GET /api/ledger and POST /api/contest/{ref} are HTTP, not MCP (they
  land with the panel)
- MCP is stateless (`sessionIdGenerator` unset). GET /mcp returns 405
  so the SDK client does not wait on a standalone SSE stream

## Phase 1 — panel (this commit)

The tree carries a 2D account-for rail: six golden actions, five
English questions, and a Contest button that re-runs `explain`. The
Vite proxy injects `VERAX_DEV_TOKEN` onto `/api` so the token does not
reach the browser.

Known gaps:

- questions 3 and 4 are explicit holes (`not tracked yet`, `not
  connected`); there is no invented green
- PKCE for the panel is not built
- GET /api/ledger and POST /api/contest/{ref} are HTTP, not MCP
- contest re-audits the whole ledger; no window bound (phase 4)
- the rail screenshot is a schematic PNG, not a live capture
- no React Three Fiber in the account-for rail commit

## Phase 2 — presence (removed)

Phase 2 added a textured full-body figure, a `Points` field on top of
it, an eight-state machine, adaptive draw-range quality, and a static
body-map page. None of it is in the tree any more: the figure, its
point cloud, the model scripts and the body-map page were removed, and
no screen draws a figure. The source GLB was never in git.

Known gaps that still apply:

- the panel has no frame-time gate since the galaxy was removed (16 Sep
  2026); `proxy-perf` times the body and, with no baseline recorded yet,
  prints its numbers without failing (`packages/proxy/perf/README.md`)
- all witnesses remain self; reconciliation stays conditional

## Galaxy (removed)

The panel drew a three.js galaxy from the ledger and the roster document:
planets for tenants, stars for records, agents on edges, a closed-sphere
opening, `?focus=` addresses into it, and a `panel-perf` workflow that
measured its frame times. On 16 September 2026 it was removed: `packages/galaxy`,
`apps/panel/src/galaxy`, `apps/panel/perf`, the workflow and their tests are
gone, and the panel carries no three.js. What the galaxy stated is still
stated in words: the roster's groups and agents are listed on the status
rail, and one sentence there counts how many roster agents have a decision in
the ledger. `@verax-ai/inventory` stays, because the body serves the roster.
The one threshold checker both perf jobs shared moved to
`packages/proxy/perf/check-baseline.mjs`.

## Evidence honesty (this commit)

Each line is what the tree carries, then what stays open.

- G1 — Panel: carries loading, error, empty, and stale as four states, a refresh control, a failed poll that keeps the last good rail, and `/healthz` counts that require `verax:audit`; unproven until a hosted panel is watched against a live body.
- G2 — Policy: carries a snapshot file per `policyHash` and the rail resolves the rule sentence from that hash; unproven until a second policy version is opened over an old decision in production.
- G3 — Explain: carries Cedulon `guarantee`, general `warnings`, and trust-root pin state (source `env` / `own-key` / none), and the summary never says `balanced` alone; pin defaults to the body's own record key; that proves the file, not an external root; unproven until a production pin (`VERAX_RECORD_PUBKEY_PIN`) is set and a foreign key is contested.
- G4 — Inputs: carries a `DecisionInputs` document (principal + declared memory versions) bound by `inputsHash`, including deny; unproven until brains declare `_inputs` on every call (optional unless `policy.requireInputs` is `true`).
- G5 — Effects: carries a one-row Cedulon `SignedEffectExtract` receipt at call time and a COSE Sign1 attestation over `{ ref, effectHash, witnessClass, resultHash }`; unproven until a witness other than `self` signs the row.
- G6 — Ledger I/O: carries a cached chain tail, an in-memory effect-ref index, and `fsync` after each append; unproven until a crash-restart drill on the production disk.
- G7 — Ledger rotation: carries a piece list, chain handoff across a close, a persistent ref index (appended without fsync, rebuilt from the pieces when it falls short), and lifetime `/healthz` counts (manifest + active). `loadCaches` parses the active piece plus `index.jsonl`. Measured 17 Sep 2026 on the `packages/body/perf` probe: boot 3.1 s / 629 MB on one 100k piece (2.8 s / 979 MB before), 1.9 s / 518 MB on two closed 100k pieces, 2.6 s with 50k rows open; the last-day window costs the day's rows across pieces. A window that starts inside a piece seeks its upper edge by timestamp instead of walking the piece from its end (a 24-hour window centred on the first close of a 200k ledger: 1.6 s before, 0.5 s for 5,000 rows after, the same as a last-day window of that size), and `/api/ledger` answers at most 5,000 rows (1,000 when no limit is asked). evidence-copy keep/move/drop stays designed in `docs/design/ledger-rotation.md` and is not applied. Unproven until a close happens on a live body and the witness checkpoint it requests is read back.
- G8 — Fleet view: designed in `docs/design/fleet.md`, not implemented. The panel reads one body. A central single ledger is out of scope. Operator decision taken 17 Sep 2026: the panel reads several bodies directly plus checkpoints collected at a place the operator holds; a read-only collector is not the default. Unproven until two live bodies are listed on one operator session.
- F2 — Explain: carries every general Cedulon warning as a named condition; unproven until a production deny is read and the summary is not `conditional: conditional`.
- F3 — Inputs: carries `inputs-document-missing` when `claims.inputsHash` is on the record and the document is not on disk; unproven until a crash leaves a decision without `inputs.jsonl`.
- F4 — Trust root: carries `source` (`env` / `own-key` / none) and names an own-key pin; unproven until an external pin is set in production.
- F6 — Explain: carries the call-time row receipt; no window extract is signed at audit time; unproven until a production contest is compared to the call-time receipt.
- F7 — Inputs I/O: carries `fsync` on the inputs document before the decision lands; unproven until the same crash-restart drill as G6.
- F8 — Healthz: carries `ok` only for an unauthenticated probe or a token without `verax:audit`; ledger counts require `verax:audit`; an audit token also names `heartbeat` (from `heartbeat.json`, or null) and `witness` (last `witness-status.jsonl` class, or null). Unproven until an unauthenticated probe is watched on a hosted body.
- P4 — Reconcile: carries a channel-export matcher (`reconcile`) that names ghost / unsent / outOfScope without calling Cedulon `audit()`. `outOfScope` is only rows outside an explicit `--window-start/--window-end`; without a window the scope is the channel min/max and unmatched in-window rows are ghost (`nearestEffectDtMs`). CLI writes `/reconcile-report.json`. Unproven until a live Sent export is compared to a production ledger.
- P1 — Observatory: carries three tabs (records, black box, status; default records; `?tab=` names one, and a name the panel no longer has opens the records), a detail pane with evidence scope, a timeline, demo data keyed by `loadPolicy(document).hash` plus golden `inputs.jsonl` (no `.rule-missing` on the sample), receipt/attestation read from the effect, network error stays `error` with an optional demo button, TR/EN copy (`?lang=en`), and on the status rail the roster the body serves from `/api/inventory`: its groups and agents as declared, and one sentence counting how many roster agents have a decision in the ledger (the intersection of roster ids and the brains the ledger names; `stale` past 24 h; "not bound" when the body serves none, and the sample scenario says it shows no inventory rather than claiming that). The galaxy, its `?focus=` addresses and `panel-perf` were removed on 16 Sep 2026. Layout shots cover 4 viewports × 3 tabs. Unproven until a hosted panel is watched against a live body.
- P2 — Desktop: not released. `verax desktop` exits 64 with `desktop-not-released` and starts nothing; the launcher below stays under test (through `tests/desktop-entry.ts`) until it is released. The launcher runs (dev issuer → body → `vite preview` with token on env only → Edge/Chrome `--app=` with `--user-data-dir=<state>/browser-profile`, `--no-first-run`, `--no-default-browser-check`). A browser that exits within 3 s is `desktop-browser-exited-early` (exit 1). Window close kills the process tree (`taskkill /T` / POSIX group). When `<state>/ledger.lock` is held by a live process, the lock names `--body-port`, and that pid is the listener on 127.0.0.1 at that port, 0.4.0 does not join that body: exit 1, stderr `desktop-body-running:<bodyPort>`, and nothing is started. Use the panel of the desktop that started that body, or stop the body first. `verax unlock` is for a dead lock only. Any other live lock is `desktop-body-locked:<pid>:<port or unknown>` (exit 1) with nothing started; a lock with no port is that stop until the body is started again. A dead lock is left to `verax unlock`. `src/desktop.ts` is the only body file allowed to name `child_process`; it is still scanned for `import(`, `require(`, `eval`, and `tools/` imports. The CLI test builds `apps/panel/dist` when it is missing (D3). This machine (6 Sep 2026): Edge already open; `verax desktop` stayed up 20.0 s; ports closed 2.1 s after the isolated profile window closed. This machine (16 Sep 2026), before 0.4.0 stopped joining a running body: the logon body held the lock (pid 8748, 8787); `verax desktop` reported `attached=1` in 3 s, the panel on 5173 read 10 decisions from that ledger through the running issuer, and closing the window left the body answering. That join is not in 0.4.0. The browser is opened at `http://localhost:<panelPort>` and the issuer it is sent to is `http://localhost:<issuerPort>` (`VERAX_RP_ID=localhost`; the passkey ceremony runs on that issuer). Sockets, readiness lines, and `/healthz` stay on 127.0.0.1, and the panel proxy targets `http://127.0.0.1:<bodyPort>`. Still unproven on a host that has never run the profile path.

- S1 — Approvals: carries `defer` on `mode: "approve"`, `<stateDir>/approvals.jsonl` (rule sentence + inputs summary + amount/payee), `verax approve` (CLI only; queues when the ledger is locked; drain renames `approval-commands.jsonl` before apply), a panel pending list with no approve control, an explain `pair` (defer + resolution via `approver.resolves` / snapshot `allowRef`, not `prevRecordHash`), lazy `expired`, and `_ref` idempotency (`ref-reuse` / `ref-invalid` under a new nonce; retry uses that defer's resolution only). Approved `allow` uses `effectDescriptor` for `effectHash`. Carries an admission lock and an in-flight registry: one allow per limit window, one execution per ref, one approval per request, current policy re-evaluated on retry; an allow with no effect and no in-flight row is `deny outcome-unknown` rather than a second run. On the approved path an allow means the operator said yes, not that the tool ran, so the run is gated by a durable start mark instead; measured under a restart mid-run (`crash-between-allow-and-effect`).
- S2 — Spend: carries `spend` (cap / payee / daily / currency → always `defer`), authorize-once on retry (`spend-reauth-required`), card CSV reconcile (`matched` / `ghost` / `authorizedUnpaid`); the body does not move money. On 6 September 2026 a live card charge of 10.00 TRY, made by hand on an advertising platform after the rail deferred and an operator approved it, was reconciled against that ledger: one statement row, one spend effect, `matched 1 · ghost 0 · authorizedUnpaid 0 · mismatch 0`. Two limits of that run remain part of the claim, now narrowed only where the tree actually narrowed them. A card date with a time (`DD.MM.YYYY HH:MM` or `YYYY-MM-DD HH:MM`) uses a two-minute window and the report marks that row `datePrecision: "minute"` — but only when the run names the statement's UTC offset (`--tz-offset 180` for Istanbul), because a statement prints local wall-clock time and names no zone. Without that offset the printed time is not trusted: the row stays `datePrecision: "day"` on the three-day card window, as does a date-only row. The 6 September statement was date-only, so that run is still the wide window. When a spend rule carries optional `descriptors` and the statement has no `verax:` ref, a configured stamp must hit or the row is ghost `descriptor-mismatch`; stamps are not guessed. That 6 September row had no descriptors on the policy, so the weak amount/currency/class path still carried it. Still unproven for a statement holding several rows of the same amount, for a payee that carries the reference through, for a timed statement row in production, and for a settled rather than pending row. `spend-not-wired` remains for `pay` and for `spend` when no spend rule is present (policy fixtures replace the hard deny).
- S3 — Bounds: carries priced-row reconcile refuse (`amount-unknown` when one side is priced and the other is not), host allow-list egress (`egress-blocked` / `egress-host-missing`; `message.send` `to` must contain `@` or the host is missing), a no-network `message.send` outbox stub, rate/daily counters (only `allow` and `defer` increment; unreadable counts fail closed; taken under the admission lock so parallel calls see the updated count), `ledger-disk-low` (HTTP 507 and a `disk_deny_unrecorded` metric when the deny cannot append), `verax halt` (`deny halted`, still signed), and `jti` revoke (401, no decision record). A ledger with no `.dir` (MemoryLedger) leaves halt and disk limits inactive; `createProxy` writes a warning. The suite now also locks halt-before-disk when both fire. Spend approval re-checks `spend.dailyMaxMinor` against today's approved total (`budget-exceeded` keeps the snapshot pending). Carries an admission lock and an in-flight registry: one allow per limit window, one execution per ref, one approval per request, current policy re-evaluated on retry. Measured under a crash between the record and the effect: a body that restarts mid-run finds the durable start mark and answers `outcome-unknown` instead of running an approved call twice (`crash-between-allow-and-effect`). It cannot tell that run from one that crashed before the tool did anything, so an approved call can end up never running.
- S4 — Tenant: carries a tenant key of SHA-256(`{ iss, sub }` plus `tenant` / `org` when present; not `aud`), memory and inbox under `tenants/<tenantKey>/`, signed `deny tenant-mismatch` (no body) when `memory.get` names another tenant's id and this tenant has no file of its own, a `verax doctor` warning on legacy flat `memory/` (reads do not merge it), and a per-tenant `_ref` namespace so one tenant cannot close another's key. The ledger, the approvals snapshot and the resolution index key on `<tenantKey>:<_ref>`; the brain is answered with the raw `_ref` it sent, so its retry carries the same key back. `verax approve` accepts a raw `_ref` when exactly one pending row ends with `:<_ref>`; two hits list the candidates and exit `ambiguous-ref`. `audit.explain` (the brain tool only) denies another tenant's ref with a signed `tenant-mismatch` row and no record body; the operator `explain()` / panel contest path is unchanged. A missing memory id is still answered `not-found` over its allow row. Another tenant's id writes `deny tenant-mismatch` and is spoken as the `not-found` family (`spokenReason`, one table); the recorded code is never rewritten. The operator `explain()` / panel contest path still shows the full reason. The brain still owns both records and can tell them apart through `audit.explain`. Card reconcile reads descriptors from the newest `policies/<hash>.json` snapshot and names that hash on `report.scope.policyHash`. Two subjects on one issuer were driven over HTTP against one body: the second read the first's id and got a signed `deny tenant-mismatch` with no body. Unproven until two live customers share one body.
- S5 — Session: carries local PKCE and an operator scope on the audit doors: `GET /api/ledger` and `POST /api/contest/{ref}` hand out every tenant's decisions, the inputs documents that name their principals and the approval snapshots that carry spend arguments, so they now require `verax:audit`, which a brain token does not hold (the development issuer mints one token for both roles and does hold it). Unproven until a production authorization server is pinned in PRM. The panel holds the access token in memory (not `localStorage`, not the bundle) and refuses a code that comes back without the `state` that tab sent. A refresh runs `authorize` again. Vite may still inject `VERAX_DEV_TOKEN` for desktop MCP brains and tests when the request has no Authorization header; that path is not the panel session.
- S6 — Spoken reason: `spokenReason` maps `tenant-mismatch` to `not-found` on the brain-facing string only. `memory.get` and `audit.explain` therefore answer another tenant's id/ref and a missing id/ref with the same `not-found` family; the ledger row stays `deny`/`tenant-mismatch` vs `allow`. Operator `explain()` and `/api/*` are unmasked. A brain that explains the two records it owns can still tell them apart. `/healthz` counts now require `verax:audit` (a brain `verax:read` token is `{ ok: true }` only). The development issuer refuses an unlisted `redirect_uri` and caps `codes` at 100. Unproven until two live customers share one body.
- S7 — Inputs required: carries optional `policy.requireInputs` on the document root (`version: 1` stays). When it is `true`, a call with no `_inputs` key is a signed `deny inputs-required` (`effectHash: null`, no body). An empty array is a declaration and is not that deny. A broken declaration stays `input-invalid`. `inputs-required` is not masked. `DecisionInputRow` still names `validFromMs` / `validUntilMs`; optional `source` is additive. The panel reads `authorization_servers` from resource metadata before a session; an unreadable document is a visible rail error (last-resort issuer named, no silent redirect). `verax doctor` warns when the panel port is off the issuer redirect allow-list, when the panel last-resort issuer differs from `VERAX_ISSUER`, or when the development token scope lacks `verax:audit`. Doctor only reports. Unproven until brains declare `_inputs` on every production call.

## Phase 4 — independent witness (this commit)

`verax witness <stateDir>` is a second process. It holds
`keys/witness.private.pem` and signs an effect row over loopback HTTP.
The body never loads that file (`loadOrCreateSigners` still only has
record + effect). A reachable witness writes `witnessClass: "same-org"`
and a `witness-status.jsonl` `signed` row. An unreachable witness leaves
the class `self` and records `self-fallback` / `unreachable`. That is
not a third-party witness. The same process signs a durable checkpoint
onto `checkpoints.jsonl`; `explain` then evaluates window-coverage
instead of listing it as notApplicable. FileLedger also appends each
decision/effect line to `evidence-copy/` and writes `heartbeat.json`
(`alive` + last row n). `verax doctor` is the speaker: a stale
heartbeat is `heartbeat` / silent; a short or corrupt copy is
`evidence-copy`. The panel is a session UI and is not watching this.
Seven pilot drills live in `tests/pilot-drills.test.ts` (stolen token,
hostile tool, cross-tenant record, repeated `_ref`, tampered memory,
full disk, silenced copy). They are tests, not a live body.

Remaining gaps, still open:

- `_inputs` is optional unless `policy.requireInputs` is `true`; without that flag a call with no declaration still stores `inputs: []`. The flag is off on the default policy. Production brains have not been required to declare yet.
- ledger rotation carries pieces and a ref index (`docs/design/ledger-rotation.md`); `/api/ledger` is capped at 5,000 rows, so a reader that wants more pages back with `from`/`to`; `inputs.jsonl` rows carry no stamp, so the inputs of a past window are still read from the end of the piece. A multi-body panel stays designed (`docs/design/fleet.md`) and is not implemented
- a FileLedger effect is `same-org` only when `verax witness` signed it
  in another process; without that process the class is `self` and
  `witness-status.jsonl` records the fallback. MemoryLedger tests and
  the body effect key remain `self`. This is not a third-party witness.
- Cedulon's `EffectRow` still cannot hold `resultHash`; the attestation does
- a brain can still tell a cross-tenant miss from a missing id by explaining the two records it owns (`deny`/`tenant-mismatch` vs `allow`). The spoken answers on those two calls are now the same `not-found` family; that hop is the accepted remaining limit, not a claim that the oracle is closed
- the development issuer is still not a production authorization server; `NODE_ENV=production` still exits. `/authorize` now refuses a `redirect_uri` outside `VERAX_DEV_REDIRECT_URIS` (default `http://127.0.0.1:5173/` and `http://127.0.0.1:4173/`) with `400 invalid_request`, and the in-memory `codes` map is capped at 100 (expired rows drop first, then the oldest)
- the panel reads `authorization_servers` from `/.well-known/oauth-protected-resource` before it starts a session. If that document cannot be read, the session does not redirect: the rail shows `resource metadata unreachable` and names the last-resort issuer (`VITE_VERAX_ISSUER`, else `http://127.0.0.1:8790`). Vite proxies `/.well-known`. The desktop launcher (not released) opens `http://localhost:<panelPort>`, names the issuer `http://localhost:<issuerPort>`, and passes that panel origin on the issuer allow-list when it starts the issuer. 0.4.0 does not join a running body (`desktop-body-running:<bodyPort>`). `verax doctor` still names a panel origin that is off the issuer allow-list
- a JWT-less fixture principal keeps the raw `_ref` as `claims.ref` so S1 tests stay pinned; production tokens always carry `iss` and are prefixed

## Downstream MCP on the served path (0.1.3)

`VERAX_DOWNSTREAM` is a path to a JSON document: one stdio child server, or
an array of them, each `{ prefix, command, args?, cwd?, env?, timeoutMs? }`.
It is a path and not the JSON itself because the document may name a key in
`env`, and that key belongs in a file the operator controls rather than in
the environment of the body. Unset means no downstream and the door is
exactly what it was: the six built-in tools.

`listen()` attaches every named child before it binds, passes their tools to
`createBodyServices({ extraTools })` so the names enter the private registry
Map, publishes them on HTTP `tools/list` as `prefix.childName` with the
child's own description and input schema, and closes the children when the
server closes. A child the document names but cannot open throws
`downstream-attach-failed:<prefix>:<detail>` and the body does not come up:
a body serving six tools while its operator wrote seven is answering for a
gate it does not have.

A forwarded call is an ordinary call. It passes the same policy gate under
the prefixed name — an exact rule, no wildcard — leaves the same signed
decision, and on allow writes the same effect row with `effectClass` set to
that name and `resultHash` over the child's answer. Without a rule it is
`denied:no-rule:<ref>` and the child is never called. The default policy is
unchanged, so a fresh body forwards nothing until the operator writes the
rule. The panel is unchanged.

The attach starts the child through the SDK stdio transport; that source
does not write the `child_process` name, so the no-bypass scan names the SDK
stdio client transport instead, and only `src/downstream.ts` may import it
(`src/desktop.ts` remains the file that may name `child_process`). Operator
decisions of 17 Sep 2026 are on the design note (connection document,
exact-match namespace, `resultHash` only).

**Driven against a live Conarium (19 September 2026).** A body was started
with `{ "prefix": "conarium", "url": "<Conarium's public demo /mcp>" }` and
answered `tools/list` with ten tools: its own six plus `conarium.list_tables`,
`conarium.describe_table`, `conarium.query` and `conarium.search`. A policy
naming only `conarium.list_tables` was written. That call returned Conarium's
own answer and left `allow conarium.list_tables` on the ledger with an effect
row whose `resultHash` covers it; `conarium.query`, which the policy does not
name, was refused `denied:no-rule:<ref>` and the child was never called. No
Conarium code is in this repository and Conarium kept its own server.

**Not done.** The child's tool list is read once, at attach: a child that
gains or loses a tool while the body runs is not noticed, and a child cannot
be attached after start. The stdio path cannot reach the local Conarium,
which holds a single-writer audit lock a spawned copy would collide with —
that is why the HTTP transport, not the stdio one, carried the first real
attach. Nothing here has run against a live Tugra.
