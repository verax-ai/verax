# Downstream MCP servers — design note

**Status (19 September 2026).** The spike this note designed is now on
the served path. `listen()` reads `VERAX_DOWNSTREAM`, attaches the
children it names before binding, publishes their tools on HTTP
`tools/list` under `prefix.childName`, and closes them with the server;
`tests/downstream-served.test.ts` holds that up. What the sections below
mark **Open** stayed open unless this block says otherwise. Two decisions
moved: the document is a **path** in `VERAX_DOWNSTREAM` and may be an
**array** of children (§1), and HTTP `tools/list` **does** publish the
child's own description and schema (§2) — a tool a caller cannot see is a
tool the gate is never asked about. The HTTP transport landed the same day and carried the first real attach: a
body reached a live Conarium over `url`, published its four tools behind the
gate, ran the one the policy named and refused the one it did not (§1). The panel
is unchanged. Live bodies on this machine are not started from this note.

The commercial line "one ledger, three places, one contract" is a
package, not a code merge. Conarium and Tugra stay their own MCP
servers. Cedulon stays a library already inside the proxy. The body
stands in front: gate, signed decision, forward, hashed effect.

Brain-storm source: `Work/VERAX_MEGAZORD_BEYIN_FIRTINASI_20260904.md`,
proposal C (Verax Proxy). Product decision stays with the operator.

**Decisions taken (17 September 2026, operator).** Connection: a
`VERAX_DOWNSTREAM` JSON document, stdio now, HTTP later; not a `servers:`
block in the policy file, because that would change `policyHash` for
every rule. Namespace: `prefix.childName`, exact-match policy rules, no
wildcard; HTTP `tools/list` publishes the extras only once `listen()`
wires a downstream — that phase landed on 19 September and the list now
carries them. Receipt
binding: the effect row keeps `resultHash` over the child's answer and
nothing more; a Conarium receipt field is decided when the body reads a
real Conarium receipt, not before. The no-bypass scan names the SDK stdio
transport, and only `src/downstream.ts` may import it.

## 1. Connection

**Decision (spike, extended 19 Sep).** One child, described in a JSON
document as `{ prefix, command?, args?, cwd?, env?, url?, headers?,
timeoutMs? }`. Exactly one way in: `command` spawns the child over stdio,
`url` speaks Streamable HTTP to one already running. Both is
`downstream-transport-ambiguous`, neither is `downstream-transport-missing`,
and a `url` that is not `http:` or `https:` is `downstream-url-invalid`.
`headers` is the operator's, for a child that wants its own bearer; the
body's token is not forwarded on either transport. The live Conarium and
Tugra servers are reachable only this way — and the local stdio Conarium
holds a single-writer audit lock that a spawned copy would collide with,
so HTTP is the transport that made the first real attach possible. The child is spawned by the body. The body's
Bearer token is not copied into the child. If the child needs a key,
that key is the child's, named in `env` by the operator.

**Why.** The demo box already speaks stdio MCP. Conarium and Tugra
publish as their own servers; spawning them (or a local wrapper) is
the smallest attach. Putting server URLs inside the policy document
would mix "who may call this tool" with "where a process lives", and
every host change would change `policyHash`. The agent token is a
Verax resource-server credential; forwarding it is a confused-deputy
path.

**Alternative.** `servers:` on the policy file (rejected for the
hash reason). Streamable HTTP to a remote Conarium/Tugra (the
likely next attach; same prefix and gate, different transport).
Passing the agent's Verax token to the child (rejected). A shared
vault that mints a child-specific token (later, if a child refuses
stdio).

**Settled (19 Sep).** Both: `parseDownstreamDocument` reads one object
or an array, and a prefix that appears twice refuses the document
(`downstream-prefix-duplicate:<prefix>`). `VERAX_DOWNSTREAM` carries the
path to that file, not its text, so a child's key stays in a file the
operator controls.

**Open.** Whether a child may be attached or dropped while the body
runs. Today the set is fixed at `listen()`.

## 2. Namespace

**Decision (spike).** The agent sees `prefix.childName` (`echo.ping`
in the test). `tools/list` on the body services object is the six
built-in names plus the prefixed names collected at attach. The
child's input schema is not yet published on HTTP `/mcp`. A prefixed
name that collides with a built-in, or with another extra, refuses
attach (`downstream-name-collision:<name>`). Prefix:
`^[A-Za-z][A-Za-z0-9_-]{0,31}$`. Child tool name:
`^[A-Za-z][A-Za-z0-9._-]{0,63}$`.

**Why.** The gate and the ledger already key on an exact tool string
(`memory.get`, `message.send`). A prefix keeps that string stable
and names the child in the Records filter later. Attach-time list
matches how the registry Map is filled today: once, at
`createBodyServices`.

**Alternative.** Flat names (`ping` as-is) — collision with a later
built-in is silent. A slash (`conarium/query`) — unlike the existing
dot style. Live merge of the child's later `tools/list` — the Map
is not a live bus; a refresh is a later job.

**Settled (19 Sep).** HTTP `tools/list` grows. Each extra is published
as the child's own description followed by one sentence naming what the
body adds — that the call passes this gate under this name and may come
back `denied:…` or `deferred:…` before the child sees it — and the
child's `inputSchema` unchanged. A child that published no schema is
listed as `{ type: "object" }` rather than left without one.

## 3. Decision record

**Decision.** `subject` is the name the agent called
(`conarium.query`), not the child's inner name. The request hash
covers `{ name, arguments }` after `_ref` / `_inputs` are stripped,
same as a built-in. Policy match today is exact (`tool` equals
`call.name`). A rule for a forwarded tool is written with that
prefixed name. `requires` is an ordinary scope list; the spike
reuses `verax:read`. `mode: "approve"` is the existing defer path:
the proxy writes `defer`, does not call `inner`, and forwards
after an operator allow on that `_ref`.

**Why.** The ledger's vocabulary is the name the brain used. A
wildcard `conarium.*` is not in `loadPolicy` today; adding it
changes the fail-closed document. Exact rules keep the spike inside
the current evaluator. Approve-before-forward is already how
`message.send` and `spend` work; the child is just `inner`.

**Alternative.** `tool: "conarium.*"` in the policy (recommended
product follow-up, not in this spike). A dedicated scope
`verax:conarium` per child. Generating one rule per listed tool at
attach (hides the document from the operator).

**Open.** Whether a missing exact rule should stay `no-rule`, or a
later wildcard should allow a whole prefix.

## 4. Effect

**Decision.** On allow, the effect row is the existing one:
`effectClass` is the prefixed name, `effectHash` is
`sha256Canonical({ tool, arguments })`, `resultHash` is
`sha256Canonical(result)` on the Verax ledger line. Cedulon's
`EffectRow` still cannot hold `resultHash`; that hash stays on the
Verax line and in the COSE attestation payload
`{ ref, effectHash, witnessClass, resultHash }`. If Conarium
returns its own receipt, this spike does not parse it. The receipt
bytes are part of the ToolResult that `resultHash` covers. A later
bind can copy a Conarium receipt id into a side file or into
attestation metadata; it does not extend `EffectRow`.

**Why.** STATUS already states the `resultHash` / `EffectRow` split.
Putting a foreign receipt into Cedulon types would edit a closed
shape. Hashing the result (including any receipt the child returned)
is the bind this spike can do without inventing a field.

**Alternative.** A Verax-side `downstream-receipts.jsonl` keyed by
`ref` (later). Asking Conarium to put a hash in a reserved key
(later, needs Conarium). Treating the child's receipt as the Verax
effect (rejected: two ledgers, two vocabularies).

**Open.** How a Conarium receipt id should appear on the panel next
to the Verax `resultHash`. That is the operator's third call.

## 5. Error, timeout, retry

**Decision.** If the child throws, the transport fails, the call
times out (`timeoutMs`, default 10s), or the child returns
`isError: true`, the wrapper throws. The proxy already writes
`allow` then `effectClass: "<name>:threw"` and rethrows. `_ref`
retry is the existing S1 path: same arguments replay the allow; if
a primary effect row exists the brain gets `allowed:<ref>` and the
child is not called again. A second effect on the same `ref`
becomes `duplicate-effect`.

**Why.** Built-in tools that throw already take this path. Mapping
a child's `isError` onto a successful effect would look like a
finished call on the rail. Timeout is an operator bound, not a
policy field, so it does not change `policyHash`.

**Alternative.** Record `isError` results as ordinary allows
(rejected for the rail). A distinct `reasonCode` for timeout
(would deny before `inner`, so the child is not called; possible
later). At-most-once forward (would need a prepare record the
child understands; not in this spike).

## 6. Security model (unchanged door)

**Decision.** Streamable HTTP `/mcp` still refuses a call without a
verified Bearer token. Attaching a child does not open that door: it
adds names behind it. `listen()` now reads the operator's document and
passes `extraTools`, and the scope, tenant and revocation checks a
forwarded call passes are the ones every built-in call passes. A
child that cannot be opened stops the body rather than leaving a door
whose tool list is shorter than the document behind it. A stdio child's
address is an operator command line, not a host the brain supplies,
so it does not enter the `egress` allow-list (that list is for
brain-chosen hosts such as `message.send`'s `to`). Decision claims
carry hashes, not the result body. STATUS still names payloads as
plaintext where the tree already stores them (approval snapshots
hold args for held calls). The spike does not add a new plaintext
dump of the child's result. Child `env` is the SDK default
environment plus an optional operator overlay; it is not
`process.env` and not the agent's token. The attach starts the
child through the SDK stdio transport. That source does not write
the `child_process` name, so the no-bypass scan does not see the
spawn (`src/desktop.ts` remains the file that may name it).

**Why.** The threat model is a hostile brain, not a hostile
operator. Egress exists to stop the brain picking a destination.
An operator-started child is a process the host already chose.

**Alternative.** Treat the child's HTTP URL (when that transport
lands) as an egress host anyway, so a policy without that host
cannot attach (possible later, defense in depth). Encrypting
ledger payloads (already named as undesigned in STATUS).

## 7. Panel

**Decision.** Not in this phase. A forwarded allow already stores
`subject` as the prefixed tool name. The Records / agent table can
filter on that string (`conarium.` prefix) without a new column. Now
that HTTP `tools/list` publishes the extras, a panel talking to a live
`/mcp` sees them in the list; nothing in the panel says which rows came
from a downstream server, and nothing yet says which children a body
attached. That is the first panel job when a real child is attached.

**Why.** The task keeps the panel as a separate job. The ledger
shape does not need a new field for a name the brain already used.

**Alternative.** A `downstream` tag on the decision (rejected: new
meaning on a closed claims shape). A dedicated tab (later product).

## 8. What this does not do

- Copy Conarium or Tugra code into this repository.
- Move Conarium masking, completeness, or receipt minting into Verax.
- Wake Hermes, OpenClaw, or NEO.
- Touch Talamus or Mizan product surfaces.
- Bind or restart the live body on port 8787.
- Change the default policy: a fresh body forwards nothing until the
  operator writes an exact rule for the prefixed name.
- Reach a child over HTTP. stdio only, so the live Conarium and Tugra
  servers are not attachable from this note yet.
- Attach or drop a child while the body runs.

## Surface

| Piece | Role |
| --- | --- |
| `packages/body/src/downstream.ts` | stdio client, prefix, forward, `parseDownstreamJson`, `parseDownstreamDocument` |
| `VERAX_DOWNSTREAM` (`config.ts`) | path to the operator's document; unset means no downstream |
| `listen()` (`server.ts`) | attach before bind, publish on `tools/list`, close with the server, refuse to come up half-attached |
| `createBodyServices({ extraTools })` | extra names enter the private registry Map |
| `tests/downstream.test.ts` | attach unit: allow + effect; deny without a rule; child fail → `:threw`; parent `VERAX_*` stays out of the child |
| `tests/downstream-served.test.ts` | served path: `tools/list` carries the child's schema; a forwarded call writes one decision and one effect; a denied call never reaches the child; a bad document stops the body; the child dies with the body; an array document attaches each child |
| `tests/fixtures/downstream-echo.mjs` | one-tool stdio child; writes a trace when the spec's `env` names one |

Mutation checks run against these guards: dropping the extras from
`tools/list`, not passing `extraTools`, swallowing the attach failure,
leaving the child open at shutdown, reading the document as a single
object, and ignoring `VERAX_DOWNSTREAM` each turned exactly the guard
that claims them red.
