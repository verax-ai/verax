# Data classes v1 — design, not built

Status: design only. Nothing in this document is in the tree.

## What it is for

An operator connects an agent to tools through Verax and wants to say, per
kind of data, what may pass: e-mail addresses, national ID numbers, IBANs,
company figures, files of a given type, later audio and photos. For each
class the choice is one of four:

| Choice | What happens to a call that carries it |
|---|---|
| **allow** | passes unchanged |
| **mask** | the value is replaced by a label (`[MASKED_EMAIL]`) before the call is forwarded |
| **local** | the call runs only against a tool the operator marked as local; to any other tool it is refused |
| **block** | the call is refused |

Every mask or refusal is written into the signed decision record, so the
ledger can show not only that a call was refused but which classes were
taken out of the calls that were forwarded. The claim is narrow and stated
that way: **this covers tool calls that pass through the Verax gate**. Text
the agent writes straight to its model, files it reads with its own
process, and calls to tools that are not behind Verax are outside it.

## What exists today (measured on main 7d7ca51)

- A policy rule (`packages/proxy/src/policy.ts`, `asRule`) reads `id`,
  `tool`, `requires`, `text`, and optionally `mode`, `spend`, `egress`.
  There is no class, mask or file-type field, in the rule or in
  `types.ts`.
- `asRule` copies the keys it knows and **ignores any other key**. A rule
  written today with a `dataClasses` key would load and do nothing. The
  first change therefore makes an unknown key a load error (or bumps the
  document `version` and refuses unknown keys under the new version), so an
  operator cannot believe masking is on when it is not.
- Egress is already decided per tool (`HOST_EXTRACTORS`, named per tool,
  no sniffing of arbitrary arguments). Data classes follow the same rule:
  a tool's arguments are read where the operator says, not guessed.

## The masking engine: Conarium, as a dependency

`@conarium-ai/core` (0.2.53) has the masking pipeline Verax would reuse:
`maskSensitiveText(text, { detectors, customPatterns, scanCharCap })` in
`src/mask-text.ts` — e-mail, numeric PII (Turkish ID number, card
numbers by Luhn, phone numbers), IBAN, passport MRZ, optional IP, secret-shaped
values, URL credentials, bearer tokens — plus operator patterns compiled
with ReDoS checks (`compileCustomPatterns`). Text over the scan cap is
replaced whole rather than scanned partly.

Measured constraint: the package's `main` is `dist/index.js`, the MCP
server entrypoint, which starts the server when imported. The masking
module is reachable only as an internal path (`dist/mask-text.js`), and
the package has no `exports` map. Verax should not import an internal
path. The order is:

1. Conarium publishes the pipeline as a library entry (an `exports`
   subpath such as `@conarium-ai/core/mask`, or a small `@conarium-ai/mask`
   package) with no side effects on import.
2. Verax depends on that entry, pinned to an exact version, the way it pins
   `@cedulon/*`. The code is not copied: one masking implementation, so a
   detector fixed in Conarium is fixed in Verax.

Running Conarium as a downstream child does not fit here: a downstream
child is a tool the agent calls; masking has to sit inside the gate, on
every call's arguments.

## Policy shape (proposed)

```json
{
  "version": 2,
  "default": "deny",
  "dataClasses": {
    "email": "mask",
    "tckn": "block",
    "iban": "mask",
    "company-figures": { "choice": "local", "pattern": "revenue-pattern" }
  },
  "fileTypes": { "block": [".pfx", ".pem", ".kdbx"] },
  "rules": [
    { "id": "send", "tool": "message.send", "requires": ["verax:send"],
      "text": "Sending needs the send scope.", "egress": true,
      "dataClasses": { "email": "allow" } }
  ]
}
```

- Document-level `dataClasses` is the default; a rule can narrow or widen
  it for its tool (the `to` of `message.send` has to carry an address).
- Built-in class names map to Conarium detectors. An operator class names a
  custom pattern, compiled with Conarium's ReDoS checks at load; a pattern
  that does not compile stops the load.
- `local` needs a list of tools the operator marks as local (for example a
  downstream child started by `command`); a call to anything else that
  carries the class is refused with `data-class-local`.
- `fileTypes.block` reads file names and paths only where a tool's
  extractor says arguments hold them, the same way egress reads hosts.

## Order inside the gate

1. Policy decides allow, defer or deny as today.
2. For an allow, the class scan runs on the arguments the extractor names.
   A `block` class or a blocked file type turns the allow into a signed deny
   (`data-class-block:<class>`, `file-type-block:<ext>`). A `local` class to
   a non-local tool is a signed deny.
3. Otherwise `mask` classes are replaced, and the **masked** arguments are
   what is forwarded.
4. The decision record keeps `requestHash` over the arguments as the agent
   sent them and adds `forwardedHash` over what was forwarded, with a count
   per class (`masked: { email: 2 }`), never the values. A reader can then
   check that what left matches `forwardedHash`, and the record says what
   was removed without repeating it.
5. Results coming back can be scanned the same way before the agent sees
   them (`resultClasses`, same choices except `local`), recorded the same
   way.

`requestHash` over the original arguments is a hash of personal data; see
`docs/design/erasure.md` for why that hash should become keyed. The two
designs meet there: data classes say what did not leave; erasure says what
was kept and can be destroyed.

## Order of work

1. Text classes and file-type block on arguments, Conarium engine via a
   library entry, signed counts; unknown policy keys refused.
2. Panel: the operator picks a choice per class; the panel writes the
   policy document, the body loads it as today.
3. Audio: a recording does not leave. It is transcribed on the machine,
   the transcript goes through the same classes, and either the masked
   transcript or nothing is forwarded. Measure a local speech model's
   accuracy on Turkish before promising this.
4. Photos: blur faces and document regions before forwarding. A detector
   choice and its error rate are measured before this is offered.

## Guards it would need (each seen red first)

- A policy with `dataClasses` under the current version is refused, not
  ignored.
- A call carrying a `block` class is a signed deny and the tool is not
  reached.
- A masked call reaches the tool with the label, and the record's
  `forwardedHash` matches what the tool received.
- A `local` class to a non-local tool is refused.
- The record carries counts per class and no masked value.
- Text over the scan cap is replaced whole, as in Conarium.

## What it does not do

- It does not see what the agent sends its model directly, or what the
  agent's own process reads and writes. Only calls through the gate.
- A detector misses what it does not recognise. Masking lowers what
  leaves; it does not prove nothing personal left. The record proves what
  the gate removed, not what it missed.
- `local` trusts the operator's marking of a tool as local.
