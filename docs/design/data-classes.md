# Data classes v1

Status: the first step of the order of work below (text classes on tool-call
arguments, the file-type block, signed counts) is in the tree; see "What is in
the tree". The panel, audio, photos, operator pattern classes and
`resultClasses` are design only.

## What it is for

An operator connects an agent to tools through Verax and wants to say, per
kind of data, what may pass: e-mail addresses, national ID numbers, IBANs,
company figures, files of a given type, later audio and photos. For each
class the choice is one of four:

| Choice | What happens to a call that carries it |
|---|---|
| **allow** | passes unchanged |
| **mask** | the value is replaced by a label (`[MASKED_PII]`) before the call is forwarded |
| **local** | the call runs only against a tool the operator marked as local; to any other tool it is refused |
| **block** | the call is refused |

Every mask or refusal is written into the signed decision record, so the
ledger can show not only that a call was refused but which classes were
taken out of the calls that were forwarded. The claim is narrow and stated
that way: **this covers tool calls that pass through the Verax gate**. Text
the agent writes straight to its model, files it reads with its own
process, and calls to tools that are not behind Verax are outside it.

## What is in the tree

`packages/proxy/src/data-classes.ts`, called from `proxy.ts`; every point
below is a test in `packages/proxy/tests/data-classes.test.ts`.

- **Policy.** A `version: 2` document may carry `dataClasses` (class →
  `allow` / `mask` / `local` / `block`), `localTools`, `fileTypes.block`,
  `scanCharCap`, and per-rule `dataClasses` that override the document's
  choice for that rule's tool. Class names are Conarium's span classes; an
  unknown name or choice, or `local` without `localTools`, stops the load.
  Under `version: 1` these keys are refused, and arguments are forwarded as
  before.
- **What is scanned.** Every string, object key and number in the call's
  arguments, at any depth, and Verax's own `_ref` and `_inputs`. This
  differs from the egress rule above: classes are not read only where an
  extractor points, because a value that is not scanned would leave
  unmasked.
- **Refusals**, each a signed deny and the tool is not reached:
  `data-class-block:<class>`, `data-class-local:<class>`,
  `file-type-block:<ext>` (after cutting a URL query or fragment,
  percent-decoding, dropping an NTFS stream suffix and trailing dots or
  spaces), `data-class-key:<class>` (a key cannot be masked),
  `data-class-meta:<class>` (a class in `_ref` or `_inputs`),
  `data-class-unscanned` (a key that could not be scanned; or a value that
  could not be scanned when a class is chosen `block` or `local` and none is
  chosen `mask`, since with a `mask` class that value is replaced whole
  instead), `data-class-error` (the masker threw).
  Arguments nested deeper than 64 levels are refused before the request is
  hashed (`data-class-unscanned`, or `arguments-too-deep` under version 1).
- **Masking.** `mask` classes are replaced, regions the masker covers
  without a class are always replaced, and a string over the scan cap is
  replaced whole. The decision keeps `requestHash` over the arguments as
  sent; its inputs carry `dataClasses: { masked, forwardedHash }`, counts
  and a hash, never a value.
- **Approval.** A deferred call is gated before the operator is asked. The
  operator's allow names the forwarded (masked) call. The retry after
  approval gates again and is refused with `data-class-changed` when the
  call the policy would now forward differs from the one approved.

Not built: operator pattern classes (`{ choice, pattern }`), `resultClasses`,
the panel, audio and photos.

## The masking engine: Conarium, as a dependency

`@conarium-ai/core` (0.2.53) has the masking pipeline Verax would reuse:
`maskSensitiveText(text, { detectors, customPatterns, scanCharCap })` in
`src/mask-text.ts` — e-mail, numeric PII (Turkish ID number, card
numbers by Luhn, phone numbers), IBAN, passport MRZ, optional IP, secret-shaped
values, URL credentials, bearer tokens — plus operator patterns compiled
with ReDoS checks (`compileCustomPatterns`). Text over the scan cap is
replaced whole rather than scanned partly.

Done in Conarium 0.3.3: the pipeline is published as
`@conarium-ai/mask`, built from the same source as `@conarium-ai/core`,
with no side effects on import and two dependencies
(`@eslint-community/regexpp`, `re2js`). `@conarium-ai/core` was not used
because it brings the gateway's server and database dependencies.
`maskField` reports what it found per class (`classes`), what it replaced
(`masked`), and masks only the classes it is asked to (`only`).
`packages/proxy` pins `@conarium-ai/mask` to an exact version, the way it
pins `@cedulon/*`. The code is not copied: one masking implementation, so a
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
