# Data classes v1

Status: step 1 of the order of work (text classes on tool-call arguments,
the file-type block, signed counts) and step 3 (audio, with `resultClasses`)
are in the tree; see "What is in the tree". The panel (2) and photos (4)
are not. Transcripts are masked with Conarium's `speech` pipeline
(`@conarium-ai/mask` 0.3.4).

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
  `file-type-block:<ext>` (each string is split into tokens on whitespace,
  quotes and shell punctuation; in each token a URL query or fragment is
  cut, escapes are decoded, an NTFS stream suffix, trailing separators and
  dot segments are dropped; this is a filter on names as they appear, not a
  boundary: a name the agent encodes or renames is not caught), `data-class-key:<class>` (a key cannot be masked),
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

`packages/proxy/src/result-classes.ts`, called from `runInner` in `proxy.ts`
after the effect row is written; every point below is a test in
`packages/proxy/tests/result-classes.test.ts` except a throw from the
masker, which is
`packages/proxy/tests/result-classes-error.test.ts`.

- **Policy.** A `version: 2` document may carry `resultClasses` (class →
  `allow` / `mask` / `block`) and `media` (`audio` → `allow` / `transcribe` /
  `withhold`, `image` → `allow` / `withhold`, and `transcriber` when audio is
  `transcribe`). `local` is refused: a result is already here. A rule may
  carry its own `resultClasses`. Under `version: 1` both keys are refused.
- **Text results.** Text blocks are masked with the merged `resultClasses`.
  A block over the scan cap is split at line breaks into pieces under the
  cap; a single line over the cap is replaced whole. A line of exactly the
  cap followed by a break is scanned without the break, and the break is
  put back. A `block` class in a text block or a transcript withholds the
  whole result (`withheld:result-class-block:<class>:<ref>`); the tool has
  already run. A throw from the masker while scanning a text block or a
  transcript withholds the whole result
  (`withheld:result-class-error:<ref>`) and writes a signed deny
  (`result-class-error`).
- **Error text.** When the policy sets `resultClasses` or `media`, a throw
  that leaves `runInner` has its message scanned as a text block. A `block`
  class becomes `withheld:result-class-block:<class>:<ref>`; a masker throw
  becomes `withheld:result-class-error:<ref>`. The error that leaves is a
  new object with the masked message, the original's prototype (so
  `instanceof` still holds), and no cause or other fields beyond
  `prefix`/`tool`; a non-Error throw becomes an Error. A throw inside the
  error gate itself is `withheld:result-class-error:<ref>`, never the
  original. The `:threw` row is written first, over the original payload.
  When the message changed, a result record is chained: `returnedHash`
  over `{ error: <message as it leaves> }`, `requestHash` the `:threw`
  row's `resultHash`. Without those keys, errors leave as before.
- **Media.** `body` keeps `image` and `audio` blocks as blocks when `data`
  and `mimeType` are strings; other block types stay JSON text. Without
  `resultClasses` and `media`, results are not changed. Once either key is
  set, a kind the document does not name is `withhold`. `transcribe` writes
  the bytes into a temporary directory, starts `command[0]` without a shell
  (it must be an executable; on Windows a `.cmd` or `.bat` cannot be
  started this way) with `{file}` replaced, masks the stdout with
  `resultClasses` under the `text` pipeline, and replaces the block as
  `[audio transcript] <masked text>`. A timeout, a non-zero exit, empty
  output or output over the scan cap is `[audio withheld: transcriber-failed]`.
  On a timeout the transcriber is stopped with its process group (on
  Windows, with node's job object); a process that leaves its group is not.
  On a timeout or output over the cap the call ends at once: the child's
  stdout and stderr are destroyed and the gate does not wait for `close`.
  The temporary directory is removed after the run; if that fails, one
  stderr line names the directory.
- **Record.** The effect row's `resultHash` is the hash of the result as the
  tool returned it. When the gate changes or withholds anything, a chained
  decision names the call in `inputs.resultOf` and carries
  `inputs.resultClasses: { masked, transcribed, withheld, returnedHash }`:
  counts and the hash of what the agent received, never a value or
  transcript. An `allow` carries the effect row's `resultHash` as its
  `effectHash` too, because a signed allow needs an effect hash; a `deny`
  carries none. Ledger verification reads that record as a statement about a
  result (`result-record-mismatch` when `resultOf` or `requestHash` does not
  match the call's effect row; when the decision is not `allow` or `deny`;
  when an `allow`'s `effectHash` is not its `requestHash` or a `deny`'s is
  not null; when `returnedHash` is not 64 lowercase hex; when `masked` or
  `withheld` is not a map of positive integers or `transcribed` is not a
  non-negative integer; when `subject` is not the named call's
  `effectClass`, `:threw` allowed for an error; or when two result records
  name the same call). If the record cannot be written, the result is not
  delivered (`result-unrecorded:<ref>`).

Not built: operator pattern classes (`{ choice, pattern }`), the panel,
and photos.

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
(`masked`), and masks only the classes it is asked to (`only`). Conarium
0.3.4 adds `pipeline: 'speech'`, which Verax uses for transcripts.
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
- `fileTypes.block` is checked on every string of the arguments, split
  into tokens as "What is in the tree" says.

## Order inside the gate

1. Policy decides allow, defer or deny as today.
2. For an allow, the class scan runs on every string, key and number of the
   arguments and on `_ref` and `_inputs`. A `block` class or a blocked file type turns the allow into a signed deny
   (`data-class-block:<class>`, `file-type-block:<ext>`). A `local` class to
   a non-local tool is a signed deny.
3. Otherwise `mask` classes are replaced, and the **masked** arguments are
   what is forwarded.
4. The decision record keeps `requestHash` over the arguments as the agent
   sent them and adds `forwardedHash` over what was forwarded, with a count
   per class (`masked: { email: 2 }`), never the values. A reader can then
   check that what left matches `forwardedHash`, and the record says what
   was removed without repeating it.
5. Results coming back are scanned before the agent sees them
   (`resultClasses`); see "Results and audio".

`requestHash` over the original arguments is a hash of personal data; see
`docs/design/erasure.md` for why that hash should become keyed. The two
designs meet there: data classes say what did not leave; erasure says what
was kept and can be destroyed.

## Results and audio (step 3)

**Measured first.** A local speech model on Turkish, one Windows machine, two
synthetic recordings that carry a test ID number, an IBAN, an e-mail address
and a phone number. `faster-whisper` with `large-v3-turbo` on the recording
read the way people say numbers: the text masker then caught the ID number
and the phone number; the IBAN was masked but its last digits were split off
and left; the e-mail address lost its `@` and was not recognised. The `small`
model gave the masker nothing it caught. So transcripts need harsher rules
than typed text (below), and the claim stays "masks what it recognises".

**Which way audio crosses the gate.** MCP tools return audio and images as
result content blocks (`{ "type": "audio", "data": <base64>, "mimeType": … }`);
the reference filesystem server's `read_media_file` does. Today `body` turns
every block that is not text into JSON text, so a recording reaches the agent,
and from there its model, as base64 text, and no result is scanned. A tool
that takes audio as an argument cannot be handed a transcript instead, so
step 3 works on results. Audio in arguments stays under the rules above: a
base64 string over the scan cap is replaced whole when a class is masked, or
refused as unscanned.

**Media blocks keep their type.** `body` passes `image` and `audio` blocks
through as blocks (`type`, `data`, `mimeType`); other block types stay JSON
text as today. Without `resultClasses` and `media` in the policy, results are
not changed, so the agent receives images and audio as media instead of as
JSON text.

**Policy.** Version 2 adds two keys:

```json
"resultClasses": { "tckn": "mask", "iban": "mask", "email": "mask", "phone": "mask" },
"media": {
  "audio": "transcribe",
  "image": "withhold",
  "transcriber": { "command": ["transcribe-local", "{file}"], "timeoutMs": 60000 }
}
```

- `resultClasses`: class → `allow`, `mask` or `block`, the class names of
  `dataClasses`. `local` is refused at load: a result is already here. A
  rule may carry its own `resultClasses` for its tool.
- `media.audio`: `allow` (the block reaches the agent as audio),
  `transcribe`, or `withhold` (the block is replaced by a label).
  `media.image`: `allow` or `withhold` until step 4. Once `resultClasses` or
  `media` is set, a media kind it does not name is `withhold`.
- `transcribe` needs `media.transcriber.command`: an array of strings with
  `{file}` in exactly one of them, run without a shell. Without it the load
  stops.

**Transcribe.** The block's bytes are written into a new temporary directory
only the current user can read; `command[0]` is started without a shell, so
it must be an executable (on Windows a `.cmd` or `.bat` cannot be started
this way); `{file}` is replaced; its standard output, UTF-8 and trimmed, is
the transcript; the directory is removed after the run, and if that fails
one stderr line names it. On a timeout the transcriber is stopped with its
process group (on Windows, with node's job object); a process that leaves
its group is not. On a timeout or output over the cap the call ends at
once: the child's stdout and stderr are destroyed and the gate does not
wait for `close`. The transcript is
masked with `resultClasses` and replaces the block as text:
`[audio transcript] <masked text>`. A timeout, a non-zero exit, empty
output, or output over the scan cap replaces the block with
`[audio withheld: transcriber-failed]`. Once `transcribe` or `withhold` is
chosen, the audio block does not reach the agent in any case. The
transcriber runs on this machine; Verax does not check what it does with
the file, the same trust it gives `localTools`.

**Text results.** Text blocks are masked with `resultClasses`. A result is
often longer than the scan cap (a file, a query), so a text block over the
cap is split at line breaks into pieces under the cap and each piece is
scanned; a single line over the cap is replaced whole. A line of exactly
the cap followed by a break is scanned without the break, and the break is
put back. A value that spans two pieces is not recognised. A throw from
the masker while scanning a text block or a transcript withholds the whole
result (`withheld:result-class-error:<ref>`) and writes a signed deny
(`result-class-error`), the same as on the argument side (`data-class-error`).

**Error text.** When the policy sets `resultClasses` or `media`, a throw
that leaves `runInner` has its message scanned as a text block. A `block`
class becomes `withheld:result-class-block:<class>:<ref>`; a masker throw
becomes `withheld:result-class-error:<ref>`. The error that leaves is a
new object with the masked message, the original's prototype (so
`instanceof` still holds), and no cause or other fields beyond
`prefix`/`tool`; a non-Error throw becomes an Error. A throw inside the
error gate itself is `withheld:result-class-error:<ref>`, never the
original. The `:threw` row is written first, over the original payload.
When the message changed, a result record is chained: `returnedHash`
over `{ error: <message as it leaves> }`, `requestHash` the `:threw`
row's `resultHash`. Without those keys, errors leave as before.

**Block.** A `block` class in a text block or a transcript withholds the
whole result: the agent gets `withheld:result-class-block:<class>:<ref>` as
an error. The tool has already run, and its effect row stands.

**Record.** The effect row's `resultHash` stays the hash of the result as the
tool returned it. When the gate changes or withholds anything, a signed
decision record is chained with its own ref: `inputs.resultOf` names the
call's ref, its `requestHash` is that effect row's `resultHash`, and
`inputs.resultClasses` carries `{ masked, transcribed, withheld,
returnedHash }`: counts, and the hash of what the agent received, never a
value or transcript text. An `allow` carries the effect row's `resultHash`
as its `effectHash` too, because a signed allow needs an effect hash; a
`deny` carries none. Ledger verification reads it as a statement about a
result, not as an allow that needs an effect row, and holds the record to
those hashes and counts, to a decision of `allow` or `deny`, to `subject`
matching the named call's `effectClass` (`:threw` allowed for an error),
and to at most one result record naming a call (`result-record-mismatch`).
If it cannot be written,
the result is not delivered (`result-unrecorded:<ref>`).

**Speech rules, in Conarium.** In a transcript, digits come split by hyphens
and spaces and the `@` can be lost. These rules are Conarium's `speech`
pipeline (`@conarium-ai/mask` 0.3.4), so the `text` rules do not move. What
it masks and what it leaves is stated once, in Conarium's
`docs/API-STABILITY.md` row for `pipeline: 'speech'`, not here. Transcripts
use it (`TRANSCRIPT_MASK_PIPELINE` in `packages/proxy/src/result-classes.ts`);
text results and a tool's error text keep `text`, because the speech rules
would mask an order number of 7 or more digits or a spaced amount.

**Not in step 3:** images beyond `allow` and `withhold` (step 4), audio in
arguments beyond the whole-field rules, and transcription anywhere but the
machine Verax runs on.

## Order of work

1. Text classes and file-type block on arguments, Conarium engine via a
   library entry, signed counts; unknown policy keys refused.
2. Panel: the operator picks a choice per class; the panel writes the
   policy document, the body loads it as today.
3. Audio: a recording does not leave. It is transcribed on the machine,
   the transcript goes through the same classes, and either the masked
   transcript or nothing reaches the agent; see "Results and audio", which
   also brings `resultClasses` for text results.
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
