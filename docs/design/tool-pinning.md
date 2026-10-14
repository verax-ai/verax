# Tool definition pinning — design, not built


Status: design only. Nothing in this document is in the tree.

## What exists

- A downstream child is described in the operator's document
  (`VERAX_DOWNSTREAM`, `docs/design/downstream.md` §1): `command`/`args` or
  `url`, optional `tools` (names to attach), optional `effectKeyPem`.
- At `listen()` the body asks the child for `tools/list` once
  (`packages/body/src/downstream.ts` `openDownstream`), parses it with the
  SDK's `ListToolsResultSchema` (which drops fields the schema does not know),
  bounds each entry and republishes the prefixed name, `description` and
  `inputSchema` to the brain (`downstream.ts:513`, `server.ts:281`). Any
  attach error stops the start (`server.ts` `attachDownstream`), and the
  design keeps it that way (`downstream.md:191`: no half attach).
- Nothing records what the child listed. A child that changes a tool's
  description or schema between two starts, or adds or removes a tool, is
  attached as if it were the same child.

## Threat

The tool server is hostile (`THREAT_MODEL.md`). A description is text the
brain follows; a server can put an instruction in it after the operator
looked at it once ("rug pull", "tool poisoning"). The operator's rule names
a tool; the name stays while the meaning changes. Scanners outside the gate
(MCP-Scan, mcp-audit) hash descriptions on first scan and compare later.
The gate is the one place every start passes through, so the comparison
belongs there and the record of it belongs in a signed row.

Out of scope here, and said so: tool results and error text reach the brain
on every call (`downstream.ts:275`, `:533`) and can carry the same
instruction with no change to any definition. Pins do not cover them;
`THREAT_MODEL.md` already says results are not filtered.

## Proposal

1. **What is pinned.** The digest is `sha256Canonical` of the tool entry
   **after** `ListToolsResultSchema` parsing — the object the body actually
   holds — taken whole, with every key it has (name, title, description,
   inputSchema, outputSchema, annotations, icons, execution, `_meta`, and
   any key a later SDK keeps). The digest is not built from a list of named
   fields. Pin and attach call the same function on the same parsed shape.
   It is a digest of the parsed object, not of the bytes on the wire: keys
   the SDK drops, and numbers JSON parsing merges, are not distinguished.
   No Unicode normalisation: NFC and NFD spellings are different digests.
2. **Deterministic publication.** The body republishes each downstream tool
   with object keys sorted recursively (array order kept, it can carry
   meaning), and the downstream part of the tool list sorted by prefixed
   name. The native tools keep their order (`tool-meta.test.ts:16–20` holds
   it). Two schemas that differ only in key order pin the same and are
   shown the same.
3. **Check at attach.** When a spec has `pins`:
   - with no `tools`: the set of pinned names and the set of listed names
     must be equal. A listed name with no pin →
     `downstream-tool-unpinned:<prefix>.<name>`; a pinned name not listed →
     `downstream-tool-unlisted:<prefix>.<name>`;
   - with `tools`: every selected name must have a pin, and only selected
     names are compared; the rest of the child's list is still never read
     past its name;
   - a digest that differs → `downstream-definition-changed:<prefix>.<name>`.
   Each stops the start, as every attach error does today.
4. **Manifest, not only a hash.** Each pin set the operator approves is a
   content-addressed file `{ v: 1, prefix, selected: [...] | null,
   tools: { <name>: <parsed entry> } }` named `<sha256>.json`, kept in a
   `definitions/` directory **next to the downstream document** (the
   operator's file, which the body already reads; in an installed layout the
   operator cannot write the state directory, `install.ts:2684`). The
   document's spec names it: `pins: "sha256:<manifest digest>"`. At attach
   the body:
   - reads the manifest once and checks that the canonical hash of the bytes
     it read equals the digest in the document; missing, unreadable or
     different → `downstream-manifest-invalid:<prefix>`, start stops;
   - checks `manifest.prefix` equals the spec's prefix and
     `manifest.selected` equals the spec's `tools` as a set (both absent
     counts as equal); otherwise `downstream-manifest-mismatch:<prefix>`.
     A change of selection needs a new manifest;
   - compares each tool's digest against that same snapshot;
   - copies the manifest into the state directory as
     `definitions/<sha256>.json` (create-only; an existing file with the same
     name must have the same bytes, else start stops) **before** it writes
     the start row, so `verify` can read it from the state directory.
5. **Signed record.** The start row (`heartbeat.ts`, v2) gains an optional
   `downstream: [{ prefix, manifest }]` (`manifest` = digest, or `null`
   with no pins). `verify` checks that each named manifest file exists and
   hashes to its name, and reports which definitions were in force for each
   start. The field is optional: existing v1 and v2 rows verify unchanged,
   and nothing is added to an old row. What this proves, and no more: the
   body that held a trusted record key recorded these definitions at that
   start. It does not prove that a person read them or that the child's
   code behaves as described. Reading the state directory in an installed
   layout needs the account that can (`verify-cli.ts:334` exits 77
   otherwise) or a full copy for offline `verify`.
6. **Pinning is an operator act.** `verax downstream pin --file <doc>
   --prefix <p>`:
   - before connecting, says which account will run the child (the account
     running the command, which may not be the body's account) and refuses
     to spawn a stdio child as an elevated account;
   - lists once and keeps that snapshot. Everything shown is JSON-escaped:
     control characters, escape sequences (ESC, OSC), bidirectional and
     zero-width characters are printed as visible `\uXXXX`. The child's
     stderr and error text are shown the same way, never raw;
   - shows the full entries (no truncation) and the difference against the
     manifest the document names now;
   - after the operator types `yes`, writes the manifest from **that**
     snapshot (no second listing) into the document's `definitions/`
     directory, create-only, and prints the one line to put in the
     document (`"pins": "sha256:…"`). It never edits the document itself,
     so there is no read-compare-write race with another editor.
7. **Doctor.** `verax doctor` reports each child with no `pins`, and each
   stdio command that fetches a package with no version (`npx <name>`,
   `uvx <name>`; `npx --package <name>@<v>` and `uvx --from <name>==<v>`
   count as versioned). A version is a name for the code, not proof of it.

## Second slice (after the first is in)

Shape warnings in the pin command: phrases that address the model ("ignore
previous", `<IMPORTANT>`), names of other tools, paths such as `~/.ssh` or
`.env`, base64/hex runs over 64 characters, a description over 2 KiB.
Printed next to the entry; never a decision.

## What this does not do

- Read a description for meaning.
- Cover tool results, error text, server `instructions`, prompts or
  resources (the last three are not republished today; if they ever are,
  they join the manifest).
- Follow `notifications/tools/list_changed`; the set stays fixed at
  `listen()`.
- Protect a document the agent can write (`THREAT_MODEL.md`, "a brain with
  a shell").
- Refuse only one child. Whole-start refusal stays until a visible
  quarantine state exists (later work).

## Tests first

- Fixture child, one tool. Second start with one change each in
  description, inputSchema, annotations, `_meta`, icons → each
  `downstream-definition-changed`.
- No `tools`: child adds a tool → `unpinned`; child drops a pinned tool →
  `unlisted`. With `tools`: selected name unpinned → `unpinned`.
- Key order inside `inputSchema` swapped → same digest, and the published
  JSON text identical.
- `pins` absent → today's behaviour; existing attach tests unchanged.
- Start row with `downstream` verifies; old v1/v2 rows verify; a changed
  `manifest` value in a signed row → signature failure; a manifest file
  edited → `verify` names it.
- Pin command: a description containing `\u001b[2J` and `‮` is
  printed escaped; no write without typed `yes`; the manifest equals the
  displayed snapshot when the child answers differently on a second list;
  the document changed during the prompt → no write.
- Manifest edited after pinning (document unchanged) → `manifest-invalid`;
  manifest missing → `manifest-invalid`; document `tools` narrowed from
  `[a,b]` to `[a]` with the old manifest → `manifest-mismatch`; manifest of
  another prefix → `manifest-mismatch`.
- State copy: start writes `definitions/<H>.json` before the start row; a
  different file already under that name → start stops.
- Pin command never writes the downstream document; a second run with the
  same snapshot writes nothing new.
- Native tool order unchanged (`tool-meta.test.ts`); downstream section
  sorted.
- Mutations: compare only description → red; skip the manifest hash check →
  edited-manifest case red; skip the selection check → narrowed-tools case
  red; skip the reverse set check →
  `unlisted` red; build the digest from named fields → icons case red;
  print raw → escape case red.
