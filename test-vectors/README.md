<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verax ledger test vectors

A frozen set of Verax ledgers for cross-implementation checks: run the
committed bytes through *your* verifier and compare with each vector's
`expected.json`. A disagreement with your implementation is the report we
want, on acceptance and on rejection alike. Please open an issue with your
verifier's output.

The record format is the Decision Record of
[draft-dogru-cedulon-decision-profile-03](https://datatracker.ietf.org/doc/draft-dogru-cedulon-decision-profile/03/):
an untagged COSE_Sign1 with Ed25519 under algorithm -19 ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)),
headers as in Section 6.2 of
[draft-dogru-cedulon-08](https://datatracker.ietf.org/doc/html/draft-dogru-cedulon-08), which the
decision profile references normatively.

## Stability

`v1/` is append-only. Once merged, no file under it changes. A correction or
an addition ships as a new vector or a new version directory, with a note in
`manifest.json`. [`SHA256SUMS`](SHA256SUMS) lists the digest of every file
under `v1/`, and the test suite fails on any file that is missing from it, is
not listed in it, or no longer has its digest.

```bash
cd test-vectors && sha256sum -c SHA256SUMS
```

## Where the bytes come from

`valid-full`, `valid-deny-only` and `valid-full-2` were written by a running
Verax body over HTTP, with a witness process beside it signing effects and the
checkpoint ([`tools/capture.ts`](tools/capture.ts)); `valid-anchored` is
`valid-full` with a receipt added. Each `fail-*` vector changes one thing in a
copy of `valid-full` ([`tools/generate.ts`](tools/generate.ts)), or of
`valid-full-2` for the two appended with it
([`tools/append.ts`](tools/append.ts)). Where the change alters a record's
octets, every later record is re-linked and re-signed and the checkpoint is
re-signed, so the only check that should fail is the one the vector names;
`fail-allow-while-halted` is the exception noted below. The keys are test keys generated for this set; the
private halves were discarded.

## Layout

```
manifest.json          index: version, stability, stage order, vectors[]
SHA256SUMS             digest of every file under v1/
v1/<vector-id>/
  ledger/              decisions.jsonl, effects.jsonl, inputs.jsonl,
                       index.jsonl, checkpoints.jsonl, as the body writes them
  pins/                keys a reader holds out of band:
                       record-key.pem    the Decider's record key (SPKI PEM)
                       witness-key.pem   signs same-org effect receipts and checkpoints
                       operator-credentials.json  the operator's passkey (COSE key)
  expected.json        verdict, first failing stage, the record hashes
tools/                 capture, generate, run, and the by-hand checker
```

Each line of `inputs.jsonl` is `{ref, inputs}`. A record's `inputsHash` is
SHA-256 over the RFC 8785 form of the row's `inputs` member, not of the whole
row; `ref` joins the row to its record. The decision profile does not define
this layout; it is Verax's.

## Stages

A negative vector names the first check that must fail, in this order:

| stage | what fails |
|---|---|
| `record-header` | not an untagged COSE_Sign1; alg not -19; content type not `application/cedulon-decision-record+cbor`; unprotected header not empty; kid not the pinned key's |
| `record-signature` | Ed25519 over the RFC 9052 Sig_structure |
| `record-claims` | the decoded payload breaks a claim rule (decision profile 4.2), or differs from the claims presented beside it |
| `chain` | `prevRecordHash` is not SHA-256 of the previous record's COSE_Sign1 octets |
| `inputs-binding` | a record's signed `inputsHash` does not match its inputs row, or the row is missing |
| `effect-binding` | an effect row does not bind to the allow that admitted it, or an allow outside the boundary allowance has no effect row (`decision-without-effect`) |
| `index` | the unsigned `index.jsonl` cannot be read; it names a ref the ledger no longer holds as a decision; it marks a ref as having an effect (`kind` `effect` or `hasEffect` true) with no bound effect row; a non-empty line is not JSON, unless it is the last line and an earlier line parsed; or a line is JSON but not an object, such as `null`. A row whose `ref` or `piece` is not a string is skipped, so its ref is not compared; no other field of a row is checked |
| `approval-signature` | the operator's WebAuthn assertion on an approval does not verify against the challenge rebuilt from the held record |
| `checkpoint-signature` | the witness signature on a checkpoint |
| `checkpoint-coverage` | the checkpoint counts records, or names a head, the ledger no longer holds |
| `checkpoint-totals` | the checkpoint's allow / deny / defer totals differ from the records in its window |
| `control` | an allow inside a halt window opened by a signed halt record |

## The vectors

| id | result | first failing stage |
|---|---|---|
| `valid-full` | VALID | - |
| `valid-deny-only` | VALID | - |
| `fail-record-signature` | INVALID | `record-signature` |
| `fail-record-alg-8` | INVALID | `record-header` |
| `fail-record-content-type` | INVALID | `record-header` |
| `fail-record-key-not-pinned` | INVALID | `record-header` |
| `fail-record-claims-mismatch` | INVALID | `record-claims` |
| `fail-record-claim-rule` | INVALID | `record-claims` |
| `fail-chain-removed` | INVALID | `chain` |
| `fail-inputs-approver-downgraded` | INVALID | `inputs-binding` |
| `fail-approval-signature` | INVALID | `approval-signature` |
| `fail-effect-hash` | INVALID | `effect-binding` |
| `fail-checkpoint-signature` | INVALID | `checkpoint-signature` |
| `fail-tail-truncated` | INVALID | `checkpoint-coverage` |
| `fail-checkpoint-totals` | INVALID | `checkpoint-totals` |
| `fail-allow-while-halted` | INVALID | `control` |
| `valid-anchored` | VALID | - |
| `valid-full-2` | VALID | - |
| `fail-effect-extract-body` | INVALID | `effect-binding` |
| `fail-allow-while-halted-witnessed` | INVALID | `control` |

`valid-full` holds eight records: a write deferred for approval, the
operator's passkey approval, the agent's retry that runs it, an allowed read,
a refused spend, a halt, a read refused while halted, a resume and an allowed
read. Each vector's `expected.json` says what was changed.

`valid-anchored` is `valid-full` with its checkpoint registered at the public
capsule-anchor instance, `https://witness.agentactioncapsule.org`, through
`POST /register`, which received only the checkpoint hash.
`ledger/checkpoint-anchors.jsonl` holds the RFC 9162 COSE Receipt (leaf 2542
of a tree of 2543). `pins/anchor-key.pem` is the service key; it is the key
published at `/.well-known/did.json` and `/anchor/authority-pubkey`, which
agreed when the receipt was taken, and you can fetch it yourself. The receipt
proves the service's log held that hash at that tree size; it does not show
the service agrees with anything the checkpoint counts.

The first capture's private keys were discarded, so a vector that re-signs an
effect extract cannot be cut from `valid-full`. `valid-full-2` is the same
scenario captured again under new keys, by a body that also signs the resume
with the operator's passkey; the two vectors after it each change one thing in
a copy of it and carry its pins. `fail-effect-extract-body` re-signs the first
read's extract over a row with a different `effectHash` and leaves the
presented row as it was. `fail-allow-while-halted-witnessed` is cut from
`valid-full-2` the way `fail-allow-while-halted` is cut from `valid-full`, and
its one change also gives the forged allow a witness-signed effect row, so
every allow has its row.

### Where the drafts decide the stage

- **Which key signs a checkpoint.** In these ledgers a witness process signs
  the checkpoint under its own key (`pins/witness-key.pem`), separate from the
  record key and under the same operator. Decision profile -03 says the
  Decider signs checkpoints; read that way, every valid vector that carries a
  checkpoint fails at `checkpoint-signature`. The next profile revision is to let a deployment pin
  a separate checkpoint key and require it to state which key it uses.
- **`fail-allow-while-halted`.** The forged allow has no effect row and sits
  30 ms after the halt's extract window, inside the core's five-minute
  clock-skew allowance. A verifier that applies no allowance, departing from
  the profile's boundary rule, fails it first at `effect-binding`. One that
  applies the allowance reports it as `boundary-deferred`, a warning, and
  fails it at `control`; whether that deferral would harden turns on whether
  the next per-row extract counts as the following window's extract, which
  the profile does not yet say. `expected.json` names `control`;
  `manifest.json` notes both. In `fail-allow-while-halted-witnessed` every
  allow has its row, and Verax fails it at `control`.
- **`fail-effect-hash`.** The vector changes the presented effect row, not the
  extract that signs it. A verifier can fail it at `effect-binding` because the
  presented row no longer matches its allow, or because it no longer matches
  the row the extract signs; the vector does not tell those two checks apart.
  `fail-effect-extract-body` does: its presented row still matches its allow,
  and only the signed row differs.

## Verify by hand (records and chain)

The first four stages need nothing beyond the two drafts, RFC 9052 and an
Ed25519 library. [`tools/verify_by_hand.py`](tools/verify_by_hand.py) is that
recipe as code; it uses no Verax code.

```bash
pip install cbor2 cryptography
python test-vectors/tools/verify_by_hand.py --all test-vectors
```

For each line of `ledger/decisions.jsonl`:

1. Hex-decode `coseHex` and CBOR-decode it. It must be an untagged array of
   four: protected (bstr), unprotected, payload (bstr), signature (bstr).
2. Decode the protected header. Require `1` (alg) = -19, `3` (content type) =
   `application/cedulon-decision-record+cbor`, and `4` (kid) = the first eight
   bytes of SHA-256 over the SubjectPublicKeyInfo DER of `pins/record-key.pem`.
   Require the unprotected header to be an empty map.
3. Verify the Ed25519 signature over
   `["Signature1", protected, h'', payload]`, CBOR-encoded.
4. Decode the payload: a map with exactly the labels -70501 to -70513
   (decision profile 4.1). Apply the claim rules of 4.2 yourself: an allow has
   a ref, an effectHash and an effectClass; a refusal has effectHash null;
   every hash is 64 lowercase hex characters. Require the decoded claims to
   equal the `claims` object presented beside the record.
5. Require `prevRecordHash` to be null for the first record and SHA-256 of
   the previous record's COSE_Sign1 octets for every later one.

For a vector whose failure lies beyond the chain, every record must pass these
five steps: the change in that vector is elsewhere.

## Run with Verax

```bash
node --experimental-strip-types test-vectors/tools/run.ts
```

The runner calls `verax verify` once per vector with every key pinned
(`--key`, `--witness-key`, `--checkpoint-key`, `--operator-credentials`, and
`--anchor-key` when the vector has one) and
compares the verdict and the first problem line with `expected.json`. `--bin`
runs another build, for example a published one:

```bash
npm install @verax-ai/body@0.4.2
node --experimental-strip-types test-vectors/tools/run.ts --bin node_modules/@verax-ai/body/dist/cli.js
```

`verax verify` reports the three record stages as one line
("signature does not verify"), so for those vectors the runner accepts any of
the three; the by-hand checker tells them apart.

Verax 0.4.3 reaches all 20. Verax 0.4.2 reaches 15 of the first 17: it accepts
`fail-inputs-approver-downgraded` and `fail-checkpoint-totals`, because it did
not check inputs rows against `inputsHash` or compare checkpoint totals, and it
passes `valid-anchored` without reading the receipt at all. Those checks and
`--anchor-key` were added in 0.4.3.

Builds after 0.4.3, unreleased as of this change, also hold every allow to an
effect row, without reading the unsigned `index.jsonl`: an allow with no row
is `decision-without-effect`, and one within five minutes of the newest record
is reported as `boundary-deferred`, a warning, since its row may not be
written yet. They report the forged allow in `fail-allow-while-halted` that
way and still fail the vector at `control`.

## Independent runs

Two readers ran the set with verifiers of their own and posted the results in
[mirjak/audit-bof-preparation#9](https://github.com/mirjak/audit-bof-preparation/issues/9).
Their questions led to the notes above.

- Tymofii Pidlisnyi (Agent Passport System), with a runner in the APS
  conformance suite: a partial, stage-by-stage comparison across all 16
  vectors at `vectors-v1`, not a whole-ledger verdict
  ([run](https://github.com/mirjak/audit-bof-preparation/issues/9#issuecomment-5972115527)).
- Roberto Locatelli (cryptovalid-opencore), with clean-room checkers written
  from the drafts, the RFCs, this README and, for two file layouts, the vector
  files: with the checkpoint verified under the witness key, 16 of 16 verdicts
  and 15 of 16 first failing stages at `vectors-v1`. One of those matches
  came from a rule added after reading the vector, as the run itself states
  ([run](https://github.com/mirjak/audit-bof-preparation/issues/9#issuecomment-5979503944)).

## What a green run shows

That your verifier reads these encodings and reaches the same verdict at the
same stage, over bytes it did not produce. It does not show that two record
models mean the same thing, that a draft is aligned with another, or anything
about adoption. All of these vectors were produced by one implementation;
they are a seed set, not independent conformance.
