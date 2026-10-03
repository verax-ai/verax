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
headers as in Section 7.2 of
[draft-dogru-cedulon-core-03](https://datatracker.ietf.org/doc/draft-dogru-cedulon-core/03/).

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

The two `valid-*` vectors were written by a running Verax body over HTTP, with
a witness process beside it signing effects and the checkpoint
([`tools/capture.ts`](tools/capture.ts)). Each `fail-*` vector changes one
thing in a copy of `valid-full` ([`tools/generate.ts`](tools/generate.ts)).
Where the change alters a record's octets, every later record is re-linked and
re-signed and the checkpoint is re-signed, so the only check that can fail is
the one the vector names. The keys are test keys generated for this set; the
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

## Stages

A negative vector names the first check that must fail, in this order:

| stage | what fails |
|---|---|
| `record-header` | not an untagged COSE_Sign1; alg not -19; content type not `application/cedulon-decision-record+cbor`; unprotected header not empty; kid not the pinned key's |
| `record-signature` | Ed25519 over the RFC 9052 Sig_structure |
| `record-claims` | the decoded payload breaks a claim rule (decision profile 4.2), or differs from the claims presented beside it |
| `chain` | `prevRecordHash` is not SHA-256 of the previous record's COSE_Sign1 octets |
| `inputs-binding` | a record's signed `inputsHash` does not match its inputs row, or the row is missing |
| `effect-binding` | an effect row does not bind to the allow that admitted it |
| `index` | the index names a record the ledger no longer holds |
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

`valid-full` holds eight records: a write deferred for approval, the
operator's passkey approval, the agent's retry that runs it, an allowed read,
a refused spend, a halt, a read refused while halted, a resume and an allowed
read. Each vector's `expected.json` says what was changed.

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
(`--key`, `--witness-key`, `--checkpoint-key`, `--operator-credentials`) and
compares the verdict and the first problem line with `expected.json`. `--bin`
runs another build, for example a published one:

```bash
npm install @verax-ai/body@0.4.2
node --experimental-strip-types test-vectors/tools/run.ts --bin node_modules/@verax-ai/body/dist/cli.js
```

`verax verify` reports the three record stages as one line
("signature does not verify"), so for those vectors the runner accepts any of
the three; the by-hand checker tells them apart.

Verax 0.4.2 as published reaches 14 of the 16 expected results. It accepts
`fail-inputs-approver-downgraded` and `fail-checkpoint-totals`: it did not
check inputs rows against `inputsHash`, and it did not compare checkpoint
totals. Both checks were added to `verax verify` with this set.

## What a green run shows

That your verifier reads these encodings and reaches the same verdict at the
same stage, over bytes it did not produce. It does not show that two record
models mean the same thing, that a draft is aligned with another, or anything
about adoption. All of these vectors were produced by one implementation;
they are a seed set, not independent conformance.
