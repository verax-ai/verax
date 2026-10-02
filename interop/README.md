<!-- SPDX-License-Identifier: Apache-2.0 -->
# Interop runs

Other implementers' frozen vectors, run through checks written in this
repository. Each run states the pinned commit of the vectors, the verifier,
the result per vector and the first failing stage of every negative. The
verifiers use no code from the repositories whose vectors they run.

## scitt-cose `vectors-ietf126`

Vectors: [action-state-group/scitt-cose](https://github.com/action-state-group/scitt-cose)
tag `vectors-ietf126` at `529515ba7445af0f07e5da578ad938e371e8c7a8`.
Verifier: [`scitt-cose-vectors-ietf126/verify.ts`](scitt-cose-vectors-ietf126/verify.ts),
written from RFC 8949, RFC 9052, RFC 9162 and the set's README, with a CBOR
decoder of its own and Node built-ins only.

```bash
git clone https://github.com/action-state-group/scitt-cose && git -C scitt-cose checkout vectors-ietf126
node --experimental-strip-types interop/scitt-cose-vectors-ietf126/verify.ts scitt-cose/test-vectors
node --experimental-strip-types interop/scitt-cose-vectors-ietf126/verify.ts scitt-cose/test-vectors --mutate
```

`SHA256SUMS` verified every listed file. Stages: statement-decode,
statement-sig, leaf-entry, vds-gate, receipt-decode, inclusion, receipt-sig.

| vector | expected | result | first failing stage |
|---|---|---|---|
| `valid-eddsa` | VALID | VALID, reconstructed root equals `expected.json` | - |
| `valid-es256` | VALID | VALID, reconstructed root equals `expected.json` | - |
| `fail-tampered-path` | INVALID `TAMPERED_INCLUSION_PATH` | INVALID | `receipt-sig`, over the root rebuilt from the committed path |
| `fail-unsupported-vds` | INVALID `UNSUPPORTED_VDS` | INVALID | `vds-gate` (vds read from the protected header) |
| `fail-bad-statement-sig` | INVALID `BAD_STATEMENT_SIGNATURE` | INVALID | `statement-sig` |
| `valid-ccf-vds2` | VALID | SCOPE-OUT | stops at `vds-gate`: the CCF receipt profile (vds 2) is not implemented here |

`--mutate` flips one statement payload byte, one statement signature byte and
one audit-path byte of `valid-eddsa`; each fails closed, at `statement-sig`,
`statement-sig` and `receipt-sig`. Two runs produce byte-identical
[`results.json`](scitt-cose-vectors-ietf126/results.json).

## aps-conformance-suite `accountability-record` v0.1.0

Vectors: [aeoess/aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite)
tag `v0.1.0` at `4b9dbb006642f2c47800f62412db3a4b6a1b42e4`,
`fixtures/accountability-record/accountability-record-fixture-v1.json`.
Verifier: [`aps-accountability-record-v0.1.0/verify.ts`](aps-accountability-record-v0.1.0/verify.ts):
the schema's constraints applied by hand, RFC 8785 canonicalization from
`@cedulon/core`, Ed25519 from `node:crypto`.

```bash
git clone https://github.com/aeoess/aps-conformance-suite && git -C aps-conformance-suite checkout v0.1.0
node --experimental-strip-types interop/aps-accountability-record-v0.1.0/verify.ts aps-conformance-suite
```

Every stage runs on every vector. CANONICAL compares the signing input this
verifier builds with `signing_input_bytes_hex`, byte for byte, and the
SHA-256 of the full record's canonical form with `canonical_sha256`.

| vector | expected | result | stages |
|---|---|---|---|
| `allow-executed-settled` | verifies | verifies | all pass |
| `deny-no-settlement` | verifies | verifies | all pass |
| `halt` | verifies | verifies | all pass |
| `detached-payload` | verifies | verifies, payload-unverified | DIGEST skipped (no inline action) |
| `negative-tampered-payload` | fails (digest) | fails | DIGEST fails; signature passes |
| `negative-wrong-key` | fails (signature) | fails | SIGNATURE fails |
| `negative-schema-decision` | fails (schema) | fails | SCHEMA fails (`permit` is not in the enum); signature passes |
| `negative-type-relabel` | fails (signature) | fails | SIGNATURE fails; SCHEMA fails first, as the vector's description says it also breaks the `record_type` const |
| `positive-deny-executed` | verifies | verifies | all pass |
| `positive-collision-same-second-a` | verifies | verifies | all pass |
| `positive-collision-same-second-b` | verifies | verifies | all pass |
| `negative-sig-alg-lowercase` | fails (schema) | fails | SCHEMA fails (`ed25519` is not the const); signature passes |

12 of 12 as expected. CANONICAL passed on all 12: Cedulon's RFC 8785
implementation reproduces the fixture's signing bytes. `action_ref` is not
recomputed here; that belongs to the suite's `actionref-canonical` set.

## What these runs show

That checks written in this repository read these encodings and reach the
same verdicts, at the stages named, over bytes they did not produce. They do
not show that the record models mean the same thing, that any draft is
aligned with another, endorsement, or adoption.
