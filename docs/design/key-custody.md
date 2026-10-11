# Key custody — design, not built

Status: design only, except the `doctor` check named below.

## The gap

The body signs with keys it reads from PEM files under `<stateDir>/keys/`:
`record.private.pem` (decision and control records) and
`effect.private.pem` (effect rows); `verax witness` holds
`witness.private.pem`. Whoever can open a file can copy the key and sign
elsewhere, at any time, as the body.

- `verax install` puts the state directory under a separate account
  (`verax-svc`, `verax`, `_verax`), so the agent's user cannot open the
  files. That boundary holds against the agent; it does not hold against an
  administrator or root, which THREAT_MODEL already states.
- `verax init --local` writes the state directory as the user who runs the
  agent. That user can read every key. From this branch on, `verax doctor`
  reports it as a failure (`key-custody`): an unelevated user who can open
  `keys/record.private.pem` can sign records as the body, and an elevated
  session that can is a warning.

Moving the key out of a file changes what a thief gets: from a key they can
use anywhere, forever, to a signing service they can call only while they
hold the machine. It does not stop a compromised body process from signing;
nothing local does.

## What the code allows today (measured on main 7d7ca51)

- `RecordSigner` and `EffectSigner` (`packages/proxy/src/types.ts`) are
  `{ privateKeyPem, publicKeyPem }`: data, not an operation. The private PEM
  is passed on at eight call sites (`ledger.ts` 3, `approvals.ts` 2,
  `proxy.ts`, `control-sync.ts`, `revoke-sync.ts`), plus the witness.
- `@cedulon/cose` 0.13.1 already defines the seam:
  `Signer = { publicKeyPem; sign(payload: Uint8Array): Uint8Array }`, and
  `signDecisionRecord`, `signCheckpoint` and `signCoseSign1` accept it. Its
  comment names a KMS adapter as the intended second implementation.
- That `sign` is synchronous. A KMS call is a network round trip and cannot
  satisfy it. Either Cedulon gains an asynchronous signer
  (`signAsync(payload): Promise<Uint8Array>`) and the signing paths in the
  proxy await it, or a key store that can sign synchronously in-process is
  used. Most proxy signing paths already run inside async functions
  (`proxy.call`, the control and revoke syncs); the ledger append itself is
  where ordering must be kept, because the chain hash of record N+1 needs
  record N.

## Which stores can hold an Ed25519 key (Verax signs only Ed25519)

| Store | Ed25519 | Source |
|---|---|---|
| Windows CNG, software KSP and TPM (Platform Crypto Provider) | **No.** `BCryptOpenAlgorithmProvider("ED25519")` returns `STATUS_NOT_FOUND`; `NCryptIsAlgSupported("ED25519")` returns `NTE_NOT_SUPPORTED` on both providers. ECDSA P-256/384/521, RSA and ML-DSA are present. | Measured 11 Oct 2026 on Windows 11 26H2 (10.0.26300). |
| AWS KMS | **Yes.** Key spec `ECC_NIST_EDWARDS25519`, signing algorithm `ED25519_SHA_512` with `MessageType: RAW` (pure Ed25519, the signature Verax already verifies); `ED25519_PH_SHA_512` is the pre-hashed variant and does not verify as pure Ed25519. | AWS KMS developer guide, key spec reference, read 11 Oct 2026. Not exercised against a live key. |
| macOS Keychain / Secure Enclave | Not measured on this host. The Secure Enclave is documented for P-256 keys only; a software Keychain item can store any bytes but hands them to the process that signs, which is a file with a password, not custody. | To measure on a Mac. |
| Linux kernel keyring / TPM 2.0 | Not measured on this host. | To measure. |

So on a desktop operating system the store that can hold a key the process
never sees is, today, a P-256 key, and Verax records are Ed25519. A
desktop store therefore means one of: a second signature algorithm in
Verax and Cedulon (ES256 next to EdDSA, which `verify` would have to accept
and name), or Ed25519 in a store that does not exist on Windows.

## Proposal, in order

1. **doctor** (this branch): `key-custody` fails when the user running
   doctor can open the record key, and is a warning when that session is
   elevated. Local mode is named in the line.
2. **Asynchronous signer seam.** Cedulon: `AsyncSigner = { publicKeyPem;
   signAsync(payload): Promise<Uint8Array> }`, accepted by the sign
   functions next to `Signer`. Verax: `RecordSigner` and `EffectSigner`
   become `Signer | AsyncSigner`; the eight call sites call the seam
   instead of passing PEM. A PEM signer stays the default and the ledger
   format does not change, so every existing ledger and test vector still
   verifies.
3. **AWS KMS adapter** (`VERAX_RECORD_KEY=kms:<key-arn>`): `Sign` with
   `ED25519_SHA_512`, `MessageType: RAW`. The public key comes from
   `GetPublicKey` once at start and is pinned in `keys/record.public.pem`
   so `verify` reads it the same way. Every append waits for one KMS call;
   the latency and the 4,096-byte `RAW` message limit have to be measured
   against the largest COSE `Sig_structure` the body signs before this is
   the default anywhere. The KMS key's policy, not the body's account,
   decides who can sign; CloudTrail records each `Sign`, which is a second,
   independent log of every signature.
4. **Desktop stores** only after a decision on a second algorithm. If ES256
   is added, the Windows TPM and the Secure Enclave become usable; the
   record says which algorithm signed it, and `verify` names it.

## What none of this does

- A process that can call the signer can still sign while it runs. Custody
  takes away the copy, not the use.
- It does not protect against an administrator who can change the KMS
  policy or the service's credentials. That stays outside the model; the
  anchored checkpoints and CloudTrail are what detect it.
- The witness key and the effect key need the same treatment; this
  document uses the record key as the first case.

## AWS resources

Creating a KMS key costs money and is a resource in the operator's
account. Nothing here creates one; the adapter is tested against a fake
`Sign` endpoint until an operator approves a key.
