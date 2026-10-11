# Erasure by key destruction — design, not built

Status: design only. Nothing here is in the tree.

## The conflict

The ledger is append-only: each decision record names the hash of the one
before it, and `verax verify` fails on a missing or changed row. A data
protection law (GDPR Art. 17, KVKK Art. 7) can require that personal data
about a person be erased on request. Deleting a row breaks the chain and
reads as tampering; keeping it keeps the data. THREAT_MODEL ("retention and
erasure") and `ledger-rotation.md` ("Still not designed") both leave this
open.

## Where personal data sits today (main 7d7ca51)

- **Decision records** (`decisions.jsonl`, signed, chained) carry hashes for
  the payload: `inputsHash`, `requestHash`, `effectHash`. They also carry
  `ref`, `nonce` and `subject` (the tool name) in clear. Verax generates
  refs at random; a caller-supplied `_ref` is the caller's text.
- **Inputs rows** (`inputs.jsonl`) carry the principal and the approval
  inputs in clear. `verify` holds each record that has an `inputsHash` to an
  inputs row whose canonical SHA-256 is that hash (0.4.3).
- **Approvals** (`approvals.jsonl`) carry the rule sentence, an inputs
  summary, amount and payee in clear.
- **Effect rows** carry hashes (`effectHash`, `resultHash`) and the signed
  extract; the tool's result is not kept in the ledger.
- **Memory** (`tenants/<key>/memory/`) is the agent's stored notes. It is
  not chained and can be deleted today; that is not this design.
- **Evidence copy** (`evidence-copy/`) mirrors decisions and effects.

So the chain already commits to hashes, not to payloads. What needs a
design is the clear text beside it (inputs rows and approvals), and the
fact that a hash of a short, guessable value (an email address, an
amount) lets anyone holding the ledger test a guess.

## Proposal

1. **Seal the payload, chain the seal.** An inputs row's `inputs` becomes
   an envelope: `{ "sealed": 1, "kid": "<subject key id>", "alg":
   "A256GCM", "iv": "<b64>", "ct": "<b64>" }`, with the canonical
   plaintext encrypted under that subject's data key and the ref as AAD.
   The record's `inputsHash` is the canonical SHA-256 of the envelope, as
   it is of the clear `inputs` today. `verify` needs no change to hold the
   record to the row: it hashes what is there. Approvals rows get the same
   envelope for the summary, amount and payee.
2. **One data key per subject.** A subject is whatever the operator names
   as the person the data is about, taken from the call by a policy field
   (for example `subjectFrom: "arguments.customerId"`); calls with no
   subject use the tenant's key. Data keys live in
   `<stateDir>/keys/subjects/<kid>.key`, wrapped by a key-encryption key
   that follows `key-custody.md` (a file first, KMS later). The key id is
   random, not derived from the subject, so the id says nothing about the
   person; the map from subject to key id is itself sealed under the tenant
   key.
3. **Erase = destroy the key.** `verax erase --subject <id>` (operator only)
   deletes that subject's data key and writes a signed control record
   `verax.erase` naming the key id and the time, so the erasure is part of
   the chain rather than a gap in it. The sealed rows stay byte for byte:
   the chain verifies, and nobody can read them again.
4. **verify after erasure.** Every row still hashes to its record. `verify`
   additionally names how many rows are sealed under an erased key id
   (`sealed-erased N`), and an `explain` of such a record says its inputs
   were erased by the control record at time T, not that they are missing.

## Fit with ledger rotation

- A closed piece is never rewritten. Erasure does not touch pieces; it
  touches keys. That is why it works with keep/move/drop
  (`ledger-rotation.md` F4): a piece moved to cold storage is erased by the
  same key deletion, without being fetched back.
- The evidence copy mirrors decisions and effects only. It must never hold
  a data key. Neither must the witness's directory or an anchor service:
  they hold hashes.
- A drop of a piece remains an operator command with its own record; it is
  not how erasure is done, because a drop removes everyone's rows.

## What it does not do

- A backup of `keys/subjects/` taken before the erasure can read the rows
  again. Erasure is only as good as the key's last copy; the key store
  therefore must not be in the same backup as the ledger, and with a KMS
  key-encryption key the backup is useless without that key.
- Hashes in decision records (`requestHash`, `effectHash`) are of
  canonical JSON that includes the arguments. A short argument can be
  guessed by hashing candidates. Closing that needs those hashes keyed
  (an HMAC under the subject key, destroyed with it) — a change to the
  decision profile and to Cedulon, which this document does not make.
- A caller-supplied `_ref` or a tool name that itself contains personal
  data stays in clear. The rule is that refs carry no personal data;
  `verify` cannot check that.
- Data that left through the tool call (the downstream system, the model
  provider) is not reached. This erases what Verax kept.

## Order of work, when built

1. Envelope for inputs rows behind a flag, tenant key only; existing
   ledgers keep clear rows and verify as before.
2. Subject keys and `subjectFrom` in policy.
3. `verax erase` and the `verax.erase` control record; `verify` and
   `explain` read it.
4. Keyed request/effect hashes, with Cedulon.

Each step ships with a guard seen red first: a sealed row whose key is
destroyed still verifies; a sealed row changed by one byte does not; an
erase without an operator is refused; the evidence copy holds no key.
