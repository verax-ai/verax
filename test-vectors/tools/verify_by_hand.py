#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the Decision Records of a vector from the draft text alone.

No Verax code is used. The checks follow draft-dogru-cedulon-core-03
Section 7.2 (COSE_Sign1 headers, kid, Sig_structure) and
draft-dogru-cedulon-decision-profile-03 Sections 4.1-4.4 (claim labels
-70501..-70513, claim rules, the content type, the prevRecordHash chain).

It covers the first four stages only: record-header, record-signature,
record-claims and chain. Effects, inputs, approvals, checkpoints and halt
windows are left to a full verifier; for a vector whose failure lies there,
this script is expected to pass every record.

    pip install cbor2 cryptography
    python verify_by_hand.py test-vectors/v1/<vector-id>
    python verify_by_hand.py --all test-vectors
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CTY_RECORD = "application/cedulon-decision-record+cbor"
LABELS = {
    -70501: "decider",
    -70502: "subject",
    -70503: "requestHash",
    -70504: "policyHash",
    -70505: "inputsHash",
    -70506: "decision",
    -70507: "reasonCode",
    -70508: "ref",
    -70509: "effectHash",
    -70510: "timestampMs",
    -70511: "nonce",
    -70512: "prevRecordHash",
    -70513: "effectClass",
}
HASHED = ("requestHash", "policyHash", "inputsHash", "effectHash", "prevRecordHash")
HASH = re.compile(r"^[0-9a-f]{64}$")
STAGES_HERE = ("record-header", "record-signature", "record-claims", "chain")


class Refused(Exception):
    def __init__(self, stage, reason):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage


def pinned_key(path):
    der_or_pem = Path(path).read_bytes()
    key = serialization.load_pem_public_key(der_or_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise Refused("record-header", "pinned key is not Ed25519")
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, hashlib.sha256(spki).digest()[:8]


def check_record(row, key, kid):
    """Returns the decoded claim map, or raises Refused naming the stage."""
    raw = bytes.fromhex(row["coseHex"])
    # core-03 7.2: an untagged COSE_Sign1, protected header {1: -19, 3: cty, 4: kid}, empty unprotected.
    msg = cbor2.loads(raw)
    if isinstance(msg, cbor2.CBORTag) or not isinstance(msg, list) or len(msg) != 4:
        raise Refused("record-header", "not an untagged COSE_Sign1 array of four")
    protected, unprotected, payload, signature = msg
    if not isinstance(protected, bytes) or not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise Refused("record-header", "protected, payload and signature must be byte strings")
    header = cbor2.loads(protected)
    if unprotected != {}:
        raise Refused("record-header", "unprotected header is not empty")
    if header.get(1) != -19:
        raise Refused("record-header", f"alg is {header.get(1)}, not -19 (RFC 9864 Ed25519)")
    # decision-profile-03 4.3: the content type is checked before the signature and before any claim.
    if header.get(3) != CTY_RECORD:
        raise Refused("record-header", f"content type is {header.get(3)!r}")
    if header.get(4) != kid:
        raise Refused("record-header", "kid is not the first eight bytes of SHA-256 over the pinned key's SPKI")
    # RFC 9052 4.4: Sig_structure = ["Signature1", protected, external_aad = h'', payload].
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload])
    try:
        key.verify(signature, to_be_signed)
    except InvalidSignature:
        raise Refused("record-signature", "Ed25519 signature does not verify")
    decoded = cbor2.loads(payload)
    if not isinstance(decoded, dict) or set(decoded) != set(LABELS):
        raise Refused("record-claims", "payload is not the thirteen-label claim map")
    claims = {LABELS[label]: value for label, value in decoded.items()}
    # decision-profile-03 4.2, applied here on the decoded map (MUST-DP-3).
    if claims["decision"] not in ("allow", "deny", "defer"):
        raise Refused("record-claims", "decision is not allow, deny or defer")
    for name in HASHED:
        value = claims[name]
        if value is not None and (not isinstance(value, str) or not HASH.match(value)):
            raise Refused("record-claims", f"{name} does not match the hash grammar")
    ts = claims["timestampMs"]
    if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0 or ts > 2**53 - 1:
        raise Refused("record-claims", "timestampMs is not a uint at most 2^53 - 1")
    if claims["decision"] == "allow":
        if not claims["ref"] or claims["effectHash"] is None or not claims["effectClass"]:
            raise Refused("record-claims", "an allow needs a ref, an effectHash and an effectClass")
    elif claims["effectHash"] is not None:
        raise Refused("record-claims", "a refusal carries effectHash null")
    # core-03 7.3: the presented claims are outside the signature and must equal the decoded ones.
    if row.get("claims") != claims:
        raise Refused("record-claims", "presented claims differ from the signed payload")
    return claims


def check_vector(vector_dir):
    vector_dir = Path(vector_dir)
    key, kid = pinned_key(vector_dir / "pins" / "record-key.pem")
    rows = [json.loads(line) for line in (vector_dir / "ledger" / "decisions.jsonl").read_text("utf8").splitlines() if line]
    previous = None
    for i, row in enumerate(rows):
        try:
            claims = check_record(row, key, kid)
        except Refused as refused:
            return refused.stage, f"record {i}: {refused}"
        # decision-profile-03 4.1: prevRecordHash is SHA-256 of the previous record's COSE_Sign1 octets.
        expected = None if previous is None else hashlib.sha256(previous).hexdigest()
        if claims["prevRecordHash"] != expected:
            return "chain", f"record {i}: prevRecordHash does not name the previous record"
        previous = bytes.fromhex(row["coseHex"])
    return None, f"{len(rows)} record(s): header, signature, claims and chain pass"


def main(argv):
    if len(argv) == 3 and argv[1] == "--all":
        root = Path(argv[2])
        manifest = json.loads((root / "manifest.json").read_text("utf8"))
        mismatches = 0
        for v in manifest["vectors"]:
            stage, detail = check_vector(root / v["dir"])
            wanted = v["first_failing_stage"] if v["first_failing_stage"] in STAGES_HERE else None
            ok = stage == wanted
            mismatches += 0 if ok else 1
            print(f"{'ok  ' if ok else 'FAIL'} {v['id']:<34} {stage or 'pass':<17} {detail}")
        print(f"{len(manifest['vectors']) - mismatches}/{len(manifest['vectors'])} as expected for stages {', '.join(STAGES_HERE)}")
        return 0 if mismatches == 0 else 1
    if len(argv) == 2:
        stage, detail = check_vector(argv[1])
        print(f"{stage or 'pass'}: {detail}")
        return 0 if stage is None else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
