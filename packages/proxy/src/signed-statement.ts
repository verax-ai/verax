/**
 * A Signed Statement (RFC 9943) about one checkpoint, for a SCITT
 * Transparency Service that registers statements over SCRAPI.
 *
 * The statement is a COSE Hash Envelope (draft-ietf-cose-hash-envelope): the
 * payload is the 32-octet checkpoint hash, 258 names SHA-256 and 259 the
 * preimage's type, a COSE_Sign1. Only the hash leaves the machine, as with the
 * digest route; what changes is that the witness signs it as an Issuer.
 *
 * The Issuer is named in the CWT claims (15) as a did:x509 over the X.509
 * chain the statement carries in x5chain (33), leaf first. The leaf must hold
 * the witness key. Verax does not mint certificates; the operator issues the
 * leaf for the witness public key and hands Verax the chain as PEM. The
 * subject (CWT sub) is the ledger, named by the SHA-256 of the witness key.
 */
import { createHash, createPublicKey, sign, verify, X509Certificate } from "node:crypto";

import { cborMap, encodeCbor } from "@cedulon/cose";

import { decodeSign1, sign1Structure, type Sign1 } from "./transparency-receipt.ts";

const HDR_ALG = 1;
const HDR_CWT_CLAIMS = 15;
const HDR_X5CHAIN = 33;
const HDR_PAYLOAD_HASH_ALG = 258;
const HDR_PREIMAGE_CONTENT_TYPE = 259;
const CWT_ISS = 1;
const CWT_SUB = 2;
const ALG_EDDSA = -8;
const HASH_SHA256 = -16;
const PREIMAGE_TYPE = "application/cose";
const HASH = /^[0-9a-f]{64}$/;

/** The DER certificates of a PEM chain, leaf first. A chain is a leaf and at least one CA. */
export function readIssuerChain(pem: string): Uint8Array[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length < 2) throw new Error("issuer-chain-too-short");
  return blocks.map((block) => {
    try {
      return new Uint8Array(new X509Certificate(block).raw);
    } catch {
      throw new Error("issuer-chain-certificate");
    }
  });
}

// did:x509 keeps ALPHA / DIGIT / "-" / "." / "_" and percent-encodes the rest.
export function didX509Value(value: string): string {
  return Array.from(Buffer.from(value, "utf8"))
    .map((b) => {
      const c = String.fromCharCode(b);
      return /[A-Za-z0-9._-]/.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
    })
    .join("");
}

/** did:x509:0:sha256:<root fingerprint>::subject:CN:<leaf CN>. */
export function didX509Issuer(chain: readonly Uint8Array[]): string {
  if (chain.length < 2) throw new Error("issuer-chain-too-short");
  const leaf = new X509Certificate(chain[0]!);
  const cn = leaf.subject
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith("CN="));
  if (!cn || cn.length === 3) throw new Error("issuer-chain-leaf-cn");
  const fingerprint = createHash("sha256").update(chain[chain.length - 1]!).digest("base64url");
  return `did:x509:0:sha256:${fingerprint}::subject:CN:${didX509Value(cn.slice(3))}`;
}

function spki(publicKeyPem: string): Buffer {
  return createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
}

/** The ledger a witness key signs for, as the statement's subject. */
export function ledgerSubject(publicKeyPem: string): string {
  return `verax-ledger:${createHash("sha256").update(spki(publicKeyPem)).digest("hex")}`;
}

/** The Signed Statement for one checkpoint hash, signed by the witness key the chain's leaf holds. */
export function checkpointStatement(
  checkpointHash: string,
  chain: readonly Uint8Array[],
  keys: { privateKeyPem: string; publicKeyPem: string },
): Uint8Array {
  if (!HASH.test(checkpointHash)) throw new Error("statement-checkpoint-hash");
  const leafKey = new X509Certificate(chain[0]!).publicKey.export({ type: "spki", format: "der" });
  if (!leafKey.equals(spki(keys.publicKeyPem))) throw new Error("issuer-chain-leaf-key");
  const protectedBytes = encodeCbor(
    cborMap([
      [HDR_ALG, ALG_EDDSA],
      [
        HDR_CWT_CLAIMS,
        cborMap([
          [CWT_ISS, didX509Issuer(chain)],
          [CWT_SUB, ledgerSubject(keys.publicKeyPem)],
        ]),
      ],
      [HDR_X5CHAIN, chain.map((der) => new Uint8Array(der))],
      [HDR_PAYLOAD_HASH_ALG, HASH_SHA256],
      [HDR_PREIMAGE_CONTENT_TYPE, PREIMAGE_TYPE],
    ]),
  );
  const payload = new Uint8Array(Buffer.from(checkpointHash, "hex"));
  const signature = new Uint8Array(sign(null, sign1Structure(protectedBytes, payload), keys.privateKeyPem));
  // Tagged COSE_Sign1 (tag 18, one octet 0xd2): scitt-ccf-ledger refuses an untagged one.
  return new Uint8Array(Buffer.concat([Buffer.of(0xd2), encodeCbor([protectedBytes, cborMap([]), payload, signature])]));
}

export type StatementRead = { ok: true; issuer: string; subject: string } | { ok: false; reason: string };

/**
 * Whether `bytes` is this ledger's Signed Statement for `checkpointHash`,
 * signed by `publicKeyPem` with a chain whose leaf holds that key. The
 * did:x509 itself is the service's to resolve when it registers the statement.
 */
export function readCheckpointStatement(bytes: Uint8Array, checkpointHash: string, publicKeyPem: string): StatementRead {
  let sign1: Sign1;
  try {
    sign1 = decodeSign1(bytes);
  } catch {
    return { ok: false, reason: "the statement is not a COSE_Sign1" };
  }
  const h = sign1.protectedHeader;
  if (h.get(HDR_ALG) !== ALG_EDDSA) return { ok: false, reason: "the statement is not EdDSA" };
  if (h.get(HDR_PAYLOAD_HASH_ALG) !== HASH_SHA256) return { ok: false, reason: "the statement is not a SHA-256 hash envelope" };
  const cwt = h.get(HDR_CWT_CLAIMS);
  const issuer = cwt instanceof Map ? cwt.get(CWT_ISS) : undefined;
  const subject = cwt instanceof Map ? cwt.get(CWT_SUB) : undefined;
  if (typeof issuer !== "string" || !issuer.startsWith("did:x509:") || typeof subject !== "string") {
    return { ok: false, reason: "the statement names no did:x509 issuer and subject" };
  }
  if (!HASH.test(checkpointHash) || !(sign1.payload instanceof Uint8Array) || !Buffer.from(sign1.payload).equals(Buffer.from(checkpointHash, "hex"))) {
    return { ok: false, reason: "the statement names another checkpoint" };
  }
  let signed = false;
  try {
    signed = verify(null, sign1Structure(sign1.protectedBytes, sign1.payload), publicKeyPem, sign1.signature);
  } catch {
    signed = false;
  }
  if (!signed) return { ok: false, reason: "the statement does not verify under the checkpoint key" };
  const x5chain = h.get(HDR_X5CHAIN);
  const leaf = Array.isArray(x5chain) ? x5chain[0] : x5chain;
  try {
    if (!(leaf instanceof Uint8Array) || !new X509Certificate(leaf).publicKey.export({ type: "spki", format: "der" }).equals(spki(publicKeyPem))) {
      return { ok: false, reason: "the statement's x5chain leaf holds another key" };
    }
  } catch {
    return { ok: false, reason: "the statement's x5chain leaf is not a certificate" };
  }
  return { ok: true, issuer, subject };
}
