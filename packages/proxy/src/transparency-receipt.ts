/**
 * COSE Receipts from a SCITT Transparency Service (RFC 9943) over an RFC 9162
 * SHA-256 Merkle tree, read without the service.
 *
 * A receipt is a COSE_Sign1, normally tagged 18, whose protected header names
 * the verifiable data structure at label 395 (1 is RFC9162_SHA256) and whose
 * unprotected header carries, at label 396 key -1, one inclusion proof: the
 * CBOR array [tree_size, leaf_index, audit_path]. The payload is detached: it
 * is the tree root, which the verifier rebuilds from the leaf entry and the
 * path and then checks the signature over. A receipt carries no key id, so the
 * service key is always the reader's to supply.
 *
 * This is a second CBOR reader beside @cedulon/cose on purpose. That one reads
 * Cedulon's own objects and refuses tags, floats and non-empty unprotected
 * headers, which is right for them; a receipt written by someone else's
 * service uses all three.
 */
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

export class CborTag {
  readonly tag: number;
  readonly value: unknown;
  constructor(tag: number, value: unknown) {
    this.tag = tag;
    this.value = value;
  }
}

const MAX_BYTES = 65_536;
const MAX_DEPTH = 16;
const MAX_ITEMS = 4_096;

/** RFC 8949 definite-length items; floats and indefinite lengths are refused. */
export function decodeCborItem(bytes: Uint8Array): unknown {
  if (bytes.length > MAX_BYTES) throw new Error("cbor-too-large");
  let at = 0;
  let items = 0;
  const need = (n: number) => {
    if (at + n > bytes.length) throw new Error("cbor-eof");
  };
  const length = (ai: number): number => {
    if (ai < 24) return ai;
    const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
    if (size === 0) throw new Error("cbor-indefinite-or-reserved");
    need(size);
    let n = 0n;
    for (let i = 0; i < size; i += 1) n = (n << 8n) | BigInt(bytes[at + i]!);
    at += size;
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("cbor-int-too-large");
    return Number(n);
  };
  const item = (depth: number): unknown => {
    if (depth > MAX_DEPTH) throw new Error("cbor-too-deep");
    items += 1;
    if (items > MAX_ITEMS) throw new Error("cbor-too-many-items");
    need(1);
    const ib = bytes[at]!;
    at += 1;
    const major = ib >> 5;
    const ai = ib & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      throw new Error("cbor-simple-or-float");
    }
    const n = length(ai);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
        need(n);
        at += n;
        return bytes.slice(at - n, at);
      case 3:
        need(n);
        at += n;
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(at - n, at));
      case 4: {
        if (n > MAX_ITEMS) throw new Error("cbor-too-many-items");
        const out: unknown[] = [];
        for (let i = 0; i < n; i += 1) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        if (n > MAX_ITEMS) throw new Error("cbor-too-many-items");
        const out = new Map<unknown, unknown>();
        for (let i = 0; i < n; i += 1) {
          const key = item(depth + 1);
          if (key instanceof Uint8Array || key instanceof Map || Array.isArray(key)) throw new Error("cbor-key-type");
          if (out.has(key)) throw new Error("cbor-duplicate-key");
          out.set(key, item(depth + 1));
        }
        return out;
      }
      case 6:
        return new CborTag(n, item(depth + 1));
      default:
        throw new Error("cbor-major");
    }
  };
  const value = item(0);
  if (at !== bytes.length) throw new Error("cbor-trailing");
  return value;
}

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.of((major << 5) | n);
  if (n < 0x100) return Buffer.of((major << 5) | 24, n);
  if (n < 0x10000) return Buffer.of((major << 5) | 25, n >> 8, n & 0xff);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

/** RFC 9052 4.4: ["Signature1", body_protected, external_aad = h'', payload], CBOR-encoded. */
export function sign1Structure(protectedBytes: Uint8Array, payload: Uint8Array): Buffer {
  const text = Buffer.from("Signature1", "utf8");
  return Buffer.concat([
    head(4, 4),
    head(3, text.length),
    text,
    head(2, protectedBytes.length),
    protectedBytes,
    head(2, 0),
    head(2, payload.length),
    payload,
  ]);
}

export type Sign1 = {
  protectedBytes: Uint8Array;
  protectedHeader: Map<unknown, unknown>;
  unprotected: Map<unknown, unknown>;
  payload: Uint8Array | null;
  signature: Uint8Array;
};

/** A COSE_Sign1, tagged 18 or untagged. */
export function decodeSign1(bytes: Uint8Array): Sign1 {
  let value = decodeCborItem(bytes);
  if (value instanceof CborTag) {
    if (value.tag !== 18) throw new Error(`cose-tag-${value.tag}`);
    value = value.value;
  }
  if (!Array.isArray(value) || value.length !== 4) throw new Error("cose-sign1-shape");
  const [p, u, payload, signature] = value as [unknown, unknown, unknown, unknown];
  if (!(p instanceof Uint8Array) || !(u instanceof Map) || !(signature instanceof Uint8Array)) {
    throw new Error("cose-sign1-members");
  }
  if (payload !== null && !(payload instanceof Uint8Array)) throw new Error("cose-sign1-payload");
  const protectedHeader = p.length === 0 ? new Map() : decodeCborItem(p);
  if (!(protectedHeader instanceof Map)) throw new Error("cose-protected-header");
  return { protectedBytes: p, protectedHeader, unprotected: u, payload, signature };
}

/** COSE algorithms a receipt may use: EdDSA/Ed25519 (-8, -19), ES256 (-7), ES384 (-35). */
export function verifyCoseSignature(alg: unknown, publicKeyPem: string, data: Buffer, signature: Uint8Array): boolean {
  const key = createPublicKey(publicKeyPem);
  if (alg === -8 || alg === -19) {
    return key.asymmetricKeyType === "ed25519" && verifySignature(null, data, key, signature);
  }
  const curve = key.asymmetricKeyType === "ec" ? key.asymmetricKeyDetails?.namedCurve : undefined;
  if (alg === -7) {
    return curve === "prime256v1" && verifySignature("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  }
  if (alg === -35) {
    return curve === "secp384r1" && verifySignature("sha384", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  }
  return false;
}

const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();

/** RFC 9162 2.1.3.2: the root an inclusion proof yields for a leaf entry. */
export function rootFromInclusion(leafEntry: Uint8Array, leafIndex: number, treeSize: number, path: readonly Uint8Array[]): Buffer {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) {
    throw new Error("inclusion-index");
  }
  let fn = leafIndex;
  let sn = treeSize - 1;
  // RFC 9162 2.1.1: a leaf hashes as SHA-256(0x00 || entry), an interior node as SHA-256(0x01 || left || right).
  let r = sha256(Buffer.of(0x00), leafEntry);
  for (const p of path) {
    if (p.length !== 32) throw new Error("inclusion-node-size");
    if (sn === 0) throw new Error("inclusion-path-too-long");
    if (fn % 2 === 1 || fn === sn) {
      r = sha256(Buffer.of(0x01), p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = sha256(Buffer.of(0x01), r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("inclusion-path-too-short");
  return r;
}

export type ReceiptStage = "receipt-decode" | "vds-gate" | "inclusion" | "receipt-sig";

export type ReceiptCheck =
  | { ok: true; root: string; treeSize: number; leafIndex: number }
  | { ok: false; stage: ReceiptStage; reason: string };

/**
 * Checks one receipt for one leaf entry under the service key the reader
 * holds. vds is read from the protected header only.
 */
export function verifyReceipt(receipt: Uint8Array, leafEntry: Uint8Array, publicKeyPem: string): ReceiptCheck {
  let sign1: Sign1;
  try {
    sign1 = decodeSign1(receipt);
  } catch (err) {
    return { ok: false, stage: "receipt-decode", reason: err instanceof Error ? err.message : String(err) };
  }
  const vds = sign1.protectedHeader.get(395);
  if (vds !== 1) return { ok: false, stage: "vds-gate", reason: `vds ${String(vds)} is not RFC9162_SHA256` };
  const vdp = sign1.unprotected.get(396);
  const proofs = vdp instanceof Map ? vdp.get(-1) : undefined;
  if (!Array.isArray(proofs) || proofs.length !== 1 || !(proofs[0] instanceof Uint8Array)) {
    return { ok: false, stage: "receipt-decode", reason: "no single inclusion proof at 396/-1" };
  }
  if (sign1.payload !== null) return { ok: false, stage: "receipt-decode", reason: "receipt payload is not detached" };
  let proof: unknown;
  try {
    proof = decodeCborItem(proofs[0]);
  } catch (err) {
    return { ok: false, stage: "receipt-decode", reason: err instanceof Error ? err.message : String(err) };
  }
  if (!Array.isArray(proof) || proof.length !== 3) return { ok: false, stage: "receipt-decode", reason: "inclusion proof shape" };
  const [treeSize, leafIndex, path] = proof as [unknown, unknown, unknown];
  if (typeof treeSize !== "number" || typeof leafIndex !== "number" || !Array.isArray(path) || !path.every((p) => p instanceof Uint8Array)) {
    return { ok: false, stage: "receipt-decode", reason: "inclusion proof members" };
  }
  let root: Buffer;
  try {
    root = rootFromInclusion(leafEntry, leafIndex, treeSize, path as Uint8Array[]);
  } catch (err) {
    return { ok: false, stage: "inclusion", reason: err instanceof Error ? err.message : String(err) };
  }
  let verified = false;
  try {
    verified = verifyCoseSignature(sign1.protectedHeader.get(1), publicKeyPem, sign1Structure(sign1.protectedBytes, root), sign1.signature);
  } catch {
    verified = false;
  }
  if (!verified) return { ok: false, stage: "receipt-sig", reason: "signature does not verify over the rebuilt root" };
  return { ok: true, root: root.toString("hex"), treeSize, leafIndex };
}
