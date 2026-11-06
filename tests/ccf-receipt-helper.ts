import { createHash, sign, type KeyObject } from "node:crypto";

import { CborTag, sign1Structure } from "../packages/proxy/src/transparency-receipt.ts";

/** Enough CBOR to build a receipt: uint, nint, bstr, tstr, bool, array, map, null, tag. */
export function cbor(value: unknown): Buffer {
  const head = (major: number, n: number): Buffer => {
    if (n < 24) return Buffer.of((major << 5) | n);
    if (n < 0x100) return Buffer.of((major << 5) | 24, n);
    if (n < 0x10000) return Buffer.of((major << 5) | 25, n >> 8, n & 0xff);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (value === null) return Buffer.of(0xf6);
  if (value === true) return Buffer.of(0xf5);
  if (value === false) return Buffer.of(0xf4);
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof CborTag) return Buffer.concat([head(6, value.tag), cbor(value.value)]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error("cbor-test-encoder");
}

export const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();

/** A CCF receipt (ES256, vds 2) committing to `claimsDigest`, signed by a P-256 `privateKey`. */
export function ccfReceiptFor(claimsDigest: Uint8Array, privateKey: KeyObject): Buffer {
  const internalHash = sha256(Buffer.from("internal"));
  const evidence = "ce:3.7:0f3c9e";
  const sibling = sha256(Buffer.from("sibling"));
  const root = sha256(sha256(internalHash, sha256(Buffer.from(evidence)), claimsDigest), sibling);
  const protectedBytes = cbor(new Map<unknown, unknown>([[1, -7], [395, 2]]));
  const proof = cbor(new Map<unknown, unknown>([[1, [internalHash, evidence, claimsDigest]], [2, [[false, sibling]]]]));
  const unprotected = new Map<unknown, unknown>([[396, new Map<unknown, unknown>([[-1, [proof]]])]]);
  const signature = sign("sha256", sign1Structure(protectedBytes, root), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return cbor(new CborTag(18, [protectedBytes, unprotected, null, new Uint8Array(signature)]));
}
