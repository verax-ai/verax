/**
 * Enough definite-length CBOR to encode a COSE receipt: uint, nint, bstr,
 * tstr, array, map, null, and tag 18. Floats and indefinite lengths are not
 * written.
 */

export class CborTag {
  readonly tag: number;
  readonly value: unknown;
  constructor(tag: number, value: unknown) {
    this.tag = tag;
    this.value = value;
  }
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

export function encodeCbor(value: unknown): Buffer {
  if (value === null) return Buffer.of(0xf6);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("cbor-int");
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.length), value]);
  }
  if (value instanceof CborTag) {
    return Buffer.concat([head(6, value.tag), encodeCbor(value.value)]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
  }
  if (value instanceof Map) {
    const parts: Buffer[] = [head(5, value.size)];
    for (const [k, v] of value) {
      parts.push(encodeCbor(k), encodeCbor(v));
    }
    return Buffer.concat(parts);
  }
  throw new Error("cbor-type");
}

/** RFC 9052 4.4: ["Signature1", body_protected, external_aad = h'', payload]. */
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
