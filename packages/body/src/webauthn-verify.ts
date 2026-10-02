/**
 * WebAuthn assertion checks for an HTTP approval, using only node:crypto
 * and the CBOR decoder already in @cedulon/cose. The body does not take a
 * certificate stack to verify one signature.
 */
import { constants, createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

import { decodeCbor, isCborMap, mapGet, type CborMap } from "@cedulon/cose";

export type AssertionVerdict = { ok: true; counter: number; flags: number } | { ok: false; reason: string };

type PostedAssertion = {
  response?: {
    clientDataJSON?: unknown;
    authenticatorData?: unknown;
    signature?: unknown;
  };
};

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromBase64Url(value: string): Buffer | null {
  if (value === "") return null;
  const trimmed = value.replace(/=+$/u, "");
  if (trimmed === "" || !/^[A-Za-z0-9_-]+$/u.test(trimmed)) return null;
  const buf = Buffer.from(trimmed, "base64url");
  return buf.length === 0 ? null : buf;
}

function mapNum(map: CborMap, key: number): number | null {
  const value = mapGet(map, key);
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function mapBytes(map: CborMap, key: number, length?: number): Uint8Array | null {
  const value = mapGet(map, key);
  if (!(value instanceof Uint8Array)) return null;
  if (value.length === 0) return null;
  if (length !== undefined && value.length !== length) return null;
  return value;
}

/**
 * COSE public key, base64url, to a node key. EC2 is P-256 / ES256, OKP is
 * Ed25519 / EdDSA, RSA is RS256. Any other kty, alg, or curve is refused.
 * A refusal returns null; this does not throw.
 */
export function coseKeyToPublicKey(base64urlCose: string): KeyObject | null {
  try {
    const bytes = fromBase64Url(base64urlCose);
    if (!bytes) return null;
    const decoded = decodeCbor(new Uint8Array(bytes));
    if (!isCborMap(decoded)) return null;
    const kty = mapNum(decoded, 1);
    const alg = mapNum(decoded, 3);
    if (kty === 2 && alg === -7) {
      const x = mapBytes(decoded, -2, 32);
      const y = mapBytes(decoded, -3, 32);
      if (mapNum(decoded, -1) !== 1 || !x || !y) return null;
      return createPublicKey({
        format: "jwk",
        key: { kty: "EC", crv: "P-256", alg: "ES256", x: b64url(x), y: b64url(y) },
      });
    }
    if (kty === 1 && alg === -8) {
      const x = mapBytes(decoded, -2, 32);
      if (mapNum(decoded, -1) !== 6 || !x) return null;
      return createPublicKey({
        format: "jwk",
        key: { kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: b64url(x) },
      });
    }
    if (kty === 3 && alg === -257) {
      const n = mapBytes(decoded, -1);
      const e = mapBytes(decoded, -2);
      if (!n || !e) return null;
      return createPublicKey({
        format: "jwk",
        key: { kty: "RSA", alg: "RS256", n: b64url(n), e: b64url(e) },
      });
    }
    return null;
  } catch {
    return null;
  }
}

function signatureHolds(key: KeyObject, data: Buffer, signature: Buffer): boolean {
  try {
    const kind = key.asymmetricKeyType;
    if (kind === "ec") return cryptoVerify("sha256", data, { key, dsaEncoding: "der" }, signature);
    if (kind === "ed25519") return cryptoVerify(null, data, key, signature);
    if (kind === "rsa") {
      return cryptoVerify("sha256", data, { key, padding: constants.RSA_PKCS1_PADDING }, signature);
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Check one authentication assertion. `expectedOrigins` is the caller's
 * allow-list; a caller that does not have one passes the origin it read
 * back, and says so at the call site. `crossOrigin: true` is refused.
 */
export function verifyAssertion(opts: {
  response: PostedAssertion;
  expectedChallenge: string;
  expectedOrigins: readonly string[];
  rpId: string;
  publicKeyCose: string;
}): AssertionVerdict {
  try {
    const clientB64 = opts.response.response?.clientDataJSON;
    const authB64 = opts.response.response?.authenticatorData;
    const sigB64 = opts.response.response?.signature;
    if (typeof clientB64 !== "string" || typeof authB64 !== "string" || typeof sigB64 !== "string") {
      return { ok: false, reason: "bad-assertion" };
    }
    const clientBytes = fromBase64Url(clientB64);
    const authenticatorData = fromBase64Url(authB64);
    const signature = fromBase64Url(sigB64);
    if (!clientBytes || !authenticatorData || !signature) return { ok: false, reason: "bad-assertion" };
    let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
    try {
      const parsed: unknown = JSON.parse(clientBytes.toString("utf8"));
      if (!parsed || typeof parsed !== "object") return { ok: false, reason: "bad-client-data" };
      client = parsed as { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
    } catch {
      return { ok: false, reason: "bad-client-data" };
    }
    if (client.type !== "webauthn.get") return { ok: false, reason: "type" };
    if (client.challenge !== opts.expectedChallenge) return { ok: false, reason: "challenge" };
    if (typeof client.origin !== "string" || !opts.expectedOrigins.includes(client.origin)) {
      return { ok: false, reason: "origin" };
    }
    if (client.crossOrigin === true) return { ok: false, reason: "cross-origin" };
    if (authenticatorData.length < 37) return { ok: false, reason: "authenticator-data" };
    const rpIdHash = createHash("sha256").update(opts.rpId).digest();
    if (Buffer.compare(authenticatorData.subarray(0, 32), rpIdHash) !== 0) return { ok: false, reason: "rp-id" };
    const flags = authenticatorData[32];
    if (flags === undefined || (flags & 0x05) !== 0x05) return { ok: false, reason: "user-verification" };
    const counter = authenticatorData.readUInt32BE(33);
    const key = coseKeyToPublicKey(opts.publicKeyCose);
    if (!key) return { ok: false, reason: "public-key" };
    const clientHash = createHash("sha256").update(clientBytes).digest();
    const data = Buffer.concat([authenticatorData, clientHash]);
    if (!signatureHolds(key, data, signature)) return { ok: false, reason: "signature" };
    return { ok: true, counter, flags };
  } catch {
    return { ok: false, reason: "signature" };
  }
}
