/**
 * WebAuthn assertion checks for an HTTP approval, and the reading of a new
 * credential at enrolment, using only node:crypto and the CBOR decoder
 * already in @cedulon/cose. The body does not take a certificate stack to
 * verify one signature.
 */
import { constants, createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

import { decodeCbor, isCborMap, mapGet, type CborMap, type CborVal } from "@cedulon/cose";

export type AssertionVerdict = { ok: true; counter: number; flags: number } | { ok: false; reason: string };

export type RegistrationVerdict =
  | { ok: true; credentialId: string; publicKeyCose: string; counter: number; flags: number }
  | { ok: false; reason: string };

/** The COSE algorithms `coseKeyToPublicKey` takes. An enrolment offers these and no others. */
export const COSE_ALGORITHMS: readonly number[] = [-7, -8, -257];

type PostedAssertion = {
  response?: {
    clientDataJSON?: unknown;
    authenticatorData?: unknown;
    signature?: unknown;
  };
};

export type PostedRegistration = {
  id?: unknown;
  rawId?: unknown;
  response?: {
    clientDataJSON?: unknown;
    attestationObject?: unknown;
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

/** Why the client data is not what was asked for, or null when it is. */
function clientDataRefusal(
  clientBytes: Buffer,
  type: "webauthn.get" | "webauthn.create",
  expectedChallenge: string,
  expectedOrigins: readonly string[],
): string | null {
  let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    const parsed: unknown = JSON.parse(clientBytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object") return "bad-client-data";
    client = parsed as { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  } catch {
    return "bad-client-data";
  }
  if (client.type !== type) return "type";
  if (client.challenge !== expectedChallenge) return "challenge";
  if (typeof client.origin !== "string" || !expectedOrigins.includes(client.origin)) return "origin";
  // Absent or false only: a string such as "true" is not a same-origin answer either.
  if (client.crossOrigin !== undefined && client.crossOrigin !== false) return "cross-origin";
  return null;
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
    const refused = clientDataRefusal(clientBytes, "webauthn.get", opts.expectedChallenge, opts.expectedOrigins);
    if (refused) return { ok: false, reason: refused };
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

/** A credential key is a flat map; an honest one never nests this deep. */
const CBOR_SKIP_DEPTH = 4;

/**
 * Where the CBOR item that starts at `start` ends, or null when it is not one
 * this file reads. `decodeCbor` refuses bytes after an item, and in
 * authenticator data the credential key may be followed by an extensions map,
 * so the key's length has to be found before it can be decoded. Integers,
 * strings, arrays, maps and the three simple values, definite lengths under
 * 2^32 only. The slice this marks out is then decoded by `decodeCbor`, which
 * is the judge of what is in it.
 */
function cborItemEnd(bytes: Buffer, start: number, depth = 0): number | null {
  if (depth > CBOR_SKIP_DEPTH) return null;
  const ib = bytes[start];
  if (ib === undefined) return null;
  let at = start + 1;
  if (ib === 0xf4 || ib === 0xf5 || ib === 0xf6) return at;
  const major = ib >> 5;
  const ai = ib & 31;
  if (major > 5) return null;
  let n = ai;
  if (ai >= 24) {
    const width = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : 0;
    if (width === 0 || at + width > bytes.length) return null;
    n = bytes.readUIntBE(at, width);
    at += width;
  }
  if (major <= 1) return at;
  if (major === 2 || major === 3) return at + n <= bytes.length ? at + n : null;
  // Every item is at least one byte, so a count past what is left ends at the first one missing.
  const items = major === 4 ? n : n * 2;
  for (let i = 0; i < items; i += 1) {
    const next = cborItemEnd(bytes, at, depth + 1);
    if (next === null) return null;
    at = next;
  }
  return at;
}

function decoded(bytes: Uint8Array): CborVal | undefined {
  try {
    return decodeCbor(bytes);
  } catch {
    return undefined;
  }
}

/**
 * Read the credential a `navigator.credentials.create()` answer carries. This
 * proves nothing about the device: the attestation asked for is "none", any
 * other format is refused rather than believed, and what vouches for the
 * caller is whatever the caller checked before calling (at the door, a
 * pairing code from the machine). What it does establish is that the answer
 * was made for this challenge, origin and relying party with the user
 * verified, that every byte of the authenticator data is accounted for, and
 * that the key is one `verifyAssertion` can use.
 */
export function verifyRegistration(opts: {
  response: PostedRegistration;
  expectedChallenge: string;
  expectedOrigins: readonly string[];
  rpId: string;
}): RegistrationVerdict {
  try {
    const clientB64 = opts.response.response?.clientDataJSON;
    const attestationB64 = opts.response.response?.attestationObject;
    if (typeof clientB64 !== "string" || typeof attestationB64 !== "string") {
      return { ok: false, reason: "bad-registration" };
    }
    const clientBytes = fromBase64Url(clientB64);
    const attestationBytes = fromBase64Url(attestationB64);
    if (!clientBytes || !attestationBytes) return { ok: false, reason: "bad-registration" };
    const refused = clientDataRefusal(clientBytes, "webauthn.create", opts.expectedChallenge, opts.expectedOrigins);
    if (refused) return { ok: false, reason: refused };

    const attestation = decoded(new Uint8Array(attestationBytes));
    if (attestation === undefined || !isCborMap(attestation)) return { ok: false, reason: "attestation" };
    if (mapGet(attestation, "fmt") !== "none") return { ok: false, reason: "attestation-format" };
    const statement = mapGet(attestation, "attStmt");
    if (statement === undefined || !isCborMap(statement) || statement.$map.length !== 0) {
      return { ok: false, reason: "attestation-statement" };
    }
    const rawAuthData = mapGet(attestation, "authData");
    if (!(rawAuthData instanceof Uint8Array)) return { ok: false, reason: "authenticator-data" };
    const authData = Buffer.from(rawAuthData);

    // rpIdHash 32, flags 1, counter 4, then aaguid 16 and the id's length 2.
    if (authData.length < 55) return { ok: false, reason: "authenticator-data" };
    const rpIdHash = createHash("sha256").update(opts.rpId).digest();
    if (Buffer.compare(authData.subarray(0, 32), rpIdHash) !== 0) return { ok: false, reason: "rp-id" };
    const flags = authData[32];
    if (flags === undefined || (flags & 0x05) !== 0x05) return { ok: false, reason: "user-verification" };
    if ((flags & 0x40) === 0) return { ok: false, reason: "attested-credential" };
    const counter = authData.readUInt32BE(33);

    const idLength = authData.readUInt16BE(53);
    const keyStart = 55 + idLength;
    if (idLength === 0 || idLength > 1023 || keyStart >= authData.length) {
      return { ok: false, reason: "credential-id" };
    }
    const credentialId = b64url(authData.subarray(55, keyStart));
    // The id the page names is the one the authenticator made, or this is two answers glued together.
    if (opts.response.id !== credentialId) return { ok: false, reason: "credential-id" };
    if (opts.response.rawId !== undefined && opts.response.rawId !== credentialId) {
      return { ok: false, reason: "credential-id" };
    }

    const keyEnd = cborItemEnd(authData, keyStart);
    if (keyEnd === null) return { ok: false, reason: "public-key" };
    if ((flags & 0x80) !== 0) {
      const extensions = keyEnd < authData.length ? decoded(new Uint8Array(authData.subarray(keyEnd))) : undefined;
      if (extensions === undefined || !isCborMap(extensions)) return { ok: false, reason: "extensions" };
    } else if (keyEnd !== authData.length) {
      return { ok: false, reason: "authenticator-data" };
    }
    const publicKeyCose = b64url(authData.subarray(keyStart, keyEnd));
    if (!coseKeyToPublicKey(publicKeyCose)) return { ok: false, reason: "public-key" };
    return { ok: true, credentialId, publicKeyCose, counter, flags };
  } catch {
    return { ok: false, reason: "bad-registration" };
  }
}
