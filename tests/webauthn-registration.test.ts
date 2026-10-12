import { strict as assert } from "node:assert";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, it } from "node:test";

import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";

import {
  COSE_ALGORITHMS,
  coseKeyToPublicKey,
  RSA_MIN_BITS,
  verifyAssertion,
  verifyRegistration,
  type RegistrationVerdict,
} from "../packages/body/src/webauthn-verify.ts";
import {
  assertWithSoftwarePasskey,
  attestedAuthData,
  mintSoftwarePasskey,
  registerWithSoftwarePasskey,
  registrationFrom,
  type SoftwarePasskey,
} from "./software-passkey.ts";

const ORIGIN = "https://door.example";
const RP_ID = "door.example";
const CHALLENGE = "Y2hhbGxlbmdlLW9uZQ";

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;
const ED = 0x80;

function verify(response: unknown, over: { challenge?: string; origin?: string; rpId?: string } = {}): RegistrationVerdict {
  return verifyRegistration({
    response: response as Parameters<typeof verifyRegistration>[0]["response"],
    expectedChallenge: over.challenge ?? CHALLENGE,
    expectedOrigins: [over.origin ?? ORIGIN],
    rpId: over.rpId ?? RP_ID,
  });
}

function reason(verdict: RegistrationVerdict): string {
  return verdict.ok ? "ok" : verdict.reason;
}

/** An answer around authenticator data the test has changed. */
function around(passkey: SoftwarePasskey, authData: Uint8Array) {
  return registrationFrom(passkey.id, authData, { challenge: CHALLENGE, origin: ORIGIN });
}

function keyBytes(key: Map<number, number | Uint8Array>): string {
  return isoBase64URL.fromBuffer(isoCBOR.encode(key));
}

describe("registration", () => {
  it("R1 reads the credential, and the key it reads verifies that passkey's assertions", () => {
    for (const alg of ["ES256", "Ed25519"] as const) {
      const passkey = mintSoftwarePasskey(alg);
      const verdict = verify(registerWithSoftwarePasskey(passkey, { challenge: CHALLENGE, rpID: RP_ID, origin: ORIGIN }));
      assert.equal(verdict.ok, true, alg);
      if (!verdict.ok) return;
      assert.equal(verdict.credentialId, passkey.id);
      assert.equal(verdict.publicKeyCose, isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()));
      assert.equal(verdict.counter, 0);
      const later = verifyAssertion({
        response: assertWithSoftwarePasskey(passkey, { challenge: "bGF0ZXI", rpID: RP_ID, origin: ORIGIN }),
        expectedChallenge: "bGF0ZXI",
        expectedOrigins: [ORIGIN],
        rpId: RP_ID,
        publicKeyCose: verdict.publicKeyCose,
      });
      assert.equal(later.ok, true, alg);
    }
  });

  it("R2 refuses an answer made for something else: a sign-in, another challenge, another origin, a frame", () => {
    const passkey = mintSoftwarePasskey();
    const authData = attestedAuthData(passkey, RP_ID);
    const answer = (over: Partial<Parameters<typeof registrationFrom>[2]>) =>
      registrationFrom(passkey.id, authData, { challenge: CHALLENGE, origin: ORIGIN, ...over });
    assert.equal(reason(verify(answer({ type: "webauthn.get" }))), "type");
    assert.equal(reason(verify(answer({ challenge: "b3RoZXI" }))), "challenge");
    assert.equal(reason(verify(answer({ origin: "https://evil.example" }))), "origin");
    assert.equal(reason(verify(answer({ crossOrigin: true }))), "cross-origin");
    assert.equal(reason(verify(answer({}))), "ok");
  });

  it("R3 refuses another relying party, a user who was not verified, and data with no credential in it", () => {
    const passkey = mintSoftwarePasskey();
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, "other.example")))), "rp-id");
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, RP_ID, { flags: UP | AT })))), "user-verification");
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, RP_ID, { flags: UV | AT })))), "user-verification");
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, RP_ID, { flags: UP | UV })))), "attested-credential");
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, RP_ID).subarray(0, 54)))), "authenticator-data");
  });

  it("R4 takes the attestation it asked for and no other", () => {
    const passkey = mintSoftwarePasskey();
    const authData = attestedAuthData(passkey, RP_ID);
    const packed = registrationFrom(passkey.id, authData, { challenge: CHALLENGE, origin: ORIGIN, fmt: "packed" });
    assert.equal(reason(verify(packed)), "attestation-format");
    const stated = registrationFrom(passkey.id, authData, {
      challenge: CHALLENGE,
      origin: ORIGIN,
      statement: new Map([["sig", new Uint8Array([1, 2, 3])]]),
    });
    assert.equal(reason(verify(stated)), "attestation-statement");
    const junk = { ...around(passkey, authData) };
    junk.response = { ...junk.response, attestationObject: isoBase64URL.fromBuffer(new Uint8Array([0x01])) };
    assert.equal(reason(verify(junk)), "attestation");
    const none = { ...around(passkey, authData), response: { clientDataJSON: around(passkey, authData).response.clientDataJSON } };
    assert.equal(reason(verify(none)), "bad-registration");
  });

  it("R5 accounts for every byte after the key: an extensions map when the flag says so, nothing otherwise", () => {
    const passkey = mintSoftwarePasskey();
    const extensions = isoCBOR.encode(new Map<string, number>([["credProtect", 2]]));
    const withExtensions = verify(around(passkey, attestedAuthData(passkey, RP_ID, { flags: UP | UV | AT | ED, afterKey: extensions })));
    assert.equal(withExtensions.ok, true);
    if (withExtensions.ok) {
      assert.equal(withExtensions.publicKeyCose, isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()));
    }
    const flagged = (afterKey?: Uint8Array) =>
      reason(verify(around(passkey, attestedAuthData(passkey, RP_ID, { flags: UP | UV | AT | ED, ...(afterKey ? { afterKey } : {}) }))));
    assert.equal(flagged(), "extensions");
    assert.equal(flagged(new Uint8Array([0x01])), "extensions");
    assert.equal(flagged(new Uint8Array([...extensions, 0x00])), "extensions");
    // The flag is clear, so what follows the key is not extensions, it is something hidden.
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, RP_ID, { afterKey: extensions })))), "authenticator-data");
    assert.equal(reason(verify(around(passkey, attestedAuthData(passkey, RP_ID, { afterKey: new Uint8Array([0x00]) })))), "authenticator-data");
  });

  it("R6 the id is the one in the authenticator data, and its length is believed only inside the data", () => {
    const passkey = mintSoftwarePasskey();
    const honest = attestedAuthData(passkey, RP_ID);
    const other = mintSoftwarePasskey();
    assert.equal(reason(verify(registrationFrom(other.id, honest, { challenge: CHALLENGE, origin: ORIGIN }))), "credential-id");
    assert.equal(reason(verify({ ...around(passkey, honest), rawId: other.id })), "credential-id");
    assert.equal(reason(verify({ ...around(passkey, honest), id: undefined })), "credential-id");
    for (const length of [0, 1024, honest.length - 55, 0xffff]) {
      const bent = Buffer.from(honest);
      bent.writeUInt16BE(length, 53);
      assert.equal(reason(verify(around(passkey, bent))), "credential-id", `length ${length}`);
    }
    // The same bounds when the page and the data agree with each other: an
    // id of no bytes, one longer than an id may be, and one with no key after it.
    const idOf = (bytes: number) => isoBase64URL.fromBuffer(new Uint8Array(randomBytes(bytes)));
    const empty = Buffer.from(honest);
    empty.writeUInt16BE(0, 53);
    assert.equal(reason(verify(registrationFrom("", empty, { challenge: CHALLENGE, origin: ORIGIN }))), "credential-id");
    const longest = { ...passkey, id: idOf(1023) };
    assert.equal(reason(verify(around(longest, attestedAuthData(longest, RP_ID)))), "ok");
    const tooLong = { ...passkey, id: idOf(1024) };
    assert.equal(reason(verify(around(tooLong, attestedAuthData(tooLong, RP_ID)))), "credential-id");
    const keyless = honest.subarray(0, honest.length - passkey.publicKeyCose.length);
    assert.equal(reason(verify(around(passkey, keyless))), "credential-id");
  });

  it("R7 refuses a key it could not verify with, and one it cannot find the end of", () => {
    const passkey = mintSoftwarePasskey();
    const honest = attestedAuthData(passkey, RP_ID);
    const keyStart = honest.length - passkey.publicKeyCose.length;

    const es384 = isoCBOR.decodeFirst<Map<number, number | Uint8Array>>(passkey.publicKeyCose.slice());
    es384.set(3, -35);
    const relabelled = { ...passkey, publicKeyCose: isoCBOR.encode(es384) };
    assert.equal(reason(verify(around(relabelled, attestedAuthData(relabelled, RP_ID)))), "public-key");

    assert.equal(reason(verify(around(passkey, honest.subarray(0, honest.length - 5)))), "public-key");

    const indefinite = Buffer.from(honest);
    indefinite[keyStart] = 0xbf;
    assert.equal(reason(verify(around(passkey, indefinite))), "public-key");

    const tagged = Buffer.from(honest);
    tagged[keyStart] = 0xc0;
    assert.equal(reason(verify(around(passkey, tagged))), "public-key");

    // A map that claims more entries than there are bytes left.
    const greedy = Buffer.concat([honest.subarray(0, keyStart), Buffer.from([0xba, 0xff, 0xff, 0xff, 0xff])]);
    assert.equal(reason(verify(around(passkey, greedy))), "public-key");

    // Arrays inside arrays, deeper than any key goes.
    const nested = Buffer.concat([honest.subarray(0, keyStart), Buffer.alloc(40, 0x81), Buffer.from([0x00])]);
    assert.equal(reason(verify(around(passkey, nested))), "public-key");
    // A good key with a label of its own that nests: shallow is read past, deep is not a key.
    const labelled = (depth: number) => {
      let value: number | number[] = 0;
      for (let i = 0; i < depth; i += 1) value = [value] as number[];
      const key = isoCBOR.decodeFirst<Map<number, unknown>>(passkey.publicKeyCose.slice());
      key.set(99, value);
      const carrier = { ...passkey, publicKeyCose: isoCBOR.encode(key as Map<number, number>) };
      return reason(verify(around(carrier, attestedAuthData(carrier, RP_ID))));
    };
    assert.equal(labelled(2), "ok");
    assert.equal(labelled(6), "public-key");
  });

  it("R8 what an enrolment offers is what the verifier takes, one for one", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
    const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
    const bytes = (value: string | undefined) => new Uint8Array(Buffer.from(value ?? "", "base64url"));
    const taken = new Map<number, string>([
      [-7, keyBytes(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, bytes(ec.x)], [-3, bytes(ec.y)]]))],
      [-8, keyBytes(new Map<number, number | Uint8Array>([[1, 1], [3, -8], [-1, 6], [-2, bytes(ed.x)]]))],
      [-257, keyBytes(new Map<number, number | Uint8Array>([[1, 3], [3, -257], [-1, bytes(rsa.n)], [-2, bytes(rsa.e)]]))],
    ]);
    assert.deepEqual([...COSE_ALGORITHMS].sort(), [...taken.keys()].sort());
    for (const [alg, key] of taken) assert.notEqual(coseKeyToPublicKey(key), null, `alg ${alg}`);
    const es384 = keyBytes(new Map<number, number | Uint8Array>([[1, 2], [3, -35], [-1, 1], [-2, bytes(ec.x)], [-3, bytes(ec.y)]]));
    assert.equal(coseKeyToPublicKey(es384), null);

    // An RSA modulus that imports is not yet one a signature fits in.
    const rsaKey = (n: Uint8Array, e: Uint8Array) => keyBytes(new Map<number, number | Uint8Array>([[1, 3], [3, -257], [-1, n], [-2, e]]));
    assert.equal(coseKeyToPublicKey(rsaKey(new Uint8Array([1]), new Uint8Array([1, 0, 1]))), null);
    const short = generateKeyPairSync("rsa", { modulusLength: RSA_MIN_BITS - 8 }).publicKey.export({ format: "jwk" });
    assert.equal(coseKeyToPublicKey(rsaKey(bytes(short.n), bytes(short.e))), null);
    // And an enrolment that carries one is refused before the code is spent on it.
    const passkey = mintSoftwarePasskey();
    const tiny = { ...passkey, publicKeyCose: isoBase64URL.toBuffer(rsaKey(new Uint8Array([1]), new Uint8Array([1, 0, 1]))) };
    assert.equal(reason(verify(around(tiny, attestedAuthData(tiny, RP_ID)))), "public-key");
  });
});
