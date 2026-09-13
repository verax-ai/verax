/**
 * A software authenticator used only by tests. Production verification stays
 * in @simplewebauthn/server; this file is never imported from the issuer.
 */
import { createHash, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

export type SoftwarePasskey = {
  id: string;
  privateKey: KeyObject;
  publicKeyCose: Uint8Array;
  counter: number;
};

function sha256(data: string | Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function clientData(type: "webauthn.create" | "webauthn.get", challenge: string, origin: string): string {
  return JSON.stringify({ type, challenge, origin, crossOrigin: false });
}

function coseEs256(x: Buffer, y: Buffer): Uint8Array {
  const map = new Map<number, number | Uint8Array>();
  map.set(1, 2);
  map.set(3, -7);
  map.set(-1, 1);
  map.set(-2, new Uint8Array(x));
  map.set(-3, new Uint8Array(y));
  return isoCBOR.encode(map);
}

export function mintSoftwarePasskey(): SoftwarePasskey {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("software-passkey-jwk");
  }
  const publicKeyCose = coseEs256(Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url"));
  const idBytes = sha256(Buffer.concat([Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]));
  return {
    id: isoBase64URL.fromBuffer(new Uint8Array(idBytes)),
    privateKey,
    publicKeyCose,
    counter: 0,
  };
}

function authData(rpID: string, flags: number, counter: number, attested?: Uint8Array): Buffer {
  const rpIdHash = sha256(rpID);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(counter);
  const head = Buffer.concat([rpIdHash, Buffer.from([flags]), count]);
  return attested ? Buffer.concat([head, attested]) : head;
}

export function registerWithSoftwarePasskey(
  passkey: SoftwarePasskey,
  options: { challenge: string; rpID: string; origin: string },
): RegistrationResponseJSON {
  const credId = isoBase64URL.toBuffer(passkey.id);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(credId.length);
  const attested = Buffer.concat([
    Buffer.alloc(16),
    credIdLen,
    Buffer.from(credId),
    Buffer.from(passkey.publicKeyCose),
  ]);
  const flags = 0x01 | 0x04 | 0x40;
  const authenticatorData = authData(options.rpID, flags, passkey.counter, new Uint8Array(attested));
  // tiny-cbor only encodes Map, not plain objects.
  const attestationObject = isoCBOR.encode(
    new Map<string, string | Map<never, never> | Uint8Array>([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", new Uint8Array(authenticatorData)],
    ]),
  );
  const clientDataJSON = clientData("webauthn.create", options.challenge, options.origin);
  return {
    id: passkey.id,
    rawId: passkey.id,
    type: "public-key",
    response: {
      clientDataJSON: isoBase64URL.fromUTF8String(clientDataJSON),
      attestationObject: isoBase64URL.fromBuffer(new Uint8Array(attestationObject)),
    },
    clientExtensionResults: {},
  };
}

export function assertWithSoftwarePasskey(
  passkey: SoftwarePasskey,
  options: { challenge: string; rpID: string; origin: string; counter?: number },
): AuthenticationResponseJSON {
  const next = options.counter ?? passkey.counter + 1;
  passkey.counter = next;
  const flags = 0x01 | 0x04;
  const authenticatorData = authData(options.rpID, flags, next);
  const clientDataJSON = clientData("webauthn.get", options.challenge, options.origin);
  const clientDataHash = sha256(clientDataJSON);
  const signature = createSign("SHA256")
    .update(Buffer.concat([authenticatorData, clientDataHash]))
    .sign(passkey.privateKey);
  return {
    id: passkey.id,
    rawId: passkey.id,
    type: "public-key",
    response: {
      clientDataJSON: isoBase64URL.fromUTF8String(clientDataJSON),
      authenticatorData: isoBase64URL.fromBuffer(new Uint8Array(authenticatorData)),
      signature: isoBase64URL.fromBuffer(new Uint8Array(signature)),
    },
    clientExtensionResults: {},
  };
}
