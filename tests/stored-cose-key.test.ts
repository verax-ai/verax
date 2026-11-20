import { strict as assert } from "node:assert";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, it } from "node:test";

import { coseKeyToPublicKey } from "../packages/body/src/webauthn-verify.ts";

/**
 * @cedulon/cose 0.16 refuses a CBOR map whose keys are out of the
 * deterministic order. An operator passkey enrolled before it may be stored
 * that way; reading it for an assertion must still work, while a new
 * enrolment stays strict.
 */
function ec2Parts() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  return { x: Buffer.from(jwk.x, "base64url"), y: Buffer.from(jwk.y, "base64url"), jwk };
}

/** kty 2, alg -7, crv 1, x, y, written in the given label order. */
function coseEc2(x: Buffer, y: Buffer, order: number[], extra: Buffer = Buffer.alloc(0)): string {
  const item: Record<number, Buffer> = {
    1: Buffer.from([0x01, 0x02]),
    3: Buffer.from([0x03, 0x26]),
    [-1]: Buffer.from([0x20, 0x01]),
    [-2]: Buffer.concat([Buffer.from([0x21, 0x58, 0x20]), x]),
    [-3]: Buffer.concat([Buffer.from([0x22, 0x58, 0x20]), y]),
  };
  return Buffer.concat([Buffer.from([0xa0 + order.length]), ...order.map((k) => item[k]), extra]).toString("base64url");
}

const exportXY = (k: KeyObject | null) => {
  assert.ok(k, "expected a key");
  const j = k.export({ format: "jwk" }) as { x: string; y: string };
  return `${j.x}.${j.y}`;
};

describe("a stored COSE key out of deterministic order", () => {
  const { x, y, jwk } = ec2Parts();
  const canonical = coseEc2(x, y, [1, 3, -1, -2, -3]);
  const outOfOrder = coseEc2(x, y, [3, 1, -2, -1, -3]);

  it("the canonical key reads the same in both modes", () => {
    assert.equal(exportXY(coseKeyToPublicKey(canonical)), `${jwk.x}.${jwk.y}`);
    assert.equal(exportXY(coseKeyToPublicKey(canonical, { storedKey: true })), `${jwk.x}.${jwk.y}`);
  });

  it("is refused for a new enrolment and read as the same public key when stored", () => {
    assert.equal(coseKeyToPublicKey(outOfOrder), null);
    assert.equal(exportXY(coseKeyToPublicKey(outOfOrder, { storedKey: true })), `${jwk.x}.${jwk.y}`);
  });

  it("reads a stored key that carries key_ops out of order", () => {
    const withOps = (order: "canonical" | "shuffled") => {
      const ops = Buffer.from([0x04, 0x81, 0x02]); // key_ops: [verify]
      const kty = Buffer.from([0x01, 0x02]);
      const alg = Buffer.from([0x03, 0x26]);
      const crv = Buffer.from([0x20, 0x01]);
      const xs = Buffer.concat([Buffer.from([0x21, 0x58, 0x20]), x]);
      const ys = Buffer.concat([Buffer.from([0x22, 0x58, 0x20]), y]);
      const parts = order === "canonical" ? [kty, alg, ops, crv, xs, ys] : [ops, alg, kty, xs, crv, ys];
      return Buffer.concat([Buffer.from([0xa6]), ...parts]).toString("base64url");
    };
    assert.equal(exportXY(coseKeyToPublicKey(withOps("canonical"))), `${jwk.x}.${jwk.y}`);
    assert.equal(coseKeyToPublicKey(withOps("shuffled")), null);
    assert.equal(exportXY(coseKeyToPublicKey(withOps("shuffled"), { storedKey: true })), `${jwk.x}.${jwk.y}`);
  });

  it("still refuses a stored key with trailing bytes, a duplicate label or a text value", () => {
    const trailing = coseEc2(x, y, [3, 1, -2, -1, -3], Buffer.from([0x00]));
    const duplicate = coseEc2(x, y, [3, 3, -2, -1, -3]);
    const text = Buffer.concat([
      Buffer.from([0xa5, 0x03, 0x26, 0x01, 0x62, 0x6f, 0x6b, 0x20, 0x01]),
      Buffer.from([0x21, 0x58, 0x20]),
      x,
      Buffer.from([0x22, 0x58, 0x20]),
      y,
    ]).toString("base64url");
    const longHead = Buffer.concat([
      Buffer.from([0xb8, 0x05, 0x03, 0x26, 0x01, 0x02, 0x20, 0x01]),
      Buffer.from([0x21, 0x58, 0x20]),
      x,
      Buffer.from([0x22, 0x58, 0x20]),
      y,
    ]).toString("base64url");
    for (const [name, b64] of Object.entries({ trailing, duplicate, text, longHead })) {
      assert.equal(coseKeyToPublicKey(b64, { storedKey: true }), null, name);
    }
  });
});
