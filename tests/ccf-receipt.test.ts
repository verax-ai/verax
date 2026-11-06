import { strict as assert } from "node:assert";
import { generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";

import { CborTag, sign1Structure, verifyCcfReceipt } from "../packages/proxy/src/transparency-receipt.ts";
import { cbor, sha256 } from "./ccf-receipt-helper.ts";

type Built = { receipt: Buffer; keyPem: string; claimsDigest: Buffer; root: Buffer };

/**
 * A receipt in the shape scitt-ccf-ledger issues: ES256, vds 2 in the
 * protected header, one inclusion proof {1: leaf, 2: path} at 396/-1, the
 * payload detached. The leaf is [internal transaction hash, commit evidence,
 * claims digest] and hashes as SHA-256(h || SHA-256(evidence) || digest).
 */
function buildReceipt(edit: {
  vds?: number;
  alg?: number;
  path?: Array<[boolean, Uint8Array]>;
  /** The path written into the proof, when it differs from the one the root was signed over. */
  writtenPath?: Array<[boolean, Uint8Array]>;
  leafDigest?: Buffer;
  proofs?: number;
  payload?: Uint8Array | null;
  crit?: unknown[];
} = {}): Built {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const claimsDigest = sha256(Buffer.from("a signed statement"));
  const internalHash = sha256(Buffer.from("internal"));
  const evidence = "ce:2.17:0f3c9e";
  const path: Array<[boolean, Uint8Array]> = edit.path ?? [
    [true, sha256(Buffer.from("left sibling"))],
    [false, sha256(Buffer.from("right sibling"))],
  ];
  let root = sha256(internalHash, sha256(Buffer.from(evidence)), claimsDigest);
  for (const [left, h] of path) root = left ? sha256(h, root) : sha256(root, h);
  const protectedHeader = new Map<unknown, unknown>([
    [1, edit.alg ?? -7],
    [395, edit.vds ?? 2],
  ]);
  if (edit.crit) protectedHeader.set(2, edit.crit);
  const protectedBytes = cbor(protectedHeader);
  const proof = cbor(new Map<unknown, unknown>([
    [1, [internalHash, evidence, edit.leafDigest ?? claimsDigest]],
    [2, edit.writtenPath ?? path],
  ]));
  const proofs = Array.from({ length: edit.proofs ?? 1 }, () => proof);
  const unprotected = new Map<unknown, unknown>([[396, new Map<unknown, unknown>([[-1, proofs]])]]);
  const signature = sign("sha256", sign1Structure(protectedBytes, root), { key: privateKey, dsaEncoding: "ieee-p1363" });
  const payload = edit.payload === undefined ? null : edit.payload;
  const receipt = cbor(new CborTag(18, [protectedBytes, unprotected, payload, new Uint8Array(signature)]));
  return { receipt, keyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), claimsDigest, root };
}

/**
 * A receipt from a CCF ledger commits to a claims digest, the SHA-256 of the
 * Signed Statement the service registered. The reader rebuilds the root from
 * the leaf and the path and checks the signature over it, offline.
 */
describe("CCF receipts (vds 2)", () => {
  it("verifies for the claims digest under the service key", () => {
    const b = buildReceipt();
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.equal(check.ok, true, JSON.stringify(check));
    assert.ok(check.ok);
    assert.equal(check.root, b.root.toString("hex"));
    assert.equal(check.commitEvidence, "ce:2.17:0f3c9e");
  });

  it("a different claims digest is refused before the signature is read", () => {
    const b = buildReceipt();
    const check = verifyCcfReceipt(b.receipt, sha256(Buffer.from("another statement")), b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "inclusion", reason: "the receipt commits to another claims digest" });
  });

  it("a receipt whose leaf names another digest does not verify for this one", () => {
    const b = buildReceipt({ leafDigest: sha256(Buffer.from("x")) });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.equal(check.ok, false);
    assert.ok(!check.ok);
    assert.equal(check.stage, "inclusion");
  });

  it("another key does not verify it", () => {
    const b = buildReceipt();
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ type: "spki", format: "pem" }).toString();
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, other);
    assert.equal(check.ok, false);
    assert.ok(!check.ok);
    assert.equal(check.stage, "receipt-sig");
  });

  it("an edited path does not verify", () => {
    const signed: Array<[boolean, Uint8Array]> = [[true, sha256(Buffer.from("left sibling"))]];
    const written: Array<[boolean, Uint8Array]> = [[false, sha256(Buffer.from("left sibling"))]];
    const b = buildReceipt({ path: signed, writtenPath: written });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "receipt-sig", reason: "signature does not verify over the rebuilt root" });
  });

  it("an RFC 9162 receipt is not read as a CCF one", () => {
    const b = buildReceipt({ vds: 1 });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "vds-gate", reason: "vds 1 is not CCF_LEDGER_SHA256" });
  });

  it("an attached payload is refused", () => {
    const b = buildReceipt({ payload: new Uint8Array(32) });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "receipt-decode", reason: "receipt payload is not detached" });
  });

  it("more than one inclusion proof is refused", () => {
    const b = buildReceipt({ proofs: 2 });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "receipt-decode", reason: "no single inclusion proof at 396/-1" });
  });

  it("a critical header it does not understand is refused", () => {
    const b = buildReceipt({ crit: [9999] });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "receipt-decode", reason: "a critical header this reader does not understand" });
  });

  it("a path node that is not 32 octets is refused", () => {
    const b = buildReceipt({ path: [[true, new Uint8Array(31)]] });
    const check = verifyCcfReceipt(b.receipt, b.claimsDigest, b.keyPem);
    assert.equal(check.ok, false);
    assert.ok(!check.ok);
    assert.equal(check.stage, "receipt-decode");
  });

  it("a claims digest that is not 32 octets is refused", () => {
    const b = buildReceipt();
    const check = verifyCcfReceipt(b.receipt, new Uint8Array(20), b.keyPem);
    assert.deepEqual(check, { ok: false, stage: "inclusion", reason: "claims digest is not 32 octets" });
  });
});
