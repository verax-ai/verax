import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync, verify, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { fixtureEd25519Pems } from "@cedulon/cose";

import {
  checkpointStatement,
  didX509Issuer,
  didX509Value,
  readCheckpointStatement,
  readIssuerChain,
} from "../packages/proxy/src/signed-statement.ts";
import { CborTag, decodeCborItem, decodeSign1, sign1Structure } from "../packages/proxy/src/transparency-receipt.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// chain.pem: a leaf for the Cedulon fixture Ed25519 key (CN=verax-witness)
// issued by a test CA (CN=Verax Test Witness CA), made with openssl 3.5.
const chainPem = readFileSync(join(root, "tests", "fixtures", "scitt-issuer", "chain.pem"), "utf8");
const keys = fixtureEd25519Pems();
const hash = createHash("sha256").update("a checkpoint").digest("hex");

function otherKeys(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/**
 * The witness registers a checkpoint with a SCITT Transparency Service as a
 * Signed Statement (RFC 9943): a COSE Hash Envelope whose payload is the
 * checkpoint hash, signed by the witness key, with the issuer named as a
 * did:x509 over the certificate chain it carries.
 */
describe("checkpoint Signed Statements", () => {
  it("reads a PEM chain leaf first, at least two certificates", () => {
    const chain = readIssuerChain(chainPem);
    assert.equal(chain.length, 2);
    assert.match(new X509Certificate(chain[0]!).subject, /CN=verax-witness/);
    assert.throws(() => readIssuerChain(chainPem.slice(0, chainPem.indexOf("-----END CERTIFICATE-----") + 26)), /issuer-chain-too-short/);
    assert.throws(() => readIssuerChain(keys.publicKeyPem), /issuer-chain-too-short/);
  });

  it("names the issuer as did:x509 over the root's SHA-256 and the leaf's CN", () => {
    const chain = readIssuerChain(chainPem);
    const fingerprint = createHash("sha256").update(chain[chain.length - 1]!).digest("base64url");
    assert.equal(didX509Issuer(chain), `did:x509:0:sha256:${fingerprint}::subject:CN:verax-witness`);
  });

  it("percent-encodes a value outside the did:x509 unreserved set", () => {
    assert.equal(didX509Value("verax-witness_1.0"), "verax-witness_1.0");
    assert.equal(didX509Value("Verax Witness"), "Verax%20Witness");
    assert.equal(didX509Value("a:b/c~ğ"), "a%3Ab%2Fc%7E%C4%9F");
  });

  it("signs the checkpoint hash as a hash envelope with CWT claims and x5chain", () => {
    const chain = readIssuerChain(chainPem);
    const statement = checkpointStatement(hash, chain, keys);
    const sign1 = decodeSign1(statement);
    assert.equal(sign1.protectedHeader.get(1), -8);
    assert.equal(sign1.protectedHeader.get(258), -16);
    assert.equal(sign1.protectedHeader.get(259), "application/cose");
    const cwt = sign1.protectedHeader.get(15) as Map<unknown, unknown>;
    assert.equal(cwt.get(1), didX509Issuer(chain));
    assert.match(String(cwt.get(2)), /^verax-ledger:[0-9a-f]{64}$/);
    const x5chain = sign1.protectedHeader.get(33) as Uint8Array[];
    assert.equal(x5chain.length, 2);
    assert.deepEqual(Buffer.from(x5chain[0]!), Buffer.from(chain[0]!));
    assert.deepEqual(Buffer.from(sign1.payload!), Buffer.from(hash, "hex"));
    assert.equal(sign1.unprotected.size, 0);
    assert.ok(verify(null, sign1Structure(sign1.protectedBytes, sign1.payload!), keys.publicKeyPem, sign1.signature));
    // scitt-ccf-ledger 0.21.0 answers 400 "COSE_Sign1 is not tagged" to an untagged one.
    const outer = decodeCborItem(statement);
    assert.ok(outer instanceof CborTag && outer.tag === 18, "a tagged COSE_Sign1");
  });

  it("refuses a chain whose leaf carries another key", () => {
    const chain = readIssuerChain(chainPem);
    assert.throws(() => checkpointStatement(hash, chain, otherKeys()), /issuer-chain-leaf-key/);
  });

  it("reads back the issuer and subject for the checkpoint it names", () => {
    const chain = readIssuerChain(chainPem);
    const statement = checkpointStatement(hash, chain, keys);
    const read = readCheckpointStatement(statement, hash, keys.publicKeyPem);
    assert.equal(read.ok, true, JSON.stringify(read));
    assert.ok(read.ok);
    assert.equal(read.issuer, didX509Issuer(chain));
  });

  it("a statement for another checkpoint is refused", () => {
    const statement = checkpointStatement(hash, readIssuerChain(chainPem), keys);
    const other = createHash("sha256").update("another checkpoint").digest("hex");
    assert.deepEqual(readCheckpointStatement(statement, other, keys.publicKeyPem), {
      ok: false,
      reason: "the statement names another checkpoint",
    });
  });

  it("a statement that does not verify under the checkpoint key is refused", () => {
    const statement = checkpointStatement(hash, readIssuerChain(chainPem), keys);
    assert.deepEqual(readCheckpointStatement(statement, hash, otherKeys().publicKeyPem), {
      ok: false,
      reason: "the statement does not verify under the checkpoint key",
    });
  });

  it("bytes that are not a statement are refused, not thrown", () => {
    const read = readCheckpointStatement(new Uint8Array([1, 2, 3]), hash, keys.publicKeyPem);
    assert.equal(read.ok, false);
  });
});
