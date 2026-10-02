import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger, verifyReceipt } from "@verax-ai/proxy";
import {
  CborTag,
  decodeCborItem,
  decodeSign1,
  rootFromInclusion,
  sign1Structure,
} from "../packages/proxy/src/transparency-receipt.ts";

import { runAnchor } from "../packages/body/src/anchor-cli.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ledger = join(root, "test-vectors", "v1", "valid-full", "ledger");
const pins = join(root, "test-vectors", "v1", "valid-full", "pins");
// A receipt for valid-full's checkpoint, issued by action-state-group/capsule-anchor
// at 0444792 run on loopback with an ephemeral key; service-key.pem is that key.
const fixture = join(root, "tests", "fixtures", "anchor-capsule");
const serviceKey = readFileSync(join(fixture, "service-key.pem"), "utf8");

function copyLedger(withAnchors = true): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-anchor-"));
  for (const name of readdirSync(ledger)) copyFileSync(join(ledger, name), join(dir, name));
  if (withAnchors) copyFileSync(join(fixture, "checkpoint-anchors.jsonl"), join(dir, "checkpoint-anchors.jsonl"));
  return dir;
}

const pinned = () => ({
  publicKeyPem: readFileSync(join(pins, "record-key.pem"), "utf8"),
  witnessPublicKeyPem: readFileSync(join(pins, "witness-key.pem"), "utf8"),
  checkpointPublicKeyPem: readFileSync(join(pins, "witness-key.pem"), "utf8"),
});

type Row = { checkpointHash: string; entryHash: string; leafIndex: number; treeSize: number; receiptB64: string };

function editAnchor(dir: string, edit: (row: Row) => void): void {
  const path = join(dir, "checkpoint-anchors.jsonl");
  const row = JSON.parse(readFileSync(path, "utf8").trim()) as Row;
  edit(row);
  writeFileSync(path, `${JSON.stringify(row)}\n`, "utf8");
}

/** Enough CBOR to re-encode a receipt: uint, nint, bstr, tstr, array, map, null, tag. */
function cbor(value: unknown): Buffer {
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
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof CborTag) return Buffer.concat([head(6, value.tag), cbor(value.value)]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error("cbor-test-encoder");
}

/** The fixture's receipt with its protected header replaced, signed again by a key this test holds. */
function resignedReceipt(protectedHeader: Map<unknown, unknown>): { receipt: Buffer; keyPem: string; entry: Buffer } {
  const row = JSON.parse(readFileSync(join(fixture, "checkpoint-anchors.jsonl"), "utf8").trim()) as Row;
  const original = decodeSign1(Buffer.from(row.receiptB64, "base64"));
  const entry = Buffer.from(row.entryHash, "hex");
  const proof = (original.unprotected.get(396) as Map<unknown, unknown[]>).get(-1)![0] as Uint8Array;
  const [treeSize, leafIndex, path] = decodeCborItem(proof) as [number, number, Uint8Array[]];
  const root = rootFromInclusion(entry, leafIndex, treeSize, path);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const protectedBytes = cbor(protectedHeader);
  const signature = sign(null, sign1Structure(protectedBytes, root), privateKey);
  const receipt = cbor(new CborTag(18, [protectedBytes, original.unprotected, null, new Uint8Array(signature)]));
  return { receipt, keyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), entry };
}

function otherKey(): string {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

/**
 * A checkpoint registered with a Transparency Service someone else runs is
 * held by a second party. The receipt names no key, so it says nothing until
 * the reader checks it under the service key they hold.
 */
describe("anchors in verify", () => {
  it("a receipt from capsule-anchor verifies under its service key", async () => {
    const dir = copyLedger();
    try {
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.anchors.verified, 1);
      assert.match(result.anchors.line, /verify under the key you supplied; the newest anchored checkpoint covers 8 record/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("without the service key the receipt is counted and said to be unchecked", async () => {
    const dir = copyLedger();
    try {
      const result = await verifyLedger(dir, pinned());
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.anchors.checked, false);
      assert.match(result.anchors.line, /not checked: pin the service key with --anchor-key/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a ledger with no anchors says so and still verifies", async () => {
    const dir = copyLedger(false);
    try {
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.match(result.anchors.line, /^anchors: none/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("another service key does not verify the receipt", async () => {
    const dir = copyLedger();
    try {
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: otherKey() });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("anchor receipt does not verify")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a flipped byte in the receipt's audit path fails at the signature over the rebuilt root", async () => {
    const dir = copyLedger();
    try {
      editAnchor(dir, (row) => {
        const bytes = Buffer.from(row.receiptB64, "base64");
        // The audit path sits in the unprotected header, before the 64-byte signature.
        bytes[bytes.length - 70] = bytes[bytes.length - 70]! ^ 0x01;
        row.receiptB64 = bytes.toString("base64");
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.includes("(receipt-sig:")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an entry hash that is not the checkpoint's is named before the receipt is read", async () => {
    const dir = copyLedger();
    try {
      editAnchor(dir, (row) => {
        row.entryHash = createHash("sha256").update("another entry").digest("hex");
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("anchor entry hash is not the checkpoint's")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a receipt whose protected vds is not RFC9162_SHA256 fails at the vds gate, though its signature is good", () => {
    const honest = resignedReceipt(new Map<unknown, unknown>([[1, -8], [395, 1]]));
    assert.equal(verifyReceipt(honest.receipt, honest.entry, honest.keyPem).ok, true);
    const other = resignedReceipt(new Map<unknown, unknown>([[1, -8], [395, 2]]));
    const check = verifyReceipt(other.receipt, other.entry, other.keyPem);
    assert.equal(check.ok, false);
    assert.equal(check.ok ? null : check.stage, "vds-gate");
  });

  it("a receipt that marks a header critical is refused unless this reader understands it", () => {
    const understood = resignedReceipt(new Map<unknown, unknown>([[1, -8], [395, 1], [2, [395]]]));
    assert.equal(verifyReceipt(understood.receipt, understood.entry, understood.keyPem).ok, true);
    for (const crit of [[999], [], "395"]) {
      const r = resignedReceipt(new Map<unknown, unknown>([[1, -8], [395, 1], [2, crit]]));
      const check = verifyReceipt(r.receipt, r.entry, r.keyPem);
      assert.equal(check.ok, false, `crit ${JSON.stringify(crit)} was accepted`);
      assert.equal(check.ok ? null : check.stage, "receipt-decode");
    }
  });

  it("a receipt for a checkpoint the ledger does not hold is named", async () => {
    const dir = copyLedger();
    try {
      editAnchor(dir, (row) => {
        row.checkpointHash = "00".repeat(32);
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("anchor names a checkpoint the ledger does not hold")));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a row whose leaf position disagrees with its receipt is named", async () => {
    const dir = copyLedger();
    try {
      editAnchor(dir, (row) => {
        row.treeSize += 1;
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("anchor row disagrees with its receipt")));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("verax anchor", () => {
  const row = JSON.parse(readFileSync(join(fixture, "checkpoint-anchors.jsonl"), "utf8").trim()) as Row;
  const answer = {
    receipt_b64: row.receiptB64,
    entry_hash: row.entryHash,
    leaf_index: row.leafIndex,
    tree_size: row.treeSize,
  };

  function fakeService(body: unknown, seen: { url: string; body: string }[]): typeof fetch {
    return (async (url: string | URL | Request, init?: RequestInit) => {
      seen.push({ url: String(url), body: String(init?.body ?? "") });
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
  }

  it("sends only the checkpoint hash, keeps the receipt, and does not send it twice", async () => {
    const dir = copyLedger(false);
    const keyFile = join(dir, "service-key.pem");
    writeFileSync(keyFile, serviceKey, "utf8");
    try {
      const seen: { url: string; body: string }[] = [];
      const out: string[] = [];
      const code = await runAnchor(
        [dir, "--service", "https://witness.example", "--service-key", keyFile],
        (s) => out.push(s),
        fakeService(answer, seen),
        () => 1,
      );
      assert.equal(code, 0, out.join("\n"));
      assert.equal(seen.length, 1);
      assert.equal(seen[0]!.url, "https://witness.example/register");
      assert.deepEqual(JSON.parse(seen[0]!.body), { capsule_id: row.checkpointHash });
      const kept = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: serviceKey });
      assert.equal(kept.anchors.verified, 1, JSON.stringify(kept.problems));
      const again = await runAnchor([dir, "--service", "https://witness.example"], (s) => out.push(s), fakeService(answer, seen));
      assert.equal(again, 0);
      assert.equal(seen.length, 1, "a checkpoint already anchored at that service was sent again");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to keep a receipt that does not verify under --service-key", async () => {
    const dir = copyLedger(false);
    const keyFile = join(dir, "other.pem");
    writeFileSync(keyFile, otherKey(), "utf8");
    try {
      const out: string[] = [];
      const code = await runAnchor([dir, "--service", "https://witness.example", "--service-key", keyFile], (s) => out.push(s), fakeService(answer, []));
      assert.equal(code, 1);
      assert.match(out.join("\n"), /not kept/);
      const result = await verifyLedger(dir, pinned());
      assert.match(result.anchors.line, /^anchors: none/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a receipt for another entry", async () => {
    const dir = copyLedger(false);
    try {
      const out: string[] = [];
      const code = await runAnchor([dir, "--service", "https://witness.example"], (s) => out.push(s), fakeService({ ...answer, entry_hash: "11".repeat(32) }, []));
      assert.equal(code, 1);
      assert.match(out.join("\n"), /another entry/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an empty --service-key file is a usage error, not a skipped check", async () => {
    const dir = copyLedger(false);
    const keyFile = join(dir, "empty.pem");
    writeFileSync(keyFile, "  \n", "utf8");
    try {
      const out: string[] = [];
      const code = await runAnchor([dir, "--service", "https://witness.example", "--service-key", keyFile], (s) => out.push(s), fakeService(answer, []));
      assert.equal(code, 64);
      assert.match((await verifyLedger(dir, pinned())).anchors.line, /^anchors: none/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses an answer larger than a receipt can be, without keeping it", async () => {
    const dir = copyLedger(false);
    try {
      const out: string[] = [];
      // Under the body cap, over what a receipt can be: refused by the receipt length.
      const long = { ...answer, receipt_b64: "A".repeat(100_000) };
      assert.equal(await runAnchor([dir, "--service", "https://witness.example"], (s) => out.push(s), fakeService(long, [])), 1);
      // A short receipt in a body past the cap: refused before the body is parsed.
      const padded = { ...answer, padding: "A".repeat(300_000) };
      assert.equal(await runAnchor([dir, "--service", "https://witness.example"], (s) => out.push(s), fakeService(padded, [])), 1);
      assert.match((await verifyLedger(dir, pinned())).anchors.line, /^anchors: none/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses plain http except on loopback", async () => {
    const out: string[] = [];
    assert.equal(await runAnchor(["dir", "--service", "http://witness.example"], (s) => out.push(s), fakeService(answer, [])), 64);
    assert.equal(await runAnchor(["dir", "--service", "https://u:p@witness.example"], (s) => out.push(s), fakeService(answer, [])), 64);
  });

  it("the receipt verifier itself fails closed on a different leaf entry", () => {
    const check = verifyReceipt(Buffer.from(row.receiptB64, "base64"), Buffer.alloc(32, 7), serviceKey);
    assert.equal(check.ok, false);
  });
});
