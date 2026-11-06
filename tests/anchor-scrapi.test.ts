import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { signCheckpoint } from "@cedulon/checkpoint";
import { fixtureEd25519Pems } from "@cedulon/cose";
import { readAnchors, readCheckpointFile, verifyLedger } from "@verax-ai/proxy";

import {
  entryIdFromLocation,
  registerStatement,
  runAnchor,
  statementIssuer,
} from "../packages/body/src/anchor-cli.ts";
import { anchorPendingCheckpoints, witnessAnchorFromEnv } from "../packages/body/src/witness.ts";
import { ccfReceiptFor, sha256 } from "./ccf-receipt-helper.ts";
import { checkpointStatement, readIssuerChain } from "../packages/proxy/src/signed-statement.ts";
import { decodeSign1, verifyCcfReceipt } from "../packages/proxy/src/transparency-receipt.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// A ledger written by a real Verax body and witness (test-vectors/tools/capture.ts),
// its checkpoint registered over SCRAPI at microsoft/scitt-ccf-ledger 0.21.0 (9aac12f)
// run as a single-node development service. pins/anchor-key.pem is that service's
// identity key (P-384); transparent-statement.cose is what GET /entries/2.12/statement
// returned. witness-chain.pem is the witness certificate and the throwaway CA that issued it.
const fixture = join(root, "tests", "fixtures", "anchor-ccf");
const pin = (name: string) => readFileSync(join(fixture, "pins", name), "utf8");
const anchorKey = pin("anchor-key.pem");
const row = JSON.parse(readFileSync(join(fixture, "ledger", "checkpoint-anchors.jsonl"), "utf8").trim()) as {
  checkpointHash: string;
  entryId: string;
  statementB64: string;
  receiptB64: string;
};
const statement = Buffer.from(row.statementB64, "base64");
const receipt = Buffer.from(row.receiptB64, "base64");

const pinned = () => ({
  publicKeyPem: pin("record-key.pem"),
  effectPublicKeyPem: pin("effect-key.pem"),
  witnessPublicKeyPem: pin("witness-key.pem"),
  checkpointPublicKeyPem: pin("witness-key.pem"),
});

function copyLedger(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-scrapi-"));
  for (const name of readdirSync(join(fixture, "ledger"))) copyFileSync(join(fixture, "ledger", name), join(dir, name));
  return dir;
}

function editRow(dir: string, edit: (r: Record<string, unknown>) => void): void {
  const path = join(dir, "checkpoint-anchors.jsonl");
  const r = JSON.parse(readFileSync(path, "utf8").trim()) as Record<string, unknown>;
  edit(r);
  writeFileSync(path, `${JSON.stringify(r)}\n`, "utf8");
}

function otherEcKey(): string {
  return generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ type: "spki", format: "pem" }).toString();
}

describe("a receipt from scitt-ccf-ledger", () => {
  it("is ES384 over a CCF tree and verifies for the SHA-256 of the statement", () => {
    const sign1 = decodeSign1(receipt);
    assert.equal(sign1.protectedHeader.get(1), -35);
    assert.equal(sign1.protectedHeader.get(395), 2);
    const check = verifyCcfReceipt(receipt, createHash("sha256").update(statement).digest(), anchorKey);
    assert.equal(check.ok, true, JSON.stringify(check));
  });

  it("is the receipt the service embeds in the transparent statement for that entry", () => {
    const transparent = decodeSign1(readFileSync(join(fixture, "transparent-statement.cose")));
    const registered = decodeSign1(statement);
    assert.deepEqual(Buffer.from(transparent.protectedBytes), Buffer.from(registered.protectedBytes));
    assert.deepEqual(Buffer.from(transparent.signature), Buffer.from(registered.signature));
    const embedded = transparent.unprotected.get(394) as Uint8Array[];
    assert.equal(embedded.length, 1);
    assert.deepEqual(Buffer.from(embedded[0]!), receipt);
  });
});

describe("SCRAPI anchors in verify", () => {
  it("the ledger verifies with its checkpoint anchored, under the service key", async () => {
    const dir = copyLedger();
    try {
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: anchorKey, requireAnchored: true, anchorGraceMs: 0 });
      assert.deepEqual(result.problems, []);
      assert.equal(result.anchors.verified, 1);
      assert.match(result.anchors.line, /1 receipt\(s\) from https:\/\/localhost:8000 verify under the key you supplied/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("another service key does not verify the receipt", async () => {
    const dir = copyLedger();
    try {
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: otherEcKey() });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => /anchor receipt does not verify: .* \(receipt-sig: /.test(p)), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an edited statement is not this checkpoint's, so its receipt is not read", async () => {
    const dir = copyLedger();
    try {
      editRow(dir, (r) => {
        const bytes = Buffer.from(String(r.statementB64), "base64");
        bytes[bytes.length - 1]! ^= 0x01;
        r.statementB64 = bytes.toString("base64");
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: anchorKey });
      assert.equal(result.ok, false);
      assert.ok(
        result.problems.some((p) => /anchor statement is not this checkpoint's: .*does not verify under the checkpoint key/.test(p)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a statement for this checkpoint signed by another key is refused", async () => {
    const dir = copyLedger();
    try {
      // Well formed, for the same checkpoint hash, with a chain whose leaf
      // holds the signing key: only the key is not the checkpoint's.
      const chain = readIssuerChain(readFileSync(join(root, "tests", "fixtures", "scitt-issuer", "chain.pem"), "utf8"));
      const forged = checkpointStatement(row.checkpointHash, chain, fixtureEd25519Pems());
      editRow(dir, (r) => {
        r.statementB64 = Buffer.from(forged).toString("base64");
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: anchorKey });
      assert.deepEqual(result.problems, [
        `anchor statement is not this checkpoint's: ${row.checkpointHash.slice(0, 12)} (the statement does not verify under the checkpoint key)`,
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a row that names an entry id that is not a transaction id is not a row", async () => {
    const dir = copyLedger();
    try {
      editRow(dir, (r) => {
        r.entryId = "../2.12";
      });
      const result = await verifyLedger(dir, { ...pinned(), anchorPublicKeyPem: anchorKey });
      assert.ok(result.problems.some((p) => /anchor line 1 is not an anchor row/.test(p)), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

type Call = { url: string; method: string };

/** A service that answers POST /entries with 303, then `pending` 302s, then the receipt. */
function scrapi(opts: { location?: string | null; pending?: number; receipt?: Uint8Array; post?: Response } = {}) {
  const calls: Call[] = [];
  let left = opts.pending ?? 1;
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, method: init?.method ?? "GET" });
    if (init?.method === "POST") {
      if (opts.post) return opts.post;
      const headers = new Headers();
      const location = opts.location === undefined ? "https://elsewhere.example/entries/2.12" : opts.location;
      if (location !== null) headers.set("location", location);
      return new Response(null, { status: 303, headers });
    }
    if (left > 0) {
      left -= 1;
      return new Response(null, { status: 302 });
    }
    return new Response(new Uint8Array(opts.receipt ?? receipt), {
      status: 200,
      headers: { "content-type": "application/scitt-receipt+cose" },
    });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const noWait = async () => undefined;

describe("registering a Signed Statement over SCRAPI", () => {
  it("posts the statement, polls the entry at the service and keeps a row that verifies", async () => {
    const svc = scrapi({ pending: 2 });
    const got = await registerStatement("https://localhost:8000", row.checkpointHash, statement, anchorKey, svc.fetchImpl, () => 7, noWait);
    assert.equal(got.ok, true, JSON.stringify(got));
    assert.ok(got.ok);
    assert.equal(got.checked, true);
    assert.deepEqual(got.row, {
      v: 2,
      checkpointHash: row.checkpointHash,
      service: "https://localhost:8000",
      route: "entries",
      entryId: "2.12",
      statementB64: row.statementB64,
      receiptB64: row.receiptB64,
      atMs: 7,
    });
    assert.deepEqual(svc.calls, [
      { url: "https://localhost:8000/entries?api-version=2026-03-26", method: "POST" },
      { url: "https://localhost:8000/entries/2.12?api-version=2026-03-26", method: "GET" },
      { url: "https://localhost:8000/entries/2.12?api-version=2026-03-26", method: "GET" },
      { url: "https://localhost:8000/entries/2.12?api-version=2026-03-26", method: "GET" },
    ]);
  });

  it("names the service's reason when it refuses the statement", async () => {
    // {-1: "InvalidInput", -2: "COSE_Sign1 is not tagged"}, as scitt-ccf-ledger sends it.
    const problem = Buffer.concat([
      Buffer.of(0xa2, 0x20, 0x6c),
      Buffer.from("InvalidInput"),
      Buffer.of(0x21, 0x78, 0x18),
      Buffer.from("COSE_Sign1 is not tagged"),
    ]);
    const svc = scrapi({
      post: new Response(problem, { status: 400, headers: { "content-type": "application/concise-problem-details+cbor" } }),
    });
    const got = await registerStatement("https://localhost:8000", row.checkpointHash, statement, anchorKey, svc.fetchImpl, Date.now, noWait);
    assert.deepEqual(got, { ok: false, reason: "unreachable", message: "HTTP 400: COSE_Sign1 is not tagged" });
  });

  it("a receipt for another statement is not kept", async () => {
    const svc = scrapi();
    const other = Buffer.from(statement);
    other[other.length - 1]! ^= 0x01;
    const got = await registerStatement("https://localhost:8000", row.checkpointHash, other, null, svc.fetchImpl, Date.now, noWait);
    assert.equal(got.ok, false);
    assert.ok(!got.ok);
    assert.equal(got.reason, "wrong-receipt");
  });

  it("a receipt that does not verify under the service key is not kept", async () => {
    const svc = scrapi();
    const got = await registerStatement("https://localhost:8000", row.checkpointHash, statement, otherEcKey(), svc.fetchImpl, Date.now, noWait);
    assert.equal(got.ok, false);
    assert.ok(!got.ok);
    assert.equal(got.reason, "receipt-unverified");
  });

  it("no entry named is no row", async () => {
    const svc = scrapi({ location: null });
    const got = await registerStatement("https://localhost:8000", row.checkpointHash, statement, anchorKey, svc.fetchImpl, Date.now, noWait);
    assert.deepEqual(got, { ok: false, reason: "wrong-receipt", message: "the service named no entry for the statement" });
  });

  it("an entry still pending after the last poll is no row", async () => {
    const svc = scrapi({ pending: 1000 });
    let waits = 0;
    const got = await registerStatement("https://localhost:8000", row.checkpointHash, statement, anchorKey, svc.fetchImpl, Date.now, async () => {
      waits += 1;
    });
    assert.deepEqual(got, { ok: false, reason: "unreachable", message: "entry 2.12 was not committed in time" });
    assert.equal(waits, 30);
  });

  it("reads an entry id from a Location and refuses anything else", () => {
    assert.equal(entryIdFromLocation("https://ccf.example/entries/2.12", "https://localhost:8000"), "2.12");
    assert.equal(entryIdFromLocation("/entries/2.12", "https://localhost:8000"), "2.12");
    assert.equal(entryIdFromLocation("https://ccf.example/operations/2.12", "https://localhost:8000"), null);
    assert.equal(entryIdFromLocation("https://ccf.example/entries/..%2F2.12", "https://localhost:8000"), null);
    assert.equal(entryIdFromLocation(null, "https://localhost:8000"), null);
  });
});

describe("the witness registers over SCRAPI when it holds a chain", () => {
  const chainPem = readFileSync(join(root, "tests", "fixtures", "scitt-issuer", "chain.pem"), "utf8");
  const validFull = join(root, "test-vectors", "v1", "valid-full");

  /** valid-full with its checkpoint signed again by the key the fixture chain certifies, and that key in keys/. */
  function ledgerForFixtureKey(): string {
    const dir = mkdtempSync(join(tmpdir(), "verax-scrapi-witness-"));
    for (const name of readdirSync(join(validFull, "ledger"))) copyFileSync(join(validFull, "ledger", name), join(dir, name));
    const keys = fixtureEd25519Pems();
    const rows = readCheckpointFile(dir).rows.map((r) => signCheckpoint(r.claims, keys.privateKeyPem, keys.publicKeyPem));
    writeFileSync(join(dir, "checkpoints.jsonl"), rows.map((r) => `${JSON.stringify(r)}\n`).join(""), "utf8");
    mkdirSync(join(dir, "keys"));
    writeFileSync(join(dir, "keys", "witness.private.pem"), keys.privateKeyPem, "utf8");
    writeFileSync(join(dir, "keys", "witness.public.pem"), keys.publicKeyPem, "utf8");
    return dir;
  }

  function statusRows(dir: string): Array<Record<string, unknown>> {
    return readFileSync(join(dir, "witness-status.jsonl"), "utf8")
      .split("\n")
      .filter((l) => l !== "")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  it("signs a statement for each pending checkpoint and keeps a row verify accepts", async () => {
    const dir = ledgerForFixtureKey();
    const service = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const serviceKeyPem = service.publicKey.export({ type: "spki", format: "pem" }).toString();
    const posted: Buffer[] = [];
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted.push(Buffer.from(init.body as Uint8Array));
        return new Response(null, { status: 303, headers: { location: "/entries/3.7" } });
      }
      return new Response(new Uint8Array(ccfReceiptFor(sha256(posted.at(-1)!), service.privateKey)), { status: 200 });
    }) as typeof fetch;
    try {
      await anchorPendingCheckpoints(dir, { serviceName: "https://ts.example", serviceKey: serviceKeyPem, chainPem }, fetchImpl);
      assert.equal(posted.length, 1);
      const anchors = readAnchors(dir);
      assert.equal(anchors.rows.length, 1);
      const kept = anchors.rows[0]!;
      assert.equal(kept.route, "entries");
      assert.ok(kept.v === 2);
      assert.equal(kept.entryId, "3.7");
      assert.deepEqual(Buffer.from(kept.statementB64, "base64"), posted[0]);
      assert.deepEqual(statusRows(dir).at(-1), {
        atMs: statusRows(dir).at(-1)!.atMs,
        result: "anchored",
        service: "https://ts.example",
        checkpointHash: kept.checkpointHash,
        receipt: "verified",
      });
      const result = await verifyLedger(dir, {
        publicKeyPem: readFileSync(join(validFull, "pins", "record-key.pem"), "utf8"),
        witnessPublicKeyPem: readFileSync(join(validFull, "pins", "witness-key.pem"), "utf8"),
        checkpointPublicKeyPem: fixtureEd25519Pems().publicKeyPem,
        anchorPublicKeyPem: serviceKeyPem,
        requireAnchored: true,
        anchorGraceMs: 0,
      });
      assert.deepEqual(result.problems, []);
      assert.equal(result.anchors.verified, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a chain for another key sends nothing and leaves an anchor-failed row", async () => {
    const dir = ledgerForFixtureKey();
    const other = generateKeyPairSync("ed25519");
    writeFileSync(join(dir, "keys", "witness.public.pem"), other.publicKey.export({ type: "spki", format: "pem" }).toString(), "utf8");
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      return new Response(null, { status: 500 });
    }) as typeof fetch;
    try {
      await anchorPendingCheckpoints(dir, { serviceName: "https://ts.example", serviceKey: null, chainPem }, fetchImpl);
      assert.equal(calls, 0);
      const last = statusRows(dir).at(-1)!;
      assert.equal(last.result, "anchor-failed");
      assert.equal(last.reason, "issuer");
      assert.equal(readAnchors(dir).rows.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the witness certificate chain", () => {
  const chainPem = readFileSync(join(root, "tests", "fixtures", "scitt-issuer", "chain.pem"), "utf8");

  function stateWithKeys(keys: { privateKeyPem: string; publicKeyPem: string }): string {
    const dir = mkdtempSync(join(tmpdir(), "verax-issuer-"));
    mkdirSync(join(dir, "keys"));
    writeFileSync(join(dir, "keys", "witness.private.pem"), keys.privateKeyPem, "utf8");
    writeFileSync(join(dir, "keys", "witness.public.pem"), keys.publicKeyPem, "utf8");
    return dir;
  }

  it("is accepted when its leaf holds the witness key", () => {
    const dir = stateWithKeys(fixtureEd25519Pems());
    try {
      const got = statementIssuer(dir, chainPem);
      assert.equal(got.ok, true, got.ok ? "" : got.reason);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("is refused when its leaf holds another key", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const dir = stateWithKeys({
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    });
    try {
      assert.deepEqual(statementIssuer(dir, chainPem), {
        ok: false,
        reason: "the x5chain leaf certificate does not hold this ledger's witness public key",
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("with no witness key in the directory is refused, and no key is created", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-issuer-"));
    try {
      const got = statementIssuer(dir, chainPem);
      assert.equal(got.ok, false);
      assert.deepEqual(readdirSync(dir), []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("VERAX_ANCHOR_X5CHAIN selects SCRAPI and needs a service and a chain of two", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-issuer-env-"));
    try {
      const chainFile = join(dir, "chain.pem");
      writeFileSync(chainFile, chainPem, "utf8");
      const got = witnessAnchorFromEnv({ VERAX_ANCHOR_SERVICE: "https://ts.example", VERAX_ANCHOR_X5CHAIN: chainFile });
      assert.equal(got.ok, true, got.ok ? "" : got.reason);
      assert.ok(got.ok && got.anchor);
      assert.equal(got.anchor.chainPem, chainPem);

      const alone = witnessAnchorFromEnv({ VERAX_ANCHOR_X5CHAIN: chainFile });
      assert.deepEqual(alone, { ok: false, reason: "VERAX_ANCHOR_X5CHAIN is set without VERAX_ANCHOR_SERVICE" });

      const leafOnly = join(dir, "leaf.pem");
      writeFileSync(leafOnly, chainPem.slice(0, chainPem.indexOf("-----END CERTIFICATE-----") + 26), "utf8");
      const short = witnessAnchorFromEnv({ VERAX_ANCHOR_SERVICE: "https://ts.example", VERAX_ANCHOR_X5CHAIN: leafOnly });
      assert.equal(short.ok, false);
      assert.ok(!short.ok);
      assert.match(short.reason, /must hold the witness certificate and at least one CA certificate/);

      const none = witnessAnchorFromEnv({ VERAX_ANCHOR_SERVICE: "https://ts.example" });
      assert.ok(none.ok && none.anchor);
      assert.equal(none.anchor.chainPem, null, "without a chain the digest route stays as it was");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verax anchor --x5chain needs a path", async () => {
    const lines: string[] = [];
    const code = await runAnchor(["/nowhere", "--service", "https://ts.example", "--x5chain"], (s) => lines.push(s));
    assert.equal(code, 64);
    assert.deepEqual(lines, ["anchor: --x5chain needs a file path"]);
  });
});
