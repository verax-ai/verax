import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  copyFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger, verifyReceipt } from "@verax-ai/proxy";

import { loadConfig, startService, type RunningService } from "../packages/anchor-service/src/index.ts";
import { pendingAnchors, registerCheckpoint, runAnchor } from "../packages/body/src/anchor-cli.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ledger = join(root, "test-vectors", "v1", "valid-full", "ledger");
const pins = join(root, "test-vectors", "v1", "valid-full", "pins");

const TOKEN = "test-anchor-token-20chars-min";

function copyLedger(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-asvc-ledger-"));
  for (const name of readdirSync(ledger)) copyFileSync(join(ledger, name), join(dir, name));
  return dir;
}

const pinned = () => ({
  publicKeyPem: readFileSync(join(pins, "record-key.pem"), "utf8"),
  witnessPublicKeyPem: readFileSync(join(pins, "witness-key.pem"), "utf8"),
  checkpointPublicKeyPem: readFileSync(join(pins, "witness-key.pem"), "utf8"),
});

type Harness = {
  dir: string;
  service: RunningService;
  tokenFile: string;
  keyFile: string;
  storePath: string;
  publicKeyPem: string;
  token: string;
};

async function startHarness(): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "verax-asvc-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyFile = join(dir, "signing.private.pem");
  const pubFile = join(dir, "signing.public.pem");
  const tokensFile = join(dir, "tokens.json");
  const storePath = join(dir, "store.jsonl");
  const tokenFile = join(dir, "token.txt");
  writeFileSync(keyFile, privatePem, "utf8");
  writeFileSync(pubFile, publicKeyPem, "utf8");
  writeFileSync(tokenFile, `${TOKEN}\n`, "utf8");
  const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
  writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
  const config = loadConfig({
    VERAX_ANCHOR_SVC_TOKENS: tokensFile,
    VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
    VERAX_ANCHOR_SVC_STORE: storePath,
    VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
    VERAX_ANCHOR_SVC_PORT: "0",
  });
  const service = await startService(config);
  return { dir, service, tokenFile, keyFile: pubFile, storePath, publicKeyPem, token: TOKEN };
}

async function stopHarness(h: Harness): Promise<void> {
  await h.service.close();
  rmSync(h.dir, { recursive: true, force: true });
}

function storeBytes(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch {
    return Buffer.alloc(0);
  }
}

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walkFiles(path));
    else out.push(path);
  }
  return out;
}

describe("hosted anchor service", () => {
  it("registerCheckpoint with real fetch gets a row and the receipt verifies", async () => {
    const h = await startHarness();
    const stateDir = copyLedger();
    try {
      const hash = pendingAnchors(stateDir, h.service.url).pending[0]!;
      const got = await registerCheckpoint(h.service.url, hash, h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(got.ok, true, got.ok ? "" : got.message);
      if (!got.ok || got.row.v !== 1) return;
      const check = verifyReceipt(Buffer.from(got.row.receiptB64, "base64"), Buffer.from(got.row.entryHash, "hex"), h.publicKeyPem);
      assert.equal(check.ok, true, check.ok ? "" : check.reason);
      if (!check.ok) return;
      assert.equal(check.leafIndex, got.row.leafIndex);
      assert.equal(check.treeSize, got.row.treeSize);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      await stopHarness(h);
    }
  });

  it("a ledger anchored at the service passes verax verify --anchor-key --require-anchored", async () => {
    const h = await startHarness();
    const stateDir = copyLedger();
    try {
      const out: string[] = [];
      const code = await runAnchor(
        [stateDir, "--service", h.service.url, "--service-key", h.keyFile, "--token-file", h.tokenFile],
        (s) => out.push(s),
      );
      assert.equal(code, 0, out.join("\n"));
      const result = await verifyLedger(stateDir, {
        ...pinned(),
        anchorPublicKeyPem: h.publicKeyPem,
        requireAnchored: true,
        nowMs: 1790974492255 + 60 * 60 * 1000,
      });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.anchors.verified, 1);
      const verifyOut: string[] = [];
      assert.equal(
        await runVerify(
          [
            stateDir,
            "--key",
            join(pins, "record-key.pem"),
            "--witness-key",
            join(pins, "witness-key.pem"),
            "--checkpoint-key",
            join(pins, "witness-key.pem"),
            "--operator-credentials",
            join(pins, "operator-credentials.json"),
            "--anchor-key",
            h.keyFile,
            "--require-anchored",
            "--anchor-grace-ms",
            "0",
          ],
          (s) => verifyOut.push(s),
        ),
        0,
        verifyOut.join("\n"),
      );
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      await stopHarness(h);
    }
  });

  it("no token and wrong token return 401 and leave the store unchanged", async () => {
    const h = await startHarness();
    const stateDir = copyLedger();
    try {
      writeFileSync(h.storePath, "", "utf8");
      const before = storeBytes(h.storePath);
      const hash = pendingAnchors(stateDir, h.service.url).pending[0]!;
      const none = await registerCheckpoint(h.service.url, hash, null, fetch, Date.now, null);
      assert.equal(none.ok, false);
      assert.equal(none.ok ? "" : none.reason, "unauthorized");
      assert.ok(storeBytes(h.storePath).equals(before));
      const wrong = await registerCheckpoint(h.service.url, hash, null, fetch, Date.now, "wrong-token-also-20chars!!");
      assert.equal(wrong.ok, false);
      assert.equal(wrong.ok ? "" : wrong.reason, "unauthorized");
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      await stopHarness(h);
    }
  });

  it("duplicate registration returns the same leaf and the store has one line", async () => {
    const h = await startHarness();
    const stateDir = copyLedger();
    try {
      const hash = pendingAnchors(stateDir, h.service.url).pending[0]!;
      const first = await registerCheckpoint(h.service.url, hash, h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      if (!first.ok || first.row.v !== 1) return;
      const second = await registerCheckpoint(h.service.url, hash, h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(second.ok, true);
      if (!second.ok || second.row.v !== 1) return;
      assert.equal(second.row.leafIndex, first.row.leafIndex);
      const lines = readFileSync(h.storePath, "utf8").split("\n").filter((l) => l.trim() !== "");
      assert.equal(lines.length, 1);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      await stopHarness(h);
    }
  });

  it("two different hashes both verify at their own tree size", async () => {
    const h = await startHarness();
    try {
      const a = "11".repeat(32);
      const b = "22".repeat(32);
      const first = await registerCheckpoint(h.service.url, a, h.publicKeyPem, fetch, Date.now, h.token);
      const second = await registerCheckpoint(h.service.url, b, h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      assert.equal(second.ok, true);
      if (!first.ok || first.row.v !== 1 || !second.ok || second.row.v !== 1) return;
      assert.equal(first.row.treeSize, 1);
      assert.equal(second.row.treeSize, 2);
      assert.equal(first.row.leafIndex, 0);
      assert.equal(second.row.leafIndex, 1);
      const checkA = verifyReceipt(
        Buffer.from(first.row.receiptB64, "base64"),
        Buffer.from(first.row.entryHash, "hex"),
        h.publicKeyPem,
      );
      const checkB = verifyReceipt(
        Buffer.from(second.row.receiptB64, "base64"),
        Buffer.from(second.row.entryHash, "hex"),
        h.publicKeyPem,
      );
      assert.equal(checkA.ok, true, checkA.ok ? "" : checkA.reason);
      assert.equal(checkB.ok, true, checkB.ok ? "" : checkB.reason);
      if (!checkA.ok || !checkB.ok) return;
      assert.equal(checkA.treeSize, 1);
      assert.equal(checkB.treeSize, 2);
    } finally {
      await stopHarness(h);
    }
  });

  it("restart on the same store keeps an old receipt valid and continues the leaf index", async () => {
    const h = await startHarness();
    try {
      const a = "33".repeat(32);
      const first = await registerCheckpoint(h.service.url, a, h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      if (!first.ok || first.row.v !== 1) return;
      const receiptB64 = first.row.receiptB64;
      const entryHash = first.row.entryHash;
      await h.service.close();
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: join(h.dir, "tokens.json"),
        VERAX_ANCHOR_SVC_SIGNING_KEY: join(h.dir, "signing.private.pem"),
        VERAX_ANCHOR_SVC_STORE: h.storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      const again = await startService(config);
      try {
        const check = verifyReceipt(Buffer.from(receiptB64, "base64"), Buffer.from(entryHash, "hex"), h.publicKeyPem);
        assert.equal(check.ok, true, check.ok ? "" : check.reason);
        const b = "44".repeat(32);
        const next = await registerCheckpoint(again.url, b, h.publicKeyPem, fetch, Date.now, h.token);
        assert.equal(next.ok, true);
        if (!next.ok || next.row.v !== 1) return;
        assert.equal(next.row.leafIndex, 1);
        assert.equal(next.row.treeSize, 2);
      } finally {
        await again.close();
      }
    } finally {
      rmSync(h.dir, { recursive: true, force: true });
    }
  });

  it("a corrupted store line stops the start", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-bad-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
      writeFileSync(storePath, "not-json\n", "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assert.rejects(() => startService(config), /store line 1/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("after a run with a token, no file under the state directory contains the token string", async () => {
    const h = await startHarness();
    const stateDir = copyLedger();
    try {
      const out: string[] = [];
      const code = await runAnchor(
        [stateDir, "--service", h.service.url, "--service-key", h.keyFile, "--token-file", h.tokenFile],
        (s) => out.push(s),
      );
      assert.equal(code, 0, out.join("\n"));
      assert.ok(!out.join("\n").includes(TOKEN), "stdout carried the token");
      for (const path of walkFiles(stateDir)) {
        const text = readFileSync(path);
        assert.equal(text.includes(TOKEN), false, `token leaked into ${path}`);
      }
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      await stopHarness(h);
    }
  });
});
