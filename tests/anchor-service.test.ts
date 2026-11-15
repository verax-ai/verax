import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger, verifyReceipt } from "@verax-ai/proxy";
import { decodeSign1 } from "../packages/proxy/src/transparency-receipt.ts";

import { CborTag, encodeCbor } from "../packages/anchor-service/src/cbor.ts";
import {
  appendStore,
  loadConfig,
  startService,
  type RunningService,
} from "../packages/anchor-service/src/index.ts";
import { storeLockPath } from "../packages/anchor-service/src/store-lock.ts";
import { pendingAnchors, registerCheckpoint, runAnchor } from "../packages/body/src/anchor-cli.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";

/** Short beat so lock refusal tests do not wait on the default 2s interval. */
const TEST_LOCK_BEAT_MS = 40;

/** Write a stale lock directory the service will judge and may take over. */
function writeStaleStoreLock(storePath: string, holder: Record<string, unknown>): void {
  const lockPath = storeLockPath(storePath);
  mkdirSync(lockPath);
  writeFileSync(join(lockPath, "holder"), `${JSON.stringify(holder)}\n`, "utf8");
}

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

async function startHarness(env: NodeJS.ProcessEnv = {}): Promise<Harness> {
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
    ...env,
  });
  const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
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
      const again = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
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

  it("a request over the rate limit is 429 and leaves the store unchanged", async () => {
    const h = await startHarness({ VERAX_ANCHOR_SVC_RATE: "1" });
    try {
      const first = await registerCheckpoint(h.service.url, "55".repeat(32), h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      const before = storeBytes(h.storePath);
      const res = await fetch(`${h.service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${h.token}`,
        },
        body: JSON.stringify({ capsule_id: "66".repeat(32) }),
      });
      assert.equal(res.status, 429);
      assert.deepEqual(await res.json(), { error: "rate-limited" });
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      await stopHarness(h);
    }
  });

  it("a non-JSON content-type is 400 and leaves the store unchanged", async () => {
    const h = await startHarness();
    try {
      writeFileSync(h.storePath, "", "utf8");
      const before = storeBytes(h.storePath);
      const res = await fetch(`${h.service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "text/plain",
          authorization: `Bearer ${h.token}`,
        },
        body: JSON.stringify({ capsule_id: "77".repeat(32) }),
      });
      assert.equal(res.status, 400);
      assert.deepEqual(await res.json(), { error: "bad-content-type" });
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      await stopHarness(h);
    }
  });

  it("a body over the size limit is 413 and leaves the store unchanged", async () => {
    const h = await startHarness();
    try {
      writeFileSync(h.storePath, "", "utf8");
      const before = storeBytes(h.storePath);
      const res = await fetch(`${h.service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${h.token}`,
        },
        body: "x".repeat(4 * 1024 + 1),
      });
      assert.equal(res.status, 413);
      assert.deepEqual(await res.json(), { error: "body-too-large" });
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      await stopHarness(h);
    }
  });

  it("after a body-too-large answer the service closes the socket", { timeout: 5_000 }, async () => {
    const h = await startHarness();
    try {
      const url = new URL(h.service.url);
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("service did not close the socket after body-too-large")),
          3_000,
        );
        const done = (): void => {
          clearTimeout(timer);
          resolve();
        };
        const fail = (err: Error): void => {
          clearTimeout(timer);
          reject(err);
        };
        const req = httpRequest(
          {
            hostname: url.hostname,
            port: url.port,
            path: "/register",
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${h.token}`,
              "content-length": String(4 * 1024 + 1),
            },
          },
          (res) => {
            assert.equal(res.statusCode, 413);
            assert.equal(res.headers.connection, "close");
            const chunks: Buffer[] = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
              assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString("utf8")), {
                error: "body-too-large",
              });
            });
            const socket = res.socket;
            assert.ok(socket);
            // Connection: close alone is not enough; the service must destroy the socket.
            let sawForcedClose = socket.destroyed;
            const onClose = (): void => {
              sawForcedClose = sawForcedClose || socket.destroyed;
              assert.equal(sawForcedClose, true, "expected the service to destroy the socket");
              done();
            };
            if (socket.destroyed) {
              onClose();
              return;
            }
            socket.once("close", onClose);
            socket.once("error", () => onClose());
          },
        );
        req.on("error", fail);
        req.write("x".repeat(4 * 1024 + 1));
        req.end();
      });
    } finally {
      await stopHarness(h);
    }
  });

  it("a slow header is cut by headersTimeout", { timeout: 10_000 }, async () => {
    const h = await startHarness({
      VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS: "200",
      VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS: "2000",
    });
    try {
      const url = new URL(h.service.url);
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("slow header was not cut")), 3_000);
        const socket = netConnect({ host: url.hostname, port: Number(url.port) }, () => {
          socket.write("POST /register HTTP/1.1\r\nHost: 127.0.0.1\r\n");
          // Deliberately never finish the headers.
        });
        socket.on("close", () => {
          clearTimeout(timer);
          resolve();
        });
        socket.on("error", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    } finally {
      await stopHarness(h);
    }
  });

  it("a slow body is cut by requestTimeout", { timeout: 10_000 }, async () => {
    const h = await startHarness({
      VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS: "200",
      VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS: "300",
    });
    try {
      const url = new URL(h.service.url);
      const before = storeBytes(h.storePath);
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("slow body was not cut")), 3_000);
        const done = (): void => {
          clearTimeout(timer);
          resolve();
        };
        const req = httpRequest(
          {
            hostname: url.hostname,
            port: url.port,
            path: "/register",
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${h.token}`,
              "content-length": "50",
            },
          },
          (res) => {
            // Node may answer 408 Request Timeout when requestTimeout fires.
            if (res.statusCode === 408) {
              res.resume();
              done();
              return;
            }
            clearTimeout(timer);
            reject(new Error(`slow body got status ${res.statusCode}`));
          },
        );
        req.on("error", () => done());
        req.write('{"capsule_id":"');
        // Never send the rest; requestTimeout must cut the socket.
      });
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      await stopHarness(h);
    }
  });

  it("maxConnections refuses an extra TCP connection", { timeout: 10_000 }, async () => {
    const h = await startHarness({
      VERAX_ANCHOR_SVC_MAX_CONNECTIONS: "2",
      VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS: "5000",
      VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS: "5000",
    });
    const sockets: Socket[] = [];
    try {
      const url = new URL(h.service.url);
      const openOne = (): Promise<Socket> =>
        new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("connect timed out")), 2_000);
          const s = netConnect({ host: url.hostname, port: Number(url.port) }, () => {
            clearTimeout(timer);
            resolve(s);
          });
          s.on("error", (err) => {
            clearTimeout(timer);
            reject(err);
          });
        });
      sockets.push(await openOne());
      sockets.push(await openOne());
      const thirdRefused = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), 1_000);
        const s = netConnect({ host: url.hostname, port: Number(url.port) });
        sockets.push(s);
        s.on("error", () => {
          clearTimeout(timer);
          resolve(true);
        });
        s.on("close", () => {
          clearTimeout(timer);
          resolve(true);
        });
        // If the OS accepts the socket, Node should still drop it when over max.
        s.on("data", () => {
          clearTimeout(timer);
          resolve(false);
        });
      });
      assert.equal(thirdRefused, true, "expected the third connection to be refused or closed");
    } finally {
      for (const s of sockets) {
        try {
          s.destroy();
        } catch {
          /* */
        }
      }
      await stopHarness(h);
    }
  });

  it("a service receipt carries a signing time that verifyReceipt reports", async () => {
    const h = await startHarness();
    try {
      const beforeSec = Math.floor(Date.now() / 1000);
      const got = await registerCheckpoint(h.service.url, "cc".repeat(32), h.publicKeyPem, fetch, Date.now, h.token);
      const afterSec = Math.floor(Date.now() / 1000);
      assert.equal(got.ok, true);
      if (!got.ok || got.row.v !== 1) return;
      const check = verifyReceipt(
        Buffer.from(got.row.receiptB64, "base64"),
        Buffer.from(got.row.entryHash, "hex"),
        h.publicKeyPem,
      );
      assert.equal(check.ok, true, check.ok ? "" : check.reason);
      if (!check.ok) return;
      assert.equal(typeof check.issuedAtSec, "number");
      assert.ok(check.issuedAtSec! >= beforeSec && check.issuedAtSec! <= afterSec);
    } finally {
      await stopHarness(h);
    }
  });

  it("changing the signing time in the protected bytes fails the signature check", async () => {
    const h = await startHarness();
    try {
      const got = await registerCheckpoint(h.service.url, "dd".repeat(32), h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(got.ok, true);
      if (!got.ok || got.row.v !== 1) return;
      const sign1 = decodeSign1(Buffer.from(got.row.receiptB64, "base64"));
      const hdr = new Map(sign1.protectedHeader);
      const cwt = new Map(hdr.get(15) as Map<unknown, unknown>);
      cwt.set(6, (cwt.get(6) as number) + 60);
      hdr.set(15, cwt);
      const protectedBytes = encodeCbor(hdr);
      const tampered = encodeCbor(
        new CborTag(18, [protectedBytes, sign1.unprotected, null, new Uint8Array(sign1.signature)]),
      );
      const check = verifyReceipt(tampered, Buffer.from(got.row.entryHash, "hex"), h.publicKeyPem);
      assert.equal(check.ok, false);
      assert.equal(check.ok ? null : check.stage, "receipt-sig");
    } finally {
      await stopHarness(h);
    }
  });

  it("a second start on the same store is refused while the first runs, and works after close", async () => {
    const h = await startHarness();
    let closed = false;
    try {
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: join(h.dir, "tokens.json"),
        VERAX_ANCHOR_SVC_SIGNING_KEY: join(h.dir, "signing.private.pem"),
        VERAX_ANCHOR_SVC_STORE: h.storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assert.rejects(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, `store already locked: ${h.storePath}`);
          return true;
        },
      );
      await h.service.close();
      closed = true;
      const again = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
      await again.close();
    } finally {
      if (!closed) await h.service.close();
      rmSync(h.dir, { recursive: true, force: true });
    }
  });

  it("a second process is refused while another holds the store lock, and takes over after a hard kill", { timeout: 15_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-xproc-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    writeFileSync(storePath, "", "utf8");
    const holderScript = join(root, "tests", "anchor-service-lock-holder.ts");
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", holderScript],
      {
        env: {
          ...process.env,
          VERAX_ANCHOR_SVC_TOKENS: tokensFile,
          VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
          VERAX_ANCHOR_SVC_STORE: storePath,
          VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
          VERAX_ANCHOR_SVC_PORT: "0",
          VERAX_ANCHOR_SVC_LOCK_BEAT_MS: String(TEST_LOCK_BEAT_MS),
        },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );
    let stderr = "";
    child.stderr?.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`lock holder did not become ready: ${stderr}`)), 10_000);
        let buffered = "";
        const onData = (buf: Buffer): void => {
          buffered += String(buf);
          if (buffered.includes("\n") && buffered.startsWith("ready ")) {
            cleanup();
            resolve();
          }
        };
        const onError = (err: Error): void => {
          cleanup();
          reject(err);
        };
        const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
          cleanup();
          reject(new Error(`lock holder exited early code=${code} signal=${signal}: ${stderr}`));
        };
        const cleanup = (): void => {
          clearTimeout(timer);
          child.stdout?.off("data", onData);
          child.off("error", onError);
          child.off("exit", onExit);
        };
        child.stdout?.on("data", onData);
        child.once("error", onError);
        child.once("exit", onExit);
      });

      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      let stolen: RunningService | null = null;
      try {
        stolen = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
        assert.fail(`expected store already locked: ${storePath}`);
      } catch (err) {
        if (stolen !== null) throw err;
        assert.ok(err instanceof Error);
        assert.equal(err.message, `store already locked: ${storePath}`);
      } finally {
        if (stolen !== null) await stolen.close();
      }

      await new Promise<void>((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolve();
          return;
        }
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      });

      const again = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
      await again.close();
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise<void>((resolve) => {
          child.once("exit", () => resolve());
          child.kill("SIGKILL");
        });
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a stale lock from a dead process is taken over", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-stale-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
      writeFileSync(storePath, "", "utf8");
      writeStaleStoreLock(storePath, {
        pid: 2_147_483_646,
        startedAt: Date.now() - 60_000,
        token: "dead-holder",
      });
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
      await service.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("deleting the lock under a live holder makes the next authenticated register 503", { timeout: 20_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-lockdel-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    writeFileSync(storePath, "", "utf8");
    const holderScript = join(root, "tests", "anchor-service-lock-holder.ts");
    const child = spawn(process.execPath, ["--experimental-strip-types", holderScript], {
      env: {
        ...process.env,
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
        VERAX_ANCHOR_SVC_LOCK_BEAT_MS: String(TEST_LOCK_BEAT_MS),
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    child.stderr?.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    let url = "";
    try {
      url = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`lock holder did not become ready: ${stderr}`)), 10_000);
        let buffered = "";
        child.stdout?.on("data", (buf: Buffer) => {
          buffered += String(buf);
          const m = /^ready (http:\/\/\S+)/m.exec(buffered);
          if (m) {
            clearTimeout(timer);
            resolve(m[1]!);
          }
        });
        child.on("exit", (code, signal) => {
          clearTimeout(timer);
          reject(new Error(`lock holder exited early code=${code} signal=${signal}: ${stderr}`));
        });
      });

      const before = storeBytes(storePath);
      rmSync(storeLockPath(storePath), { recursive: true, force: true });
      await new Promise((r) => setTimeout(r, TEST_LOCK_BEAT_MS * 3));

      const res = await fetch(`${url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "ab".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.ok(storeBytes(storePath).equals(before));
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise<void>((resolve) => {
          child.once("exit", () => resolve());
          child.kill("SIGKILL");
        });
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("replacing the lock token under a live holder makes the next authenticated register 503", { timeout: 20_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-lockswap-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    writeFileSync(storePath, "", "utf8");
    const holderScript = join(root, "tests", "anchor-service-lock-holder.ts");
    const child = spawn(process.execPath, ["--experimental-strip-types", holderScript], {
      env: {
        ...process.env,
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
        VERAX_ANCHOR_SVC_LOCK_BEAT_MS: String(TEST_LOCK_BEAT_MS),
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    child.stderr?.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    let url = "";
    try {
      url = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`lock holder did not become ready: ${stderr}`)), 10_000);
        let buffered = "";
        child.stdout?.on("data", (buf: Buffer) => {
          buffered += String(buf);
          const m = /^ready (http:\/\/\S+)/m.exec(buffered);
          if (m) {
            clearTimeout(timer);
            resolve(m[1]!);
          }
        });
        child.on("exit", (code, signal) => {
          clearTimeout(timer);
          reject(new Error(`lock holder exited early code=${code} signal=${signal}: ${stderr}`));
        });
      });

      const before = storeBytes(storePath);
      const lockPath = storeLockPath(storePath);
      writeFileSync(
        join(lockPath, "holder"),
        `${JSON.stringify({ pid: 2_147_483_646, startedAt: Date.now(), token: "other-holder", beatMs: TEST_LOCK_BEAT_MS })}\n`,
        "utf8",
      );
      await new Promise((r) => setTimeout(r, TEST_LOCK_BEAT_MS * 3));

      const res = await fetch(`${url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "ac".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.ok(storeBytes(storePath).equals(before));
      const onDisk = JSON.parse(readFileSync(join(lockPath, "holder"), "utf8")) as { token?: string };
      assert.equal(onDisk.token, "other-holder");
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise<void>((resolve) => {
          child.once("exit", () => resolve());
          child.kill("SIGKILL");
        });
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("exactly one of many processes takes over one stale lock", { timeout: 60_000 }, async () => {
    const raceScript = join(root, "tests", "anchor-service-lock-race.ts");
    const contenders = 6;
    const rounds = 20;
    for (let round = 0; round < rounds; round += 1) {
      const dir = mkdtempSync(join(tmpdir(), "verax-asvc-race-"));
      const storePath = join(dir, "store.jsonl");
      writeFileSync(storePath, "", "utf8");
      writeStaleStoreLock(storePath, {
        pid: 2_147_483_646,
        startedAt: Date.now() - 60_000,
        token: "stale-race-token",
      });
      const children: ReturnType<typeof spawn>[] = [];
      try {
        const results = await Promise.all(
          Array.from({ length: contenders }, () => {
            const child = spawn(process.execPath, ["--experimental-strip-types", raceScript], {
              env: {
                ...process.env,
                VERAX_ANCHOR_SVC_STORE: storePath,
                VERAX_ANCHOR_SVC_LOCK_BEAT_MS: String(TEST_LOCK_BEAT_MS),
              },
              stdio: ["ignore", "pipe", "pipe"],
              windowsHide: true,
            });
            children.push(child);
            return new Promise<string>((resolve, reject) => {
              const timer = setTimeout(() => {
                reject(new Error(`lock race contender timed out round=${round} stderr=${err} stdout=${out}`));
              }, 10_000);
              let out = "";
              let err = "";
              let settled = false;
              const finish = (line: string): void => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                resolve(line);
              };
              child.stdout?.on("data", (buf: Buffer) => {
                out += String(buf);
                if (/(^|\n)held\r?\n/.test(out) || out === "held\r\n" || out.startsWith("held\n") || out.startsWith("held\r\n")) {
                  finish("held");
                } else if (/(^|\n)refused\r?\n/.test(out) || out.startsWith("refused\n") || out.startsWith("refused\r\n")) {
                  finish("refused");
                }
              });
              child.stderr?.on("data", (buf: Buffer) => {
                err += String(buf);
              });
              child.on("error", (e) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                reject(e);
              });
              child.on("exit", (code) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                reject(new Error(`lock race contender exit=${code} stderr=${err} stdout=${out}`));
              });
            });
          }),
        );
        const held = results.filter((r) => r === "held").length;
        const refused = results.filter((r) => r === "refused").length;
        assert.equal(
          held,
          1,
          `round ${round}: expected exactly one holder, got held=${held} refused=${refused} results=${results.join(",")}`,
        );
        assert.equal(refused, contenders - 1);
      } finally {
        for (const child of children) {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGKILL");
          }
        }
        await Promise.all(
          children.map(
            (child) =>
              new Promise<void>((resolve) => {
                if (child.exitCode !== null || child.signalCode !== null) {
                  resolve();
                  return;
                }
                child.once("exit", () => resolve());
                child.kill("SIGKILL");
              }),
          ),
        );
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it("two instances cannot fork the same store into separate trees", async () => {
    const h = await startHarness();
    try {
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: join(h.dir, "tokens.json"),
        VERAX_ANCHOR_SVC_SIGNING_KEY: join(h.dir, "signing.private.pem"),
        VERAX_ANCHOR_SVC_STORE: h.storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assert.rejects(() => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }), /store already locked/);
      const first = await registerCheckpoint(h.service.url, "aa".repeat(32), h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      if (!first.ok || first.row.v !== 1) return;
      assert.equal(first.row.leafIndex, 0);
      assert.equal(first.row.treeSize, 1);
      const lines = readFileSync(h.storePath, "utf8").split("\n").filter((l) => l.trim() !== "");
      assert.equal(lines.length, 1);
    } finally {
      await stopHarness(h);
    }
  });

  it("without a known token, register is 401 even when the store is unavailable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-auth-first-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    let failNext = false;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, row) => {
        if (failNext) throw new Error("store-write-failed");
        appendStore(path, row);
      },
    });
    try {
      failNext = true;
      const trip = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(trip.status, 500);

      const none = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(none.status, 401);
      assert.deepEqual(await none.json(), { error: "unauthorized" });

      const wrong = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer wrong-token-also-20chars!!",
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(wrong.status, 401);
      assert.deepEqual(await wrong.json(), { error: "unauthorized" });
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a known token still gets 503 when the store is unavailable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-503-after-auth-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    let failNext = false;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, row) => {
        if (failNext) throw new Error("store-write-failed");
        appendStore(path, row);
      },
    });
    try {
      failNext = true;
      const trip = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(trip.status, 500);

      const later = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(later.status, 503);
      assert.deepEqual(await later.json(), { error: "store-unavailable" });
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a failed store write answers 500 then 503, and keeps prior receipts valid", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-fail-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privatePem, "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    let failNext = false;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, row) => {
        if (failNext) throw new Error("store-write-failed");
        appendStore(path, row);
      },
    });
    try {
      const prior = await registerCheckpoint(service.url, "aa".repeat(32), publicKeyPem, fetch, Date.now, TOKEN);
      assert.equal(prior.ok, true);
      if (!prior.ok || prior.row.v !== 1) return;
      const priorReceipt = prior.row.receiptB64;
      const priorEntry = prior.row.entryHash;

      failNext = true;
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(res.status, 500);
      assert.deepEqual(await res.json(), { error: "internal" });

      failNext = false;
      const later = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(later.status, 503);
      assert.deepEqual(await later.json(), { error: "store-unavailable" });
      assert.equal(service.log.size, 1);

      const check = verifyReceipt(Buffer.from(priorReceipt, "base64"), Buffer.from(priorEntry, "hex"), publicKeyPem);
      assert.equal(check.ok, true, check.ok ? "" : check.reason);
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a partial store append that throws leaves the service answering 503 afterwards", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-partial-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privatePem, "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, row) => {
        const fd = openSync(path, "a");
        try {
          writeSync(fd, '{"leaf', null, "utf8");
        } finally {
          closeSync(fd);
        }
        throw new Error("store-write-partial");
      },
    });
    try {
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "ee".repeat(32) }),
      });
      assert.equal(res.status, 500);
      const later = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "ff".repeat(32) }),
      });
      assert.equal(later.status, 503);
      assert.deepEqual(await later.json(), { error: "store-unavailable" });
      assert.equal(publicKeyPem.length > 0, true);
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a store ending in a partial line starts, drops it, and the next leaf index is the full-line count", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-torn-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privatePem, "utf8");
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
    const full = JSON.stringify({
      leaf_hash: "11".repeat(32),
      owner_id: "owner-a",
      at_ms: 1,
    });
    writeFileSync(storePath, `${full}\n{"leaf`, "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      assert.equal(service.log.size, 1);
      assert.equal(readFileSync(storePath, "utf8"), `${full}\n`);
      const next = await registerCheckpoint(service.url, "22".repeat(32), publicKeyPem, fetch, Date.now, TOKEN);
      assert.equal(next.ok, true);
      if (!next.ok || next.row.v !== 1) return;
      assert.equal(next.row.leafIndex, 1);
      assert.equal(next.row.treeSize, 2);
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a store with a bad line in the middle still refuses to start", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-mid-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "utf8");
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), "utf8");
      const good = JSON.stringify({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 });
      writeFileSync(storePath, `${good}\nnot-json\n${good}\n`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assert.rejects(() => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }), /store line 2/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
