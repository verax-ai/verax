import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
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
  openStore,
  startService,
  type RunningService,
} from "../packages/anchor-service/src/index.ts";
import { loadTokenMap } from "../packages/anchor-service/src/auth.ts";
import { assertSecretFile } from "../packages/anchor-service/src/secret-file.ts";
import { assertStorePath } from "../packages/anchor-service/src/store.ts";
import {
  acquireStoreLock,
  storeLockPath,
  storeTakeoverGatePath,
} from "../packages/anchor-service/src/store-lock.ts";
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

function writeSecretFile(path: string, contents: string): void {
  writeFileSync(path, contents, { encoding: "utf8", mode: 0o600 });
}

/** One v1 store line with the correct prev chain for a single-line store. */
function v1StoreLine(row: { leaf_hash: string; owner_id: string; at_ms: number }, index = 0, prev = "0".repeat(64)): string {
  return `${JSON.stringify({
    v: 1,
    index,
    prev,
    leaf_hash: row.leaf_hash,
    owner_id: row.owner_id,
    at_ms: row.at_ms,
  })}\n`;
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

async function startHarness(
  env: NodeJS.ProcessEnv = {},
  serviceOpts?: {
    bodyTimeoutMs?: number;
    connectionIdleTimeoutMs?: number;
    afterAuthBeforeBody?: () => void | Promise<void>;
  },
): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "verax-asvc-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyFile = join(dir, "signing.private.pem");
  const pubFile = join(dir, "signing.public.pem");
  const tokensFile = join(dir, "tokens.json");
  const storePath = join(dir, "store.jsonl");
  const tokenFile = join(dir, "token.txt");
  writeFileSync(keyFile, privatePem, { encoding: "utf8", mode: 0o600 });
  writeFileSync(pubFile, publicKeyPem, "utf8");
  writeFileSync(tokenFile, `${TOKEN}\n`, "utf8");
  const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
  writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), { encoding: "utf8", mode: 0o600 });
  const config = loadConfig({
    VERAX_ANCHOR_SVC_TOKENS: tokensFile,
    VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
    VERAX_ANCHOR_SVC_STORE: storePath,
    VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
    VERAX_ANCHOR_SVC_PORT: "0",
    ...env,
  });
  const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS, ...serviceOpts });
  return { dir, service, tokenFile, keyFile: pubFile, storePath, publicKeyPem, token: TOKEN };
}

async function stopHarness(h: Harness): Promise<void> {
  await h.service.close();
  rmSync(h.dir, { recursive: true, force: true });
}

/**
 * startService must refuse. If a protection is mutated away and start succeeds,
 * close the service before failing — otherwise the lock beat keeps the process alive.
 */
async function assertStartRefused(
  start: () => Promise<RunningService>,
  expect: RegExp | ((err: Error) => boolean),
): Promise<void> {
  let service: RunningService | null = null;
  try {
    service = await start();
  } catch (err) {
    const e = err instanceof Error ? err : new Error(String(err));
    if (expect instanceof RegExp) {
      assert.match(e.message, expect);
    } else {
      assert.equal(expect(e), true);
    }
    return;
  }
  try {
    await service.close();
  } catch {
    /* */
  }
  assert.fail(
    expect instanceof RegExp
      ? `expected startService to refuse matching ${expect}`
      : "expected startService to refuse",
  );
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
    let firstClosed = false;
    try {
      const a = "33".repeat(32);
      const first = await registerCheckpoint(h.service.url, a, h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      if (!first.ok || first.row.v !== 1) return;
      const receiptB64 = first.row.receiptB64;
      const entryHash = first.row.entryHash;
      await h.service.close();
      firstClosed = true;
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
      if (!firstClosed) {
        try {
          await h.service.close();
        } catch {
          /* */
        }
      }
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
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      writeFileSync(storePath, "not-json\n", "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(() => startService(config), /store line 1/);
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

  it("a slow header is cut by the connection socket timer", { timeout: 10_000 }, async () => {
    // Node headersTimeout stays far above CUT_MS so a "Request timeout" race
    // cannot satisfy this test. Only connectionIdleTimeoutMs → socket.setTimeout
    // can cut within CUT_MS.
    const CUT_MS = 1_000;
    const h = await startHarness(
      {
        VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS: "5000",
        VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS: "5000",
      },
      { connectionIdleTimeoutMs: 200 },
    );
    try {
      const url = new URL(h.service.url);
      await new Promise<void>((resolve, reject) => {
        const t0 = Date.now();
        let settled = false;
        let socket: Socket;
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          socket?.destroy();
          reject(new Error("slow header was not cut"));
        }, CUT_MS + 500);
        socket = netConnect({ host: url.hostname, port: Number(url.port) }, () => {
          socket.write("POST /register HTTP/1.1\r\nHost: 127.0.0.1\r\n");
          // Deliberately never finish the headers.
        });
        const done = (): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const elapsed = Date.now() - t0;
          if (elapsed > CUT_MS) {
            reject(new Error(`slow header cut too late (${elapsed}ms > ${CUT_MS}ms)`));
            return;
          }
          resolve();
        };
        socket.on("close", done);
        socket.on("error", done);
      });
    } finally {
      await stopHarness(h);
    }
  });

  it("a slow body is answered 408 by the body read timer", { timeout: 10_000 }, async () => {
    // Idle timer and Node requestTimeout stay far above the body timer so a
    // hang-up cannot race the JSON 408. Only the body-timeout reject yields it.
    const h = await startHarness(
      {
        VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS: "2000",
        VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS: "2000",
      },
      { bodyTimeoutMs: 300 },
    );
    try {
      const url = new URL(h.service.url);
      const before = storeBytes(h.storePath);
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("slow body was not cut")), 3_000);
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
            const chunks: Buffer[] = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
              clearTimeout(timer);
              try {
                assert.equal(res.statusCode, 408);
                assert.equal(res.headers["content-type"], "application/json");
                assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString("utf8")), {
                  error: "request-timeout",
                });
                resolve();
              } catch (err) {
                reject(err);
              }
            });
          },
        );
        req.on("error", (err) => {
          clearTimeout(timer);
          reject(err);
        });
        req.write('{"capsule_id":"');
        // Never send the rest; the body read timer must answer 408.
      });
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      await stopHarness(h);
    }
  });

  it("a request that stalls before the body is cut by requestTimeout", { timeout: 20_000 }, async () => {
    // On mutated runs without requestTimeout, the body timer's sendAndClose could
    // race the JSON 408 and look like a hang-up inside a loose 3s window. Keep the
    // connection idle timer (trickle) and the body timer (bodyTimeoutMs) several
    // times above CUT_MS. Assert a cut within CUT_MS — only requestTimeout can meet
    // that — and the opposite with a large requestTimeout: still connected after
    // CUT_MS. headersTimeout must stay set for requestTimeout to take effect under
    // Node's connections checker (pair: headersTimeout + requestTimeout).
    const CUT_MS = 1_200;
    // headersTimeout stays short so Node's connections checker can honour a short
    // requestTimeout; connection idle is widened separately so a scheduling pause
    // cannot fire the socket timer before the mechanism under test.
    const HEADERS_MS = 400;
    const SHORT_REQUEST_MS = 400;
    const LARGE_REQUEST_MS = 5_000;
    const BODY_TIMEOUT_MS = 5_000;
    const CONNECTION_IDLE_MS = 5_000;
    const TRICKLE_EVERY_MS = 40;
    const TRICKLE_COUNT = 80;

    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeFileSync(keyFile, privatePem, { encoding: "utf8", mode: 0o600 });
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeFileSync(tokensFile, JSON.stringify({ [digest]: "owner-a" }), { encoding: "utf8", mode: 0o600 });

    const startStallService = async (requestTimeoutMs: number) => {
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
        VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS: String(HEADERS_MS),
        VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS: String(requestTimeoutMs),
      });
      return startService(config, {
        lockBeatMs: TEST_LOCK_BEAT_MS,
        bodyTimeoutMs: BODY_TIMEOUT_MS,
        connectionIdleTimeoutMs: CONNECTION_IDLE_MS,
      });
    };

    const openStallClient = (
      serviceUrl: string,
      onCut: (info: { kind: "hangup" | "status"; status?: number; body?: string; elapsedMs: number }) => void,
    ): { req: ReturnType<typeof httpRequest>; stopTrickle: () => void } => {
      const url = new URL(serviceUrl);
      const t0 = Date.now();
      let settled = false;
      const finish = (info: { kind: "hangup" | "status"; status?: number; body?: string }): void => {
        if (settled) return;
        settled = true;
        onCut({ ...info, elapsedMs: Date.now() - t0 });
      };
      const req = httpRequest(
        {
          hostname: url.hostname,
          port: url.port,
          path: "/register",
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${TOKEN}`,
            "content-length": "50",
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            finish({
              kind: "status",
              status: res.statusCode,
              body: Buffer.concat(chunks).toString("utf8"),
            });
          });
        },
      );
      req.on("error", () => {
        finish({ kind: "hangup" });
      });
      let n = 0;
      let trickleTimer: ReturnType<typeof setTimeout> | undefined;
      const tick = (): void => {
        if (n >= TRICKLE_COUNT || settled) return;
        req.write("x");
        n += 1;
        trickleTimer = setTimeout(tick, TRICKLE_EVERY_MS);
      };
      tick();
      return {
        req,
        stopTrickle: () => {
          if (trickleTimer !== undefined) clearTimeout(trickleTimer);
        },
      };
    };

    let service = await startStallService(SHORT_REQUEST_MS);
    try {
      const before = storeBytes(storePath);
      await new Promise<void>((resolve, reject) => {
        let client: { req: ReturnType<typeof httpRequest>; stopTrickle: () => void };
        const watchdog = setTimeout(() => {
          client.stopTrickle();
          client.req.destroy();
          reject(new Error("stalled request was not cut"));
        }, CUT_MS + 500);
        client = openStallClient(service.url, (info) => {
          clearTimeout(watchdog);
          client.stopTrickle();
          try {
            if (info.kind === "status" && info.status === 408 && (info.body ?? "").includes("request-timeout")) {
              throw new Error("stalled request was cut by the body read timer, not requestTimeout");
            }
            if (info.elapsedMs > CUT_MS) {
              throw new Error(`stalled request cut too late (${info.elapsedMs}ms > ${CUT_MS}ms)`);
            }
            if (info.kind === "hangup" || info.status === 408) {
              resolve();
              return;
            }
            throw new Error(`stalled request got status ${info.status}`);
          } catch (err) {
            reject(err);
          }
        });
      });
      assert.ok(storeBytes(storePath).equals(before));
    } finally {
      await service.close();
    }

    // Opposite: same idle / body-delay setup, large requestTimeout — still up after CUT_MS.
    writeFileSync(storePath, "", "utf8");
    service = await startStallService(LARGE_REQUEST_MS);
    try {
      await new Promise<void>((resolve, reject) => {
        let cutEarly: { elapsedMs: number; kind: string } | undefined;
        const client = openStallClient(service.url, (info) => {
          cutEarly = { elapsedMs: info.elapsedMs, kind: info.kind };
        });
        setTimeout(() => {
          client.stopTrickle();
          try {
            if (cutEarly !== undefined && cutEarly.elapsedMs <= CUT_MS) {
              throw new Error(
                `request was cut at ${cutEarly.elapsedMs}ms with large requestTimeout (${cutEarly.kind})`,
              );
            }
            assert.equal(client.req.destroyed, false);
            const sock = client.req.socket;
            assert.ok(sock);
            assert.equal(sock.destroyed, false);
            client.req.destroy();
            resolve();
          } catch (err) {
            client.req.destroy();
            reject(err);
          }
        }, CUT_MS);
      });
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
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
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        (err) => {
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
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
      try {
        assert.equal(service.log.size, 0);
      } finally {
        await service.close();
      }
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
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
      await assertStartRefused(() => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }), /store already locked/);
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
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
    writeSecretFile(keyFile, privatePem);
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
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
    writeSecretFile(keyFile, privatePem);
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const partial = '{"leaf';
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, _row) => {
        const fd = openSync(path, "a");
        try {
          writeSync(fd, partial, null, "utf8");
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
      assert.equal(readFileSync(storePath, "utf8"), partial);
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
    } finally {
      await service.close();
    }
    // Restart drops the torn partial and the next leaf is index 0.
    const again = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      assert.equal(readFileSync(storePath, "utf8"), "");
      assert.equal(again.log.size, 0);
      const next = await registerCheckpoint(again.url, "ff".repeat(32), publicKeyPem, fetch, Date.now, TOKEN);
      assert.equal(next.ok, true);
      if (!next.ok || next.row.v !== 1) return;
      assert.equal(next.row.leafIndex, 0);
    } finally {
      await again.close();
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
    writeSecretFile(keyFile, privatePem);
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const full = v1StoreLine({
      leaf_hash: "11".repeat(32),
      owner_id: "owner-a",
      at_ms: 1,
    }).trimEnd();
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

  it("a failed torn-tail recovery leaves the complete rows on disk and refuses to start", { timeout: 10_000 }, () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-torn-fail-"));
    try {
      const storePath = join(dir, "store.jsonl");
      const full = v1StoreLine({
        leaf_hash: "11".repeat(32),
        owner_id: "owner-a",
        at_ms: 1,
      });
      const complete = full.trimEnd();
      const original = `${complete}\n{"leaf`;
      const steps = ["write-tmp", "fsync-tmp", "rename", "fsync-dir"] as const;
      for (const failAt of steps) {
        writeFileSync(storePath, original, "utf8");
        assert.throws(
          () =>
            openStore(storePath, {
              recoveryOps: {
                failAt,
              },
            }),
          /torn-tail recovery failed/,
        );
        const after = readFileSync(storePath, "utf8");
        assert.ok(after.includes(complete), `failAt=${failAt}: complete row missing`);
        assert.notEqual(after, "", `failAt=${failAt}: store must not be empty`);
        // Before rename the torn original remains; after rename the kept prefix is
        // already durable. Either way a clean start keeps the acknowledged row.
        const opened = openStore(storePath);
        try {
          assert.equal(opened.log.size, 1);
          assert.equal(readFileSync(storePath, "utf8"), full);
        } finally {
          opened.close();
        }
      }
    } finally {
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
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const good = v1StoreLine({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 }).trimEnd();
      writeFileSync(storePath, `${good}\nnot-json\n${good}\n`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(() => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }), /store line 2/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a blank store line that is not a torn tail refuses to start", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-blank-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const good = v1StoreLine({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 });
      writeFileSync(storePath, `${good}\n${good}`, "utf8");
      // Insert a blank line between two newlines: good\n\ngood\n
      writeFileSync(storePath, `${good.trimEnd()}\n\n${good}`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(() => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }), /blank/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a repeated owner_id and leaf_hash refuses to start", { timeout: 5_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-dup-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const row = { leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 };
      const first = v1StoreLine(row);
      const prev = createHash("sha256").update(first, "utf8").digest("hex");
      const second = v1StoreLine({ ...row, at_ms: 2 }, 1, prev);
      writeFileSync(storePath, `${first}${second}`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        /repeats an \(owner_id, leaf_hash\)/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an old unversioned store format is refused with a clear sentence", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-oldfmt-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      writeFileSync(
        storePath,
        `${JSON.stringify({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 })}\n`,
        "utf8",
      );
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        /old format without line index and prev hash/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a store path that is a directory is refused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-storepath-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));

      const asDir = join(dir, "store-dir");
      mkdirSync(asDir);
      await assertStartRefused(
        () =>
          startService(
            loadConfig({
              VERAX_ANCHOR_SVC_TOKENS: tokensFile,
              VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
              VERAX_ANCHOR_SVC_STORE: asDir,
              VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
              VERAX_ANCHOR_SVC_PORT: "0",
            }),
            { lockBeatMs: TEST_LOCK_BEAT_MS },
          ),
        /regular file/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a real store symlink is refused when the platform can create one", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-storesym-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const target = join(dir, "real-store.jsonl");
      writeFileSync(target, "", "utf8");
      const link = join(dir, "store-link.jsonl");
      try {
        symlinkSync(target, link);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EPERM") {
          t.skip("platform cannot create a symlink without elevation (EPERM)");
          return;
        }
        throw err;
      }
      await assertStartRefused(
        () =>
          startService(
            loadConfig({
              VERAX_ANCHOR_SVC_TOKENS: tokensFile,
              VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
              VERAX_ANCHOR_SVC_STORE: link,
              VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
              VERAX_ANCHOR_SVC_PORT: "0",
            }),
            { lockBeatMs: TEST_LOCK_BEAT_MS },
          ),
        /symbolic link/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a symlink swapped in after start answers 503 and does not append", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-swap-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    const decoy = join(dir, "decoy.jsonl");
    writeSecretFile(keyFile, privatePem);
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    writeFileSync(storePath, "", "utf8");
    writeFileSync(decoy, "", "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      try {
        rmSync(storePath);
        symlinkSync(decoy, storePath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EPERM") {
          t.skip("platform cannot create a symlink without elevation (EPERM)");
          return;
        }
        throw err;
      }
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.equal(readFileSync(decoy, "utf8"), "");
      const later = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(later.status, 503);
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a store path replaced by another regular file answers 503 with no receipt", { timeout: 10_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-replaced-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    writeFileSync(storePath, "", "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      rmSync(storePath);
      writeFileSync(storePath, '{"other":true}\n', "utf8");
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.equal(readFileSync(storePath, "utf8"), '{"other":true}\n');
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a removed store path answers 503 with no receipt", { timeout: 10_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-removed-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    writeFileSync(storePath, "", "utf8");
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const service = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      rmSync(storePath);
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.equal(existsSync(storePath), false);
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a group-readable signing key is refused on POSIX", async (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX chmod mode bits are not enforced on win32");
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-keymode-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      chmodSync(keyFile, 0o640);
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      assert.throws(
        () =>
          loadConfig({
            VERAX_ANCHOR_SVC_TOKENS: tokensFile,
            VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
            VERAX_ANCHOR_SVC_STORE: storePath,
            VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
            VERAX_ANCHOR_SVC_PORT: "0",
          }),
        /signing key must not be readable or writable by group or others/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("assertSecretFile refuses symlink, directory, and weak modes with fakes on every platform", () => {
    const fake = (kind: "symlink" | "dir" | "fifo" | "file", mode: number) => ({
      mode,
      isSymbolicLink: () => kind === "symlink",
      isFile: () => kind === "file",
    });
    assert.throws(
      () => assertSecretFile("/x", "signing key", { lstat: () => fake("symlink", 0o600), platform: "linux" }),
      /signing key must not be a symbolic link/,
    );
    assert.throws(
      () => assertSecretFile("/x", "signing key", { lstat: () => fake("dir", 0o600), platform: "linux" }),
      /signing key must be a regular file/,
    );
    assert.throws(
      () => assertSecretFile("/x", "token map", { lstat: () => fake("fifo", 0o600), platform: "linux" }),
      /token map must be a regular file/,
    );
    for (const mode of [0o640, 0o604, 0o660]) {
      assert.throws(
        () => assertSecretFile("/x", "signing key", { lstat: () => fake("file", mode), platform: "linux" }),
        /signing key must not be readable or writable by group or others/,
      );
    }
    assert.doesNotThrow(() =>
      assertSecretFile("/x", "signing key", { lstat: () => fake("file", 0o600), platform: "linux" }),
    );
    assert.doesNotThrow(() =>
      assertSecretFile("/x", "signing key", { lstat: () => fake("file", 0o640), platform: "win32" }),
    );
  });

  it("loadConfig refuses a signing key that assertSecretFile would reject", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-cfg-secret-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      assert.throws(
        () =>
          loadConfig(
            {
              VERAX_ANCHOR_SVC_TOKENS: tokensFile,
              VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
              VERAX_ANCHOR_SVC_STORE: join(dir, "store.jsonl"),
              VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
              VERAX_ANCHOR_SVC_PORT: "0",
            },
            {
              secretFile: {
                platform: "linux",
                lstat: (p) => {
                  if (p === keyFile) {
                    return {
                      mode: 0o600,
                      isSymbolicLink: () => true,
                      isFile: () => false,
                    };
                  }
                  return {
                    mode: 0o600,
                    isSymbolicLink: () => false,
                    isFile: () => true,
                  };
                },
              },
            },
          ),
        /signing key must not be a symbolic link/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadTokenMap refuses a token map that assertSecretFile would reject", () => {
    assert.throws(
      () =>
        loadTokenMap("/token-map.json", {
          platform: "linux",
          lstat: () => ({
            mode: 0o600,
            isSymbolicLink: () => false,
            isFile: () => false,
          }),
        }),
      /token map must be a regular file/,
    );
  });

  it("assertStorePath refuses symlink, directory, and fifo via an injected lstat", () => {
    assert.throws(
      () => assertStorePath("/store", () => ({ isSymbolicLink: () => true, isFile: () => false })),
      /symbolic link/,
    );
    assert.throws(
      () => assertStorePath("/store", () => ({ isSymbolicLink: () => false, isFile: () => false })),
      /regular file/,
    );
    assert.doesNotThrow(() =>
      assertStorePath("/store", () => ({ isSymbolicLink: () => false, isFile: () => true })),
    );
  });

  it("a store with a wrong index but a matching prev chain refuses to start", { timeout: 5_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-badindex-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const first = v1StoreLine({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 }, 0);
      const prev = createHash("sha256").update(first, "utf8").digest("hex");
      const second = v1StoreLine({ leaf_hash: "22".repeat(32), owner_id: "owner-a", at_ms: 2 }, 99, prev);
      writeFileSync(storePath, `${first}${second}`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        /index 99, expected 1/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a store with a broken prev after an altered earlier line refuses to start", { timeout: 5_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-badprev-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const first = v1StoreLine({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 }, 0);
      const prev = createHash("sha256").update(first, "utf8").digest("hex");
      const second = v1StoreLine({ leaf_hash: "22".repeat(32), owner_id: "owner-a", at_ms: 2 }, 1, prev);
      const alteredFirst = v1StoreLine({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 9 }, 0);
      writeFileSync(storePath, `${alteredFirst}${second}`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        /breaks the prev-hash chain/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a store with a removed middle line and renumbered indexes refuses on prev", { timeout: 5_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-gap-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      const first = v1StoreLine({ leaf_hash: "11".repeat(32), owner_id: "owner-a", at_ms: 1 }, 0);
      const prevFirst = createHash("sha256").update(first, "utf8").digest("hex");
      const middle = v1StoreLine({ leaf_hash: "22".repeat(32), owner_id: "owner-a", at_ms: 2 }, 1, prevFirst);
      const prevMiddle = createHash("sha256").update(middle, "utf8").digest("hex");
      // Drop middle; keep third's prev pointing at middle, but renumber index to 1.
      const third = v1StoreLine({ leaf_hash: "33".repeat(32), owner_id: "owner-a", at_ms: 3 }, 1, prevMiddle);
      writeFileSync(storePath, `${first}${third}`, "utf8");
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        /breaks the prev-hash chain/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("open fsyncs the store; a failed open fsync after an unflushed append refuses to start", { timeout: 10_000 }, () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-open-fsync-"));
    try {
      const storePath = join(dir, "store.jsonl");
      const row = { leaf_hash: "ab".repeat(32), owner_id: "owner-a", at_ms: 1 };
      let appendFsync = false;
      const first = openStore(storePath, {
        fileOps: {
          writeSync,
          fsyncSync: (fd) => {
            if (appendFsync) throw new Error("injected append fsync failure");
            fsyncSync(fd);
          },
        },
      });
      try {
        appendFsync = true;
        assert.throws(() => first.append(row), /injected append fsync failure/);
      } finally {
        first.close();
      }
      assert.ok(readFileSync(storePath, "utf8").includes(row.leaf_hash));
      assert.throws(
        () =>
          openStore(storePath, {
            fileOps: {
              writeSync,
              fsyncSync: () => {
                throw new Error("injected open fsync failure");
              },
            },
          }),
        /injected open fsync failure/,
      );
      assert.ok(readFileSync(storePath, "utf8").includes(row.leaf_hash));
      const again = openStore(storePath);
      try {
        assert.equal(again.log.size, 1);
      } finally {
        again.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a real I/O error flushing the parent directory refuses to create a store", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-dirfsync-"));
    try {
      const storePath = join(dir, "store.jsonl");
      assert.throws(
        () =>
          openStore(storePath, {
            parentDirOps: {
              openSync: () => {
                const err = new Error("injected directory open EIO") as NodeJS.ErrnoException;
                err.code = "EIO";
                throw err;
              },
            },
          }),
        /EIO|injected directory open/,
      );
      assert.equal(existsSync(storePath), true);
      const ignored = openStore(join(dir, "other.jsonl"), {
        parentDirOps: {
          openSync: () => {
            const err = new Error("injected directory open EINVAL") as NodeJS.ErrnoException;
            err.code = "EINVAL";
            throw err;
          },
        },
      });
      ignored.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("append does not advance memory before fsync returns, and a throwing fsync latches 503", { timeout: 10_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-fsync-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });

    const ops: string[] = [];
    let serviceRef: RunningService | null = null;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      openStore: {
        fileOps: {
          writeSync: (fd, buffer, offset, length, position) => {
            ops.push("write");
            return writeSync(fd, buffer, offset, length, position);
          },
          fsyncSync: (fd) => {
            ops.push("fsync");
            // Open also fsyncs before accept; append assertions apply only once the service exists.
            if (serviceRef === null) return;
            // In-memory log is only advanced after writeRow returns.
            assert.equal(serviceRef.log.size, 0);
            assert.ok(!ops.includes("responded"));
          },
        },
      },
    });
    serviceRef = service;
    try {
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "ab".repeat(32) }),
      });
      ops.push("responded");
      assert.equal(res.status, 200);
      const writeAt = ops.indexOf("write");
      assert.ok(writeAt >= 0, "expected a store write");
      assert.equal(ops[writeAt + 1], "fsync");
      assert.equal(service.log.size, 1);

      await service.close();
      let throwAppendFsync = true;
      let acceptOpen = true;
      const again = await startService(config, {
        lockBeatMs: TEST_LOCK_BEAT_MS,
        openStore: {
          fileOps: {
            writeSync,
            fsyncSync: () => {
              if (acceptOpen) {
                acceptOpen = false;
                return;
              }
              if (throwAppendFsync) throw new Error("fsync failed");
            },
          },
        },
      });
      try {
        const fail = await fetch(`${again.url}/register`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${TOKEN}`,
          },
          body: JSON.stringify({ capsule_id: "cd".repeat(32) }),
        });
        assert.equal(fail.status, 500);
        const later = await fetch(`${again.url}/register`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${TOKEN}`,
          },
          body: JSON.stringify({ capsule_id: "ef".repeat(32) }),
        });
        assert.equal(later.status, 503);
        assert.deepEqual(await later.json(), { error: "store-unavailable" });
      } finally {
        await again.close();
      }
    } finally {
      try {
        await service.close();
      } catch {
        /* already closed */
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it("sendAndClose destroys the socket, not only Connection: close", { timeout: 5_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-destroy-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    let destroyed: boolean | null = null;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      afterSendAndClose: (socketDestroyed) => {
        destroyed = socketDestroyed;
      },
    });
    try {
      const url = new URL(service.url);
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("body-too-large answer did not finish")), 3_000);
        const req = httpRequest(
          {
            hostname: url.hostname,
            port: url.port,
            path: "/register",
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${TOKEN}`,
              "content-length": String(4 * 1024 + 1),
            },
          },
          (res) => {
            assert.equal(res.statusCode, 413);
            res.resume();
            res.on("end", () => {
              clearTimeout(timer);
              resolve();
            });
          },
        );
        req.on("error", (err) => {
          clearTimeout(timer);
          reject(err);
        });
        req.write("x".repeat(4 * 1024 + 1));
        req.end();
      });
      const deadline = Date.now() + 2_000;
      while (destroyed === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.equal(destroyed, true, "expected sendAndClose to destroy the socket");
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("after the lock is lost, a duplicate registration is 503 with no receipt", { timeout: 15_000 }, async () => {
    const h = await startHarness();
    try {
      const first = await registerCheckpoint(h.service.url, "aa".repeat(32), h.publicKeyPem, fetch, Date.now, h.token);
      assert.equal(first.ok, true);
      const before = storeBytes(h.storePath);
      const lockPath = storeLockPath(h.storePath);
      writeFileSync(
        join(lockPath, "holder"),
        `${JSON.stringify({ pid: 2_147_483_646, startedAt: Date.now(), token: "other-holder", beatMs: TEST_LOCK_BEAT_MS })}\n`,
        "utf8",
      );
      await new Promise((r) => setTimeout(r, TEST_LOCK_BEAT_MS * 3));
      const res = await fetch(`${h.service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${h.token}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.ok(storeBytes(h.storePath).equals(before));
    } finally {
      await stopHarness(h);
    }
  });

  it("a new leaf after another request's failed append during the body is 503 with no line", { timeout: 15_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-body-latch-new-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    let failNext = false;
    let stalled: (() => void) | null = null;
    let phase = 0;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, row) => {
        if (failNext) throw new Error("store-write-failed");
        appendStore(path, row);
      },
      afterAuthBeforeBody: async () => {
        if (phase++ !== 0) return;
        await new Promise<void>((resolve) => {
          stalled = resolve;
        });
      },
    });
    try {
      const before = storeBytes(storePath);
      const aPromise = fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "a1".repeat(32) }),
      });
      const deadline = Date.now() + 5_000;
      while (stalled === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.ok(stalled, "expected request A to stall after auth");
      failNext = true;
      const b = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "b1".repeat(32) }),
      });
      assert.equal(b.status, 500);
      failNext = false;
      stalled();
      const a = await aPromise;
      assert.equal(a.status, 503);
      assert.deepEqual(await a.json(), { error: "store-unavailable" });
      assert.ok(storeBytes(storePath).equals(before));
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an existing leaf after a failed append during the body is 503 with no receipt", { timeout: 15_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-body-latch-dup-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const seeded = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      const prior = await registerCheckpoint(seeded.url, "aa".repeat(32), publicKeyPem, fetch, Date.now, TOKEN);
      assert.equal(prior.ok, true);
    } finally {
      await seeded.close();
    }
    let failNext = false;
    let stalled: (() => void) | null = null;
    let phase = 0;
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      appendRow: (path, row) => {
        if (failNext) throw new Error("store-write-failed");
        appendStore(path, row);
      },
      afterAuthBeforeBody: async () => {
        if (phase++ !== 0) return;
        await new Promise<void>((resolve) => {
          stalled = resolve;
        });
      },
    });
    try {
      const aPromise = fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      const deadline = Date.now() + 5_000;
      while (stalled === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.ok(stalled, "expected duplicate request to stall after auth");
      failNext = true;
      const b = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(b.status, 500);
      failNext = false;
      stalled();
      const a = await aPromise;
      assert.equal(a.status, 503);
      assert.deepEqual(await a.json(), { error: "store-unavailable" });
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an existing leaf after the lock was lost during the body is 503 with no receipt", { timeout: 15_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-body-lock-dup-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const seeded = await startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      const prior = await registerCheckpoint(seeded.url, "aa".repeat(32), publicKeyPem, fetch, Date.now, TOKEN);
      assert.equal(prior.ok, true);
    } finally {
      await seeded.close();
    }
    const again = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      afterAuthBeforeBody: () => {
        const lockPath = storeLockPath(storePath);
        writeFileSync(
          join(lockPath, "holder"),
          `${JSON.stringify({ pid: 2_147_483_646, startedAt: Date.now(), token: "other-holder", beatMs: TEST_LOCK_BEAT_MS })}\n`,
          "utf8",
        );
      },
    });
    try {
      const res = await fetch(`${again.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "aa".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
    } finally {
      await again.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("losing the lock after the first check and before append answers 503 with no new line", { timeout: 15_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-before-append-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyFile = join(dir, "signing.private.pem");
    const tokensFile = join(dir, "tokens.json");
    const storePath = join(dir, "store.jsonl");
    writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
    writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
    const config = loadConfig({
      VERAX_ANCHOR_SVC_TOKENS: tokensFile,
      VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
      VERAX_ANCHOR_SVC_STORE: storePath,
      VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
      VERAX_ANCHOR_SVC_PORT: "0",
    });
    const service = await startService(config, {
      lockBeatMs: TEST_LOCK_BEAT_MS,
      afterAuthBeforeBody: () => {
        const lockPath = storeLockPath(storePath);
        writeFileSync(
          join(lockPath, "holder"),
          `${JSON.stringify({ pid: 2_147_483_646, startedAt: Date.now(), token: "other-holder", beatMs: TEST_LOCK_BEAT_MS })}\n`,
          "utf8",
        );
      },
    });
    try {
      const before = storeBytes(storePath);
      const res = await fetch(`${service.url}/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ capsule_id: "bb".repeat(32) }),
      });
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { error: "store-unavailable" });
      assert.ok(storeBytes(storePath).equals(before));
    } finally {
      await service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a holder that lost its lock stops beating the new holder's file and reports lost", { timeout: 10_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-beat-"));
    const storePath = join(dir, "store.jsonl");
    writeFileSync(storePath, "", "utf8");
    const lock = acquireStoreLock(storePath, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      let lost = false;
      lock.onLost(() => {
        lost = true;
      });
      const lockPath = storeLockPath(storePath);
      const holder = join(lockPath, "holder");
      writeFileSync(
        holder,
        `${JSON.stringify({ pid: 2_147_483_646, startedAt: Date.now(), token: "other-holder", beatMs: TEST_LOCK_BEAT_MS })}\n`,
        "utf8",
      );
      const past = Date.now() / 1000 - 120;
      utimesSync(holder, past, past);
      const mtimeBefore = statSync(holder).mtimeMs;
      await new Promise((r) => setTimeout(r, TEST_LOCK_BEAT_MS * 5));
      assert.equal(lock.stillHeld(), false);
      assert.equal(lost, true);
      assert.equal(statSync(holder).mtimeMs, mtimeBefore);
      const onDisk = JSON.parse(readFileSync(holder, "utf8")) as { token?: string };
      assert.equal(onDisk.token, "other-holder");
    } finally {
      lock.release();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a holder that lost its lock does not remove the other holder's lock on release", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-release-"));
    const storePath = join(dir, "store.jsonl");
    writeFileSync(storePath, "", "utf8");
    const lock = acquireStoreLock(storePath, { lockBeatMs: TEST_LOCK_BEAT_MS });
    try {
      const lockPath = storeLockPath(storePath);
      const holder = join(lockPath, "holder");
      writeFileSync(
        holder,
        `${JSON.stringify({ pid: 2_147_483_646, startedAt: Date.now(), token: "other-holder", beatMs: TEST_LOCK_BEAT_MS })}\n`,
        "utf8",
      );
      lock.release();
      assert.equal(existsSync(lockPath), true);
      const onDisk = JSON.parse(readFileSync(holder, "utf8")) as { token?: string };
      assert.equal(onDisk.token, "other-holder");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a leftover takeover gate is refused with a sentence that names the gate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-gateleft-"));
    try {
      const { privateKey } = generateKeyPairSync("ed25519");
      const keyFile = join(dir, "signing.private.pem");
      const tokensFile = join(dir, "tokens.json");
      const storePath = join(dir, "store.jsonl");
      writeSecretFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
      const digest = createHash("sha256").update(TOKEN, "utf8").digest("hex");
      writeSecretFile(tokensFile, JSON.stringify({ [digest]: "owner-a" }));
      writeFileSync(storePath, "", "utf8");
      writeStaleStoreLock(storePath, {
        pid: 2_147_483_646,
        startedAt: Date.now() - 60_000,
        token: "dead-holder",
      });
      const gate = storeTakeoverGatePath(storePath);
      mkdirSync(gate);
      const config = loadConfig({
        VERAX_ANCHOR_SVC_TOKENS: tokensFile,
        VERAX_ANCHOR_SVC_SIGNING_KEY: keyFile,
        VERAX_ANCHOR_SVC_STORE: storePath,
        VERAX_ANCHOR_SVC_HOST: "127.0.0.1",
        VERAX_ANCHOR_SVC_PORT: "0",
      });
      await assertStartRefused(
        () => startService(config, { lockBeatMs: TEST_LOCK_BEAT_MS }),
        (err) => {
          assert.match(err.message, /store lock takeover gate is present/);
          assert.ok(err.message.includes(gate));
          assert.ok(!err.message.startsWith("store already locked:"));
          return true;
        },
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a deterministic takeover: A holds, B is refused, and a changed holder under the gate is left alone", { timeout: 30_000 }, async () => {
    const takeoverScript = join(root, "tests", "anchor-service-lock-takeover.ts");
    const dir = mkdtempSync(join(tmpdir(), "verax-asvc-det-"));
    const syncDir = mkdtempSync(join(tmpdir(), "verax-asvc-sync-"));
    const storePath = join(dir, "store.jsonl");
    writeFileSync(storePath, "", "utf8");
    writeStaleStoreLock(storePath, {
      pid: 2_147_483_646,
      startedAt: Date.now() - 60_000,
      token: "stale-det-token",
    });
    const children: ReturnType<typeof spawn>[] = [];
    const buffers = new Map<ReturnType<typeof spawn>, { out: string; err: string }>();
    const spawnOne = (id: string, pause: string) => {
      const child = spawn(
        process.execPath,
        ["--experimental-strip-types", takeoverScript, storePath, String(TEST_LOCK_BEAT_MS), pause, syncDir, id],
        { stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
      );
      children.push(child);
      const buf = { out: "", err: "" };
      buffers.set(child, buf);
      child.stdout?.on("data", (b: Buffer) => {
        buf.out += String(b);
      });
      child.stderr?.on("data", (b: Buffer) => {
        buf.err += String(b);
      });
      return child;
    };
    const waitPaused = async (id: string, point: string): Promise<void> => {
      const marker = join(syncDir, `paused-${id}-${point}`);
      const deadline = Date.now() + 10_000;
      while (!existsSync(marker)) {
        if (Date.now() > deadline) throw new Error(`missing pause marker ${marker}`);
        await new Promise((r) => setTimeout(r, 20));
      }
    };
    const go = (id: string, point: string): void => {
      writeFileSync(join(syncDir, `go-${id}-${point}`), "1", "utf8");
    };
    const readOutcome = (child: ReturnType<typeof spawn>): Promise<string> =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const buf = buffers.get(child)!;
          reject(new Error(`takeover child timed out stdout=${buf.out} stderr=${buf.err}`));
        }, 15_000);
        const check = (): void => {
          const buf = buffers.get(child)!;
          if (/(^|\n)held /.test(buf.out) || /(^|\n)refused /.test(buf.out)) {
            clearTimeout(timer);
            resolve(buf.out);
          }
        };
        check();
        child.stdout?.on("data", check);
        child.on("exit", (code) => {
          const buf = buffers.get(child)!;
          if (/(^|\n)held /.test(buf.out) || /(^|\n)refused /.test(buf.out)) {
            clearTimeout(timer);
            resolve(buf.out);
            return;
          }
          clearTimeout(timer);
          reject(new Error(`exit ${code} stderr=${buf.err} stdout=${buf.out}`));
        });
      });
    try {
      // Both try to enter the gate and pause before removal. With the gate,
      // only one pauses and the other is refused; without it, both pause and
      // both can hold after release.
      const a = spawnOne("A", "inside-gate-before-removal");
      const b = spawnOne("B", "inside-gate-before-removal");
      const point = "inside-gate-before-removal";
      const deadline = Date.now() + 10_000;
      let aPaused = false;
      let bPaused = false;
      while (Date.now() < deadline) {
        aPaused = existsSync(join(syncDir, `paused-A-${point}`));
        bPaused = existsSync(join(syncDir, `paused-B-${point}`));
        const aBuf = buffers.get(a)!.out;
        const bBuf = buffers.get(b)!.out;
        if (aPaused && bPaused) break;
        if (aPaused && /refused B/.test(bBuf)) break;
        if (bPaused && /refused A/.test(aBuf)) break;
        await new Promise((r) => setTimeout(r, 20));
      }
      aPaused = existsSync(join(syncDir, `paused-A-${point}`));
      bPaused = existsSync(join(syncDir, `paused-B-${point}`));
      // If both reached the critical section, release one then the other so the
      // second removes the first's lock (only possible when the gate is absent).
      if (aPaused && bPaused) {
        go("A", point);
        const first = await readOutcome(a);
        go("B", point);
        const second = await readOutcome(b);
        const held = [first, second].filter((o) => /held /.test(o));
        assert.equal(held.length, 1, `expected one holder, got:\n${first}\n${second}`);
      } else {
        if (aPaused) go("A", point);
        if (bPaused) go("B", point);
        const outA = await readOutcome(a);
        const outB = await readOutcome(b);
        const held = [outA, outB].filter((o) => /held /.test(o));
        const refused = [outA, outB].filter((o) => /refused /.test(o));
        assert.equal(held.length, 1, `expected one holder, got:\n${outA}\n${outB}`);
        assert.equal(refused.length, 1, `expected one refusal, got:\n${outA}\n${outB}`);
      }
      assert.equal(existsSync(storeTakeoverGatePath(storePath)), false);

      // Recheck: pause inside the gate, change holder bytes (same token), refuse.
      a.kill("SIGKILL");
      b.kill("SIGKILL");
      await Promise.all(
        children.map(
          (c) =>
            new Promise<void>((resolve) => {
              if (c.exitCode !== null || c.signalCode !== null) resolve();
              else c.once("exit", () => resolve());
            }),
        ),
      );
      children.length = 0;
      rmSync(storeLockPath(storePath), { recursive: true, force: true });
      writeStaleStoreLock(storePath, {
        pid: 2_147_483_646,
        startedAt: Date.now() - 60_000,
        token: "stale-recheck-token",
      });
      const judged = readFileSync(join(storeLockPath(storePath), "holder"), "utf8");
      const c = spawnOne("C", "inside-gate-before-recheck");
      await waitPaused("C", "inside-gate-before-recheck");
      writeFileSync(
        join(storeLockPath(storePath), "holder"),
        `${JSON.stringify({
          pid: 1,
          startedAt: Date.now() - 60_000,
          token: "stale-recheck-token",
        })}\n`,
        "utf8",
      );
      const changed = readFileSync(join(storeLockPath(storePath), "holder"), "utf8");
      assert.notEqual(changed, judged);
      go("C", "inside-gate-before-recheck");
      const outC = await readOutcome(c);
      assert.match(outC, /refused C/);
      assert.equal(readFileSync(join(storeLockPath(storePath), "holder"), "utf8"), changed);
      assert.equal(existsSync(storeTakeoverGatePath(storePath)), false);
    } finally {
      for (const child of children) {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      }
      await Promise.all(
        children.map(
          (c) =>
            new Promise<void>((resolve) => {
              if (c.exitCode !== null || c.signalCode !== null) resolve();
              else {
                c.once("exit", () => resolve());
                c.kill("SIGKILL");
              }
            }),
        ),
      );
      rmSync(dir, { recursive: true, force: true });
      rmSync(syncDir, { recursive: true, force: true });
    }
  });
});
