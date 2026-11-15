/**
 * HTTP service: POST /register with {"capsule_id": "<64 lowercase hex>"} and
 * Authorization: Bearer <token>. Answers with a COSE receipt over an RFC 9162
 * log. The token file maps digests to owner ids; the store never holds a token.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { anchorEntryHash } from "@verax-ai/proxy";

import { bearerToken, ownerForToken } from "./auth.ts";
import type { ServiceConfig } from "./config.ts";
import { RateLimiter } from "./rate.ts";
import { issueReceipt } from "./receipt.ts";
import { openStore, type OpenStore, type OpenStoreOpts, type StoreRow } from "./store.ts";
import { acquireStoreLock, type StoreLock } from "./store-lock.ts";
import type { MerkleLog } from "./merkle.ts";

const MAX_BODY = 4 * 1024;
const CAPSULE = /^[0-9a-f]{64}$/;

export type AppendRow = (path: string, row: StoreRow) => void;

export type RunningService = {
  server: Server;
  log: MerkleLog;
  config: ServiceConfig;
  url: string;
  publicKeyPem: string;
  close: () => Promise<void>;
};

function send(res: ServerResponse, status: number, body?: unknown): void {
  if (body === undefined) {
    res.writeHead(status).end();
    return;
  }
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" }).end(text);
}

/** Answer and close the connection so the client cannot keep streaming. */
function sendAndClose(
  res: ServerResponse,
  status: number,
  body: unknown,
  after?: (socketDestroyed: boolean) => void,
): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    connection: "close",
  });
  res.end(text, () => {
    res.socket?.destroy();
    after?.(res.socket?.destroyed === true);
  });
}

/** Early refusal before a body is consumed: always ends the TCP connection. */
function refuseEarly(
  res: ServerResponse,
  status: number,
  body: unknown,
  after?: (socketDestroyed: boolean) => void,
): void {
  sendAndClose(res, status, body, after);
}

// Body-timeout rejects only; the handler always answers through sendAndClose,
// which destroys the socket. Destroying here would duplicate that close and is
// not held by any test (a half-body client is gone via getConnections either way).
function readBody(req: IncomingMessage, max: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("body-timeout"));
    }, timeoutMs);
    const ok = (buf: Buffer): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(buf);
    };
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    };
    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > max) {
        fail(new Error("body-too-large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      ok(Buffer.concat(chunks));
    });
    req.on("error", (err) => {
      fail(err);
    });
  });
}

function contentTypeOk(header: string | undefined): boolean {
  if (!header) return false;
  const base = header.split(";")[0]!.trim().toLowerCase();
  return base === "application/json";
}

export async function startService(
  config: ServiceConfig,
  options?: {
    appendRow?: AppendRow;
    lockBeatMs?: number;
    openStore?: OpenStoreOpts;
    /** Test-only: after auth and the first lock check, before the body is read. */
    afterAuthBeforeBody?: () => void | Promise<void>;
    /** Test-only: called after sendAndClose finishes its end callback. */
    afterSendAndClose?: (socketDestroyed: boolean) => void;
  },
): Promise<RunningService> {
  let lock: StoreLock;
  try {
    lock = acquireStoreLock(config.storePath, { lockBeatMs: options?.lockBeatMs });
  } catch (err) {
    throw new Error(err instanceof Error ? err.message : String(err));
  }
  let store: OpenStore;
  try {
    store = openStore(config.storePath, options?.openStore);
  } catch (err) {
    lock.release();
    throw new Error(err instanceof Error ? err.message : String(err));
  }
  const log: MerkleLog = store.log;
  const rate = new RateLimiter(config.ratePerMinute);
  const writeRow = options?.appendRow ?? ((_path: string, row: StoreRow) => store.append(row));
  // stillHeld() already latches lost on the lock; every authenticated path
  // checks it (and sets storeUnavailable). A separate onLost → storeUnavailable
  // latch cannot fail alone, so it is not registered.
  let storeUnavailable = false;
  const afterAuthBeforeBody = options?.afterAuthBeforeBody;
  const afterSendAndClose = options?.afterSendAndClose;

  const server = createServer((req, res) => {
    void handle(req, res);
  });
  // server.headersTimeout alone was not held by a test (the connection socket
  // timer below is). Keep requestTimeout as a whole-request bound; the
  // slow-body path is held by readBody's timer, not req.socket.setTimeout.
  server.requestTimeout = config.requestTimeoutMs;
  server.keepAliveTimeout = config.keepAliveTimeoutMs;
  server.maxConnections = config.maxConnections;
  // Present on Node's HTTP server; not yet in the published type definitions.
  (server as Server & { connectionsCheckingInterval: number }).connectionsCheckingInterval = Math.max(
    50,
    Math.min(1_000, Math.floor(config.headersTimeoutMs / 2)),
  );
  // Connection-level timer: cuts sockets that never finish headers.
  server.on("connection", (socket) => {
    socket.setTimeout(config.headersTimeoutMs);
    socket.once("timeout", () => {
      socket.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (req.method !== "POST" || req.url !== "/register") {
        refuseEarly(res, 404, { error: "not-found" });
        return;
      }
      const token = bearerToken(req.headers.authorization);
      if (token === null) {
        refuseEarly(res, 401, { error: "unauthorized" });
        return;
      }
      const ownerId = ownerForToken(token, config.tokens);
      if (ownerId === null) {
        refuseEarly(res, 401, { error: "unauthorized" });
        return;
      }
      if (storeUnavailable || !lock.stillHeld()) {
        storeUnavailable = true;
        refuseEarly(res, 503, { error: "store-unavailable" });
        return;
      }
      if (!contentTypeOk(req.headers["content-type"])) {
        // 415 would be more precise; keep 400 for the existing client contract.
        refuseEarly(res, 400, { error: "bad-content-type" });
        return;
      }
      if (afterAuthBeforeBody) await afterAuthBeforeBody();
      let body: Buffer;
      try {
        body = await readBody(req, MAX_BODY, config.requestTimeoutMs);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "";
        if (msg === "body-too-large") {
          sendAndClose(res, 413, { error: "body-too-large" }, afterSendAndClose);
        } else if (msg === "body-timeout") {
          sendAndClose(res, 408, { error: "request-timeout" }, afterSendAndClose);
        } else {
          sendAndClose(res, 400, { error: "bad-body" }, afterSendAndClose);
        }
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(body.toString("utf8"));
      } catch {
        send(res, 400, { error: "bad-json" });
        return;
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        send(res, 400, { error: "bad-body" });
        return;
      }
      const capsuleId = (parsed as { capsule_id?: unknown }).capsule_id;
      if (typeof capsuleId !== "string" || !CAPSULE.test(capsuleId)) {
        send(res, 400, { error: "bad-capsule-id" });
        return;
      }
      if (rate.overLimit(ownerId)) {
        send(res, 429, { error: "rate-limited" });
        return;
      }

      const entryHash = anchorEntryHash(capsuleId, "register");
      let leafIndex = log.findLeaf(ownerId, entryHash);
      if (leafIndex < 0) {
        if (!lock.stillHeld()) {
          storeUnavailable = true;
          send(res, 503, { error: "store-unavailable" });
          return;
        }
        const atMs = Date.now();
        try {
          writeRow(config.storePath, { leaf_hash: entryHash, owner_id: ownerId, at_ms: atMs });
        } catch {
          storeUnavailable = true;
          send(res, 500, { error: "internal" });
          return;
        }
        leafIndex = log.append({
          entry: Buffer.from(entryHash, "hex"),
          ownerId,
          atMs,
        });
      }
      rate.record(ownerId);
      const issued = issueReceipt(log, leafIndex, config.privateKeyPem);
      send(res, 200, {
        receipt_b64: issued.receipt.toString("base64"),
        entry_hash: entryHash,
        leaf_index: issued.leafIndex,
        tree_size: issued.treeSize,
      });
    } catch {
      if (!res.headersSent) send(res, 500, { error: "internal" });
    }
  }

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.port, config.host, () => resolve());
    });
  } catch (err) {
    lock.release();
    throw err;
  }
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    lock.release();
    throw new Error("bind failed");
  }
  const url = `http://${config.host}:${addr.port}`;

  return {
    server,
    log,
    config,
    url,
    publicKeyPem: config.publicKeyPem,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => {
          try {
            store.close();
          } catch {
            // Still release the lock.
          }
          lock.release();
          if (err) reject(err);
          else resolve();
        });
      }),
  };
}
