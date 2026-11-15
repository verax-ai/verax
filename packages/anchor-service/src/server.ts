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
import { appendStore, loadStore, type StoreRow } from "./store.ts";
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

function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > max) {
        settled = true;
        reject(new Error("body-too-large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks));
      }
    });
    req.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
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
  options?: { appendRow?: AppendRow; lockBeatMs?: number },
): Promise<RunningService> {
  let lock: StoreLock;
  try {
    lock = acquireStoreLock(config.storePath, { lockBeatMs: options?.lockBeatMs });
  } catch (err) {
    throw new Error(err instanceof Error ? err.message : String(err));
  }
  let log: MerkleLog;
  try {
    log = loadStore(config.storePath);
  } catch (err) {
    lock.release();
    throw new Error(err instanceof Error ? err.message : String(err));
  }
  const rate = new RateLimiter(config.ratePerMinute);
  const writeRow = options?.appendRow ?? appendStore;

  const server = createServer((req, res) => {
    void handle(req, res);
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (req.method !== "POST" || req.url !== "/register") {
        send(res, 404, { error: "not-found" });
        return;
      }
      const token = bearerToken(req.headers.authorization);
      if (token === null) {
        send(res, 401, { error: "unauthorized" });
        return;
      }
      const ownerId = ownerForToken(token, config.tokens);
      if (ownerId === null) {
        send(res, 401, { error: "unauthorized" });
        return;
      }
      if (!contentTypeOk(req.headers["content-type"])) {
        send(res, 400, { error: "bad-content-type" });
        return;
      }
      let body: Buffer;
      try {
        body = await readBody(req, MAX_BODY);
      } catch {
        send(res, 400, { error: "body-too-large" });
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
        const atMs = Date.now();
        writeRow(config.storePath, { leaf_hash: entryHash, owner_id: ownerId, at_ms: atMs });
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
          lock.release();
          if (err) reject(err);
          else resolve();
        });
      }),
  };
}
