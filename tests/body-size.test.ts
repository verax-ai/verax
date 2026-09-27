import { strict as assert } from "node:assert";
import { request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const TWO_MIB = 2 * 1024 * 1024;

async function startPair() {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-size-"));
  const audience = "http://127.0.0.1/verax-test";
  const issuer = await startDevIssuer(0, audience);
  const server = await listen({
    issuer: issuer.issuer,
    jwksUrl: issuer.jwksUrl,
    audience,
    stateDir,
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile,
    tlsTerminated: false,
  });
  const port = (server.address() as { port: number }).port;
  return { issuer, server, port, stateDir };
}

async function closePair(pair: { issuer: { close: () => Promise<void> }; server: { close: (cb: (err?: Error) => void) => void } }) {
  await new Promise<void>((resolve, reject) => {
    pair.server.close((err) => (err ? reject(err) : resolve()));
  });
  await pair.issuer.close();
}

/**
 * POST a body and resolve the status. The server answers 413 and closes while
 * the client may still be writing, so EPIPE or ECONNRESET after the response
 * is expected; any other error, or one before a response, fails the test.
 */
function postStatus(port: number, token: string, body: string, chunked: boolean): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    let status: number | null = null;
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
          ...(chunked ? { "transfer-encoding": "chunked" } : { "content-length": String(Buffer.byteLength(body)) }),
        },
      },
      (res) => {
        status = res.statusCode ?? 0;
        res.resume();
        res.on("end", () => resolve(status ?? 0));
        res.on("error", () => resolve(status ?? 0));
      },
    );
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (status !== null) {
        resolve(status);
        return;
      }
      if (err.code !== "EPIPE" && err.code !== "ECONNRESET") {
        reject(err);
        return;
      }
      // The write side broke first; give the response a moment to arrive.
      setTimeout(() => (status !== null ? resolve(status) : reject(err)), 2_000).unref();
    });
    req.write(body);
    req.end();
  });
}

describe("P1-6 request body is capped at 1 MiB", () => {
  it("returns 413 for a 2 MiB JSON body and for a 2 MiB chunked body", async () => {
    const pair = await startPair();
    const token = await pair.issuer.sign({ scope: "verax:read" });
    const pad = "x".repeat(TWO_MIB);
    const json = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {}, pad });
    try {
      const lengthStatus = await postStatus(pair.port, token, json, false);
      assert.equal(lengthStatus, 413, `content-length body status ${lengthStatus}`);
      const chunkedStatus = await postStatus(pair.port, token, json, true);
      assert.equal(chunkedStatus, 413, `chunked body status ${chunkedStatus}`);
    } finally {
      await closePair(pair);
    }
  });
});
