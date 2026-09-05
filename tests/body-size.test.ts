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

describe("P1-6 request body is capped at 1 MiB", () => {
  it("returns 413 for a 2 MiB JSON body and for a 2 MiB chunked body", async () => {
    const pair = await startPair();
    const token = await pair.issuer.sign({ scope: "verax:read" });
    const pad = "x".repeat(TWO_MIB);
    const json = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {}, pad });
    try {
      const cl = await fetch(`http://127.0.0.1:${pair.port}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: json,
      });
      assert.equal(cl.status, 413, `content-length body status ${cl.status}`);

      const chunkedStatus = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port: pair.port,
            path: "/mcp",
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json, text/event-stream",
              authorization: `Bearer ${token}`,
              "transfer-encoding": "chunked",
            },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          },
        );
        req.on("error", reject);
        req.write(json);
        req.end();
      });
      assert.equal(chunkedStatus, 413, `chunked body status ${chunkedStatus}`);
    } finally {
      await closePair(pair);
    }
  });
});
