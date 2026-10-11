import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { Agent, request } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { diskProbe } from "@verax-ai/proxy";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

type Answer = { status: number; text: string; reusedSocket: boolean };

function post(agent: Agent, port: number, token: string, id: number): Promise<Answer> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: "memory.get", arguments: { id: "a" } },
  });
  return new Promise((resolve, reject) => {
    const req = request(
      {
        agent,
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("error", reject);
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString("utf8"),
            reusedSocket: req.reusedSocket,
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/**
 * The 507 is written by the body, on a response the MCP transport also holds.
 * The transport then wrote its own answer to the same response: the second
 * `writeHead` threw, its adapter printed the stack with `console.error` and
 * destroyed the socket under an answer that had already gone out.
 */
describe("S3 unrecorded disk deny is answered once", () => {
  it("the 507 is the only write: no stack on stderr, and the connection stays open", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-http-507-once-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const origFree = diskProbe.freeBytes;
    const origFail = diskProbe.failAppend;
    diskProbe.freeBytes = (dir) => (dir === stateDir ? 0 : origFree(dir));
    diskProbe.failAppend = true;
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
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    const printed: unknown[][] = [];
    const origError = console.error;
    console.error = (...args: unknown[]) => {
      printed.push(args);
    };
    try {
      const token = await issuer.sign({ scope: "verax:read" });
      const first = await post(agent, port, token, 1);
      assert.equal(first.status, 507, first.text);
      assert.deepEqual(JSON.parse(first.text), { error: "insufficient-storage" });
      // Long enough for a second write to the same response to have happened.
      await new Promise((resolve) => setTimeout(resolve, 150));
      const second = await post(agent, port, token, 2);
      assert.equal(second.status, 507, second.text);
      assert.deepEqual(
        printed.map((args) => String((args[0] as { code?: unknown } | undefined)?.code ?? args[0])),
        [],
        "something was printed with console.error while the body answered 507",
      );
      assert.equal(
        second.reusedSocket,
        true,
        "the connection that carried the 507 was gone when the next call came",
      );
      const metrics = JSON.parse(readFileSync(join(stateDir, "metrics.json"), "utf8")) as {
        disk_deny_unrecorded?: number;
      };
      assert.equal(metrics.disk_deny_unrecorded, 2);
    } finally {
      console.error = origError;
      agent.destroy();
      diskProbe.freeBytes = origFree;
      diskProbe.failAppend = origFail;
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
