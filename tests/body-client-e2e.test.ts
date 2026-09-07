import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

describe("E real SDK client", () => {
  it("initialize, tools/list, and tools/call complete within 10s", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-e2e-"));
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
    const token = await issuer.sign({ scope: "verax:read verax:memory" });
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
    });
    const client = new Client({ name: "verax-e2e", version: "0.0.0" });
    try {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const raced = Promise.race([
        (async () => {
          await client.connect(transport);
          const listed = await client.listTools();
          const names = listed.tools.map((t) => t.name).sort();
          assert.deepEqual(names, [
            "audit.explain",
            "memory.get",
            "memory.put",
            "message.read",
            "message.send",
            "spend",
          ]);
          const put = await client.callTool({
            name: "memory.put",
            arguments: {
              id: "e2e-1",
              body: { t: 1 },
              source: { uri: "file://e2e", retrievedAtMs: 1 },
              validUntilMs: Date.now() + 60_000,
            },
          });
          assert.equal(put.isError, false);
          const got = await client.callTool({ name: "memory.get", arguments: { id: "e2e-1" } });
          assert.match(JSON.stringify(got), /e2e-1/);
        })(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("E: SDK client hung (10s timeout)")), 10_000);
        }),
      ]);
      await raced;
      if (timer) clearTimeout(timer);
      const get = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "GET",
        headers: { authorization: `Bearer ${token}`, accept: "text/event-stream" },
      });
      assert.equal(get.status, 405);
    } finally {
      await client.close().catch(() => undefined);
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
