import { strict as assert } from "node:assert";
import { createServer, type Server as HttpServer } from "node:http";
import { after, describe, it } from "node:test";

import { openDownstream } from "../packages/body/src/downstream.ts";

/**
 * R26 (E-8). An attached tool is "held to the 64 KiB bound". The bound is
 * `JSON.stringify({ name, description, inputSchema }).length`, which counts
 * UTF-16 code units, not bytes, and measures three fields of the entry. A
 * hostile child gets past it two ways: a description in three-byte characters
 * is republished at about 180 KB, and megabytes placed in `outputSchema` or
 * `title` are never measured, though the SDK client keeps the output schema
 * and compiles a validator from it for every tool the child lists.
 */

const servers: HttpServer[] = [];

after(async () => {
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise<void>((r) => s.close(() => r()));
  }
});

const INIT = {
  protocolVersion: "2024-11-05",
  capabilities: { tools: {} },
  serverInfo: { name: "hostile", version: "0.0.0" },
};

/** An MCP child over HTTP that answers `tools/list` with `tools`. */
async function childListing(tools: unknown[]): Promise<string> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let msg: { id?: unknown; method?: string } = {};
    try {
      msg = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as typeof msg;
    } catch {
      /* empty body */
    }
    const method = String(msg.method ?? "");
    if (req.method !== "POST" || method.startsWith("notifications/")) {
      res.writeHead(req.method === "POST" ? 202 : 405).end();
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? 1, result: method === "initialize" ? INIT : { tools } }));
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

const BOUND = 64 * 1024;

describe("R26 the 64 KiB bound on an attached tool", { timeout: 60_000 }, () => {
  it("counts bytes: a 180 KB description in three-byte characters is refused", async () => {
    const description = "漢".repeat(60_000);
    const url = await childListing([{ name: "ping", description, inputSchema: { type: "object" } }]);
    let attachedBytes = 0;
    try {
      const session = await openDownstream({ prefix: "wide", url, timeoutMs: 5000, tools: ["ping"] });
      const tool = session.tools[0]!;
      attachedBytes = Buffer.byteLength(
        JSON.stringify({ name: "ping", description: tool.description, inputSchema: tool.inputSchema }),
        "utf8",
      );
      await session.close();
    } catch (err) {
      assert.match(err instanceof Error ? err.message : String(err), /downstream-tool-too-large/);
      return;
    }
    assert.ok(attachedBytes <= BOUND, `a listed tool of ${attachedBytes} bytes was attached under a ${BOUND}-byte bound`);
  });

  it("covers the whole entry: megabytes in outputSchema and title are refused", async () => {
    const entry = {
      name: "ping",
      description: "ok",
      inputSchema: { type: "object" },
      outputSchema: { type: "object", description: "z".repeat(2_000_000) },
      title: "t".repeat(1_000_000),
    };
    const url = await childListing([entry]);
    await assert.rejects(
      async () => {
        const session = await openDownstream({ prefix: "out", url, timeoutMs: 5000, tools: ["ping"] });
        await session.close();
      },
      /downstream-tool-too-large/,
      `a listed tool whose entry is ${JSON.stringify(entry).length} bytes was attached`,
    );
  });
});
