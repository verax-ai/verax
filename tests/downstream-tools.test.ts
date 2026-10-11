import { strict as assert } from "node:assert";
import { createServer, type Server as HttpServer } from "node:http";
import { after, describe, it } from "node:test";

import { openDownstream, parseDownstreamJson } from "../packages/body/src/downstream.ts";

/**
 * A `tools` list in the downstream document attaches only the child tools it
 * names. A child that also offers one tool past the size bound (REA's
 * compare_web_captures advertises 87 KB) can then sit behind the gate for the
 * tools the operator writes rules for. The bounds still apply to every tool
 * that is attached, a named tool the child does not offer stops the attach
 * the way any half-attach does, and without `tools` nothing changes.
 */

const servers: HttpServer[] = [];
after(async () => {
  for (const s of servers) await new Promise<void>((r) => s.close(() => r()));
});

const INIT = {
  protocolVersion: "2024-11-05",
  capabilities: { tools: {} },
  serverInfo: { name: "child", version: "0.0.0" },
};

async function child(tools: unknown[]): Promise<string> {
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
    if (method.startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    const result = method === "initialize" ? INIT : { tools };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? 1, result }));
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

const small = (name: string) => ({ name, description: "ok", inputSchema: { type: "object" } });
const oversize = { name: "huge", description: "y".repeat(80 * 1024), inputSchema: { type: "object" } };

describe("downstream tools list", { timeout: 60_000 }, () => {
  it("attaches only the named tools and leaves an oversize one unread", async () => {
    const url = await child([small("static_scan"), small("run_process"), oversize]);
    const session = await openDownstream({ prefix: "rea", url, timeoutMs: 5000, tools: ["static_scan"] });
    assert.deepEqual(session.tools.map((t) => t.name), ["rea.static_scan"]);
    await session.close();
  });

  it("without a list the oversize tool still stops the attach", async () => {
    const url = await child([small("static_scan"), oversize]);
    await assert.rejects(() => openDownstream({ prefix: "rea", url, timeoutMs: 5000 }), /downstream-tool-too-large:rea\.huge/);
  });

  it("a named tool past the size bound is refused", async () => {
    const url = await child([small("static_scan"), oversize]);
    await assert.rejects(
      () => openDownstream({ prefix: "rea", url, timeoutMs: 5000, tools: ["static_scan", "huge"] }),
      /downstream-tool-too-large:rea\.huge/,
    );
  });

  it("a named tool the child does not offer stops the attach", async () => {
    const url = await child([small("static_scan")]);
    await assert.rejects(
      () => openDownstream({ prefix: "rea", url, timeoutMs: 5000, tools: ["static_scan", "gone"] }),
      /downstream-tool-missing:rea\.gone/,
    );
  });

  it("the document accepts a list of child names and refuses anything else", () => {
    const base = { prefix: "rea", url: "http://127.0.0.1:1/mcp" };
    const spec = parseDownstreamJson(JSON.stringify({ ...base, tools: ["static_scan", "trace"] }));
    assert.deepEqual(spec.tools, ["static_scan", "trace"]);
    for (const bad of [[], "static_scan", ["ok", 7], ["ok", "ok"], ["rea.static_scan!"], ["9starts-with-digit"]]) {
      assert.throws(() => parseDownstreamJson(JSON.stringify({ ...base, tools: bad })), /downstream-tools-invalid/, JSON.stringify(bad));
    }
  });
});
