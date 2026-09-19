#!/usr/bin/env node
// Fixture MCP server over Streamable HTTP, for the downstream HTTP attach.
// One tool. Prints its bound URL on stdout as `url=<...>` and nothing else.
//
// When VERAX_CHILD_TOKEN is set the server refuses a request that does not
// carry it, so a test can prove the operator's headers reach the child.

import { createServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const wantToken = process.env.VERAX_CHILD_TOKEN ?? "";

// Stateless: one server and one transport per request, the same shape the
// body's own /mcp uses. A shared transport answers the first POST and then
// refuses the rest.
function yeniSunucu() {
  const server = new Server({ name: "downstream-http-child", version: "0.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "lookup",
        description: "Returns {found:true,q} for a query string q.",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: { q: { type: "string", description: "The query echoed back." } },
          required: ["q"],
        },
      },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== "lookup") throw new Error(`unknown-tool:${request.params.name}`);
    const args = request.params.arguments ?? {};
    return { content: [{ type: "text", text: JSON.stringify({ found: true, q: args.q ?? null }) }] };
  });
  return server;
}

const http = createServer(async (req, res) => {
  if (wantToken !== "" && req.headers.authorization !== `Bearer ${wantToken}`) {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "child-unauthorized" }));
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  let body;
  try {
    body = text === "" ? undefined : JSON.parse(text);
  } catch {
    res.writeHead(400).end();
    return;
  }
  const server = yeniSunucu();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);
  try {
    await transport.handleRequest(req, res, body);
  } finally {
    await transport.close().catch(() => undefined);
  }
});

await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
process.stdout.write(`url=http://127.0.0.1:${http.address().port}/mcp\n`);
