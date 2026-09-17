#!/usr/bin/env node
// Fixture MCP server for the downstream spike. One tool, stdio only.
// stdout is protocol; nothing else is printed there.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "downstream-echo", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "ping",
      description: "Returns {pong:true,n} for a number n. Throws when fail is true.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          n: { type: "number", description: "Value echoed back in the pong payload." },
          fail: { type: "boolean", description: "When true the tool throws." },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== "ping") {
    throw new Error(`unknown-tool:${request.params.name}`);
  }
  const args = (request.params.arguments ?? {});
  if (args.fail === true) {
    throw new Error("downstream-fail");
  }
  const payload = { pong: true, n: args.n };
  if (args.echoEnv === true) {
    payload.veraxKeys = Object.keys(process.env)
      .filter((k) => k.startsWith("VERAX_"))
      .sort();
  }
  return {
    content: [{ type: "text", text: JSON.stringify(payload) }],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
