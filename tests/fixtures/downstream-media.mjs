#!/usr/bin/env node
// Fixture MCP server for result media blocks. One tool, stdio only.
// stdout is protocol; nothing else is printed there.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "downstream-media", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "blocks",
      description: "Returns text, image, audio, resource, and a broken image block.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {},
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== "blocks") {
    throw new Error(`unknown-tool:${request.params.name}`);
  }
  return {
    content: [
      { type: "text", text: "hello-media" },
      { type: "image", data: "aW1n", mimeType: "image/png" },
      { type: "audio", data: "YXVk", mimeType: "audio/mpeg" },
      { type: "resource", resource: { uri: "file://x", mimeType: "text/plain", text: "note" } },
      { type: "resource_link", name: "broken-image", uri: "file://y" },
    ],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
