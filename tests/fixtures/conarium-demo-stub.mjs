#!/usr/bin/env node
// Fixture MCP server for the demo --with-conarium path. Four tools, stdio only.
// stdout is protocol; counts go to --count-file when named.

import { appendFileSync } from "node:fs";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const args = process.argv.slice(2);
const unmasked = args.includes("--unmasked");
const dieOnSecrets = args.includes("--die-on-secrets");
const countAt = args.indexOf("--count-file");
const countFile = countAt !== -1 && typeof args[countAt + 1] === "string" ? args[countAt + 1] : null;

const count = (event) => {
  if (!countFile) return;
  appendFileSync(countFile, `${JSON.stringify({ ...event, at: Date.now() })}\n`, "utf8");
};

const MASK = "[MASKED_PII]";

const customerRows = [
  { name: "Ada Example", email: "ada@example.com", card: "4111111111111111" },
  { name: "Sam Example", email: "sam@example.com", card: "5500000000000004" },
  { name: "Lin Example", email: "lin@example.com", card: "340000000000009" },
  { name: "Pat Example", email: "pat@example.com", card: "30000000000004" },
  { name: "Rio Example", email: "rio@example.com", card: "6011000000000004" },
];

function customersPayload() {
  const rows = customerRows.map((row) =>
    unmasked ? row : { name: row.name, email: MASK, card: MASK },
  );
  return {
    rowCount: 5,
    fields: ["name", "email", "card"],
    rows,
    truncated: true,
  };
}

const server = new Server({ name: "conarium-demo-stub", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "list_tables",
      description: "Lists tables the demo child would expose.",
      inputSchema: { type: "object", additionalProperties: false, properties: {} },
    },
    {
      name: "describe_table",
      description: "Describes one table.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: { table: { type: "string" } },
      },
    },
    {
      name: "query",
      description: "Runs a SQL string against the sample rows.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: { sql: { type: "string" } },
      },
    },
    {
      name: "search",
      description: "Searches the sample rows.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: { q: { type: "string" } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  count({ event: "call", tool: name });
  const sql =
    request.params.arguments && typeof request.params.arguments.sql === "string"
      ? request.params.arguments.sql
      : "";
  if (name === "query" && /public\.secrets/i.test(sql)) {
    // A child that dies mid-call is not a child that answered.
    if (dieOnSecrets) process.exit(1);
    return {
      content: [{ type: "text", text: "Error: Access to table 'public.secrets' is not available." }],
      isError: true,
    };
  }
  if (name === "query") {
    return {
      content: [{ type: "text", text: JSON.stringify(customersPayload()) }],
      isError: false,
    };
  }
  if (name === "list_tables") {
    return {
      content: [{ type: "text", text: JSON.stringify({ tables: ["public.customers", "public.secrets"] }) }],
      isError: false,
    };
  }
  if (name === "describe_table" || name === "search") {
    return {
      content: [{ type: "text", text: JSON.stringify({ ok: true, tool: name }) }],
      isError: false,
    };
  }
  throw new Error(`unknown-tool:${name}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);
count({
  event: "start",
  pid: process.pid,
  argv: process.argv.slice(2),
  env: process.env,
});
