// An agent that gets a token from the issuer and calls Verax over TLS, as a
// customer's agent would. Mounted next to the body package so the MCP SDK the
// body ships resolves.
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const secret = readFileSync("/run/secrets/idp_client_secret", "utf8").trim();
const audience = "https://verax.localhost/mcp";

async function token(scope) {
  const res = await fetch("https://idp.localhost/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: "agent-2b", client_secret: secret, scope, audience }),
  });
  if (!res.ok) throw new Error(`token ${res.status}`);
  return (await res.json()).access_token;
}

const bearer = await token("verax:read verax:memory");
const transport = new StreamableHTTPClientTransport(new URL(audience), {
  requestInit: { headers: { authorization: `Bearer ${bearer}` } },
});
const client = new Client({ name: "agent-2b", version: "1.0.0" });
await client.connect(transport);
const out = { server: client.getServerVersion(), calls: [] };
const put = await client.callTool({
  name: "memory.put",
  arguments: { id: "2b-note-1", body: { t: 1 }, source: { uri: "file://2b", retrievedAtMs: 1 }, validUntilMs: Date.now() + 3_600_000 },
});
out.calls.push({ tool: "memory.put", isError: put.isError ?? false });
const got = await client.callTool({ name: "memory.get", arguments: { id: "2b-note-1" } });
out.calls.push({ tool: "memory.get", isError: got.isError ?? false, found: JSON.stringify(got).includes("2b-note-1") });
const send = await client.callTool({ name: "message.send", arguments: { to: "someone@example.com", body: "hi" } });
out.calls.push({ tool: "message.send", isError: send.isError ?? false, text: JSON.stringify(send.content).slice(0, 160) });
await client.close();

const noToken = await fetch(audience, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
out.withoutToken = noToken.status;
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
