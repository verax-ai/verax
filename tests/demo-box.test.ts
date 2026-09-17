import { strict as assert } from "node:assert";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// The demo box is what a sandbox runs when it cannot hold a token of its own:
// one stdio process that carries the issuer and the body inside. This drives it
// the way such a sandbox would, over stdio with the real SDK client, and reads
// what comes back from the body through it: the six tools, a recorded write and
// read, the hold on spend, the egress list on message.send.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts", "demo-box.mjs");

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as { port: number }).port;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
    srv.once("error", reject);
  });
}

function text(result: unknown): string {
  const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];
  return content.map((c) => c.text ?? "").join("");
}

describe("demo box", () => {
  it("speaks MCP over stdio and forwards to a body that gates and records", async () => {
    const issuerPort = await freePort();
    const bodyPort = await freePort();
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (typeof v === "string") env[k] = v;
    env.NODE_ENV = "development";
    env.VERAX_DEMO_ISSUER_PORT = String(issuerPort);
    env.VERAX_DEMO_BODY_PORT = String(bodyPort);
    delete env.VERAX_DEV_TOKEN;

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [script],
      cwd: root,
      env,
      stderr: "pipe",
    });
    let stderrText = "";
    transport.stderr?.on("data", (c: Buffer | string) => {
      stderrText += String(c);
    });
    const client = new Client({ name: "demo-box-test", version: "0.0.0" });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        (async () => {
          await client.connect(transport);
          assert.match(client.getInstructions() ?? "", /sandbox/i, "initialize carries instructions");

          const listed = await client.listTools();
          assert.deepEqual(
            listed.tools.map((t) => t.name).sort(),
            ["audit.explain", "memory.get", "memory.put", "message.read", "message.send", "spend"],
          );
          for (const tool of listed.tools) {
            assert.ok((tool.description ?? "").length > 0, `${tool.name} arrives without a description`);
          }

          const put = await client.callTool({
            name: "memory.put",
            arguments: {
              id: "demo-1",
              body: { note: "hello" },
              source: { kind: "test" },
              validUntilMs: Date.now() + 60_000,
            },
          });
          assert.equal(put.isError, false, text(put));
          const got = await client.callTool({ name: "memory.get", arguments: { id: "demo-1" } });
          assert.equal(got.isError, false, text(got));
          assert.match(text(got), /"note":"hello"/);

          const spend = await client.callTool({
            name: "spend",
            arguments: { amountMinor: 1250, currency: "USD", payee: "sample-merchant", reference: "demo-inv-1" },
          });
          assert.equal(spend.isError, true);
          assert.match(text(spend), /^deferred:approval-required:/);

          const queued = await client.callTool({
            name: "message.send",
            arguments: { to: "ops@example.com", text: "hello" },
          });
          assert.equal(queued.isError, false, text(queued));
          assert.match(text(queued), /"queued":true/);
          const blocked = await client.callTool({
            name: "message.send",
            arguments: { to: "ops@other.invalid", text: "hello" },
          });
          assert.equal(blocked.isError, true);
          assert.match(text(blocked), /^denied:egress-blocked:/);
        })(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`demo box hung (60s)\n${stderrText.slice(-2000)}`)), 60_000);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
      await client.close().catch(() => undefined);
      await transport.close().catch(() => undefined);
    }
    assert.doesNotMatch(stderrText, /Bearer /, "the token never reaches the child's stderr");
    assert.doesNotMatch(stderrText, /eyJ[A-Za-z0-9_-]{20,}/, "no JWT in the child's stderr");
  });
});
