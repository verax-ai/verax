// On the pin screen a written escape and the character it names must not look
// the same. JSON lines (the tool entries) already double a backslash; the other
// lines (a child's error text, its stderr, the command's own sentences) did
// not, so a child that wrote the six characters `\`, `u`, `0`, `3`, `3`, `8`
// was shown exactly like one that sent U+0338. Built with String.fromCodePoint
// so this file stays ASCII.

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { renderToolEntry, runDownstreamPin } from "../packages/body/src/downstream-pin.ts";

const BACKSLASH = String.fromCharCode(0x5c);
const servers: HttpServer[] = [];
const dirs: string[] = [];
after(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function failingChild(message: string): Promise<string> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let msg: { id?: unknown; method?: string } = {};
    try {
      msg = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as typeof msg;
    } catch {
      /* empty body */
    }
    if (String(msg.method ?? "").startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? 1, error: { code: -32000, message } }));
  });
  servers.push(server);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () =>
    resolve(`http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`)));
}

async function pinScreen(message: string): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-pin-backslash-"));
  dirs.push(dir);
  const file = join(dir, "downstream.json");
  writeFileSync(file, JSON.stringify({ prefix: "rea", url: await failingChild(message), timeoutMs: 5000 }), "utf8");
  const lines: string[] = [];
  const code = await runDownstreamPin({ file, prefix: "rea" }, { out: (s) => lines.push(s), ask: async () => "no" });
  assert.notEqual(code, 0);
  return lines.join("");
}

describe("verax downstream pin: a written escape is not shown as the character", () => {
  it("a child's error text that spells \\u0338 is shown with its backslash doubled", { timeout: 20_000 }, async () => {
    const shown = await pinScreen(`stop A${BACKSLASH}u0338 here`);
    assert.ok(shown.includes(`A${BACKSLASH}${BACKSLASH}u0338 here`), JSON.stringify(shown));
  });

  it("the character itself is shown as one escape", { timeout: 20_000 }, async () => {
    const shown = await pinScreen(`stop A${String.fromCodePoint(0x338)} here`);
    assert.ok(shown.includes(`A${BACKSLASH}u0338 here`), JSON.stringify(shown));
    assert.equal(shown.includes(`${BACKSLASH}${BACKSLASH}u0338`), false, JSON.stringify(shown));
  });

  it("the two are not shown the same", { timeout: 20_000 }, async () => {
    const written = await pinScreen(`stop A${BACKSLASH}u0338 here`);
    const real = await pinScreen(`stop A${String.fromCodePoint(0x338)} here`);
    assert.notEqual(written.replace(/\d+/g, "N"), real.replace(/\d+/g, "N"));
  });

  it("a tool entry (a JSON line) keeps one level of escaping for a backslash", () => {
    const entry = renderToolEntry({ name: "a", description: `C:${BACKSLASH}x`, inputSchema: { type: "object" } });
    assert.ok(entry.includes(`C:${BACKSLASH}${BACKSLASH}x`), entry);
    assert.equal(entry.includes(`C:${BACKSLASH}${BACKSLASH}${BACKSLASH}${BACKSLASH}x`), false, entry);
  });
});
