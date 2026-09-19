import { strict as assert } from "node:assert";
import { createServer, type Server as HttpServer } from "node:http";
import { after, describe, it } from "node:test";

import { openDownstream } from "../packages/body/src/downstream.ts";

/**
 * `docs/THREAT_MODEL.md` says the tool server is hostile and names what it may
 * do: "lie, hang, or write outside the declared effect." The forward path
 * honours that — `callTool` carries `timeoutMs`. The attach path did not.
 *
 * A child that accepts the connection and then never answers `tools/list`
 * left `listen()` waiting with no deadline. That is worse than the failure it
 * was meant to have: a body that refuses to start says so and an operator can
 * read the reason, while a body that hangs looks like a machine problem.
 *
 * The same path trusted the list itself. A child answering with ten thousand
 * tools, or one tool carrying a megabyte of description, had all of it copied
 * into the registry and re-published on every `tools/list` the body serves.
 */

const sunucular: HttpServer[] = [];

after(async () => {
  for (const s of sunucular) await new Promise<void>((r) => s.close(() => r()));
});

/**
 * Starts an HTTP server that answers MCP requests with `cevap(method)`.
 *
 * Two details the handshake needs, both learned by watching it fail: the
 * response must echo the request's own `id`, and a `notifications/*` message
 * takes a bodyless 202 — answering it with a result stalls the client.
 */
async function cocukKur(cevap: (method: string) => unknown | Promise<unknown>): Promise<string> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let istek: { id?: unknown; method?: string } = {};
    try {
      istek = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as typeof istek;
    } catch {
      /* boş gövde */
    }
    const method = String(istek.method ?? "");
    if (method.startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    const sonuc = await cevap(method);
    if (sonuc === undefined) return; // hiç cevap verme: asılan çocuk
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: istek.id ?? 1, result: sonuc }));
  });
  sunucular.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

const INIT = {
  protocolVersion: "2024-11-05",
  capabilities: { tools: {} },
  serverInfo: { name: "dusman", version: "0.0.0" },
};

describe("düşman çocuk attach sırasında", { timeout: 60_000 }, () => {
  it("cevap vermeyen çocuk gövdeyi asmaz, süre dolunca reddeder", async () => {
    const url = await cocukKur((method) => (method === "initialize" ? INIT : undefined));
    const t0 = Date.now();
    await assert.rejects(
      () => openDownstream({ prefix: "asili", url, timeoutMs: 1500 }),
      /downstream-attach-timeout|timed out|timeout/i,
      "asılan çocuk için süre dolumu yok",
    );
    const gecen = Date.now() - t0;
    assert.ok(gecen < 20_000, `attach ${gecen} ms sürdü: süre dolumu uygulanmadı`);
  });

  it("binlerce araç döndüren çocuk kabul edilmez", async () => {
    const cok = Array.from({ length: 5000 }, (_, i) => ({
      name: `arac${i}`,
      description: "x",
      inputSchema: { type: "object" },
    }));
    const url = await cocukKur((method) => (method === "initialize" ? INIT : { tools: cok }));
    await assert.rejects(
      () => openDownstream({ prefix: "cok", url, timeoutMs: 5000 }),
      /downstream-too-many-tools/,
      "araç sayısına sınır yok",
    );
  });

  it("megabaytlık açıklama taşıyan araç kabul edilmez", async () => {
    const sisik = [
      {
        name: "sisik",
        description: "y".repeat(2_000_000),
        inputSchema: { type: "object" },
      },
    ];
    const url = await cocukKur((method) => (method === "initialize" ? INIT : { tools: sisik }));
    await assert.rejects(
      () => openDownstream({ prefix: "sisik", url, timeoutMs: 5000 }),
      /downstream-tool-too-large/,
      "araç boyutuna sınır yok",
    );
  });

  it("makul bir çocuk hâlâ bağlanır — sınırlar işi engellemez", async () => {
    const url = await cocukKur((method) =>
      method === "initialize"
        ? INIT
        : { tools: [{ name: "ping", description: "ok", inputSchema: { type: "object" } }] },
    );
    const oturum = await openDownstream({ prefix: "iyi", url, timeoutMs: 5000 });
    assert.deepEqual(oturum.tools.map((t) => t.name), ["iyi.ping"]);
    await oturum.close();
  });
});
