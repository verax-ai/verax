import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { openDownstream } from "../packages/body/src/downstream.ts";

/**
 * R26, left open: the bound on a downstream tool is applied after the child's
 * answer has been read and parsed, and nothing bounded the answer itself.
 * Measured before this change: an HTTP child answering `tools/call` with
 * 50 MiB was accepted and the body's memory went from 84 to 433 MiB; a 50 MiB
 * `tools/list` was read whole before `downstream-tool-too-large` refused it.
 * A stdio child was already cut at the MCP client's own 10 MiB buffer, with
 * no name for what happened ("Connection closed").
 *
 * One message from a child is now at most 10 MiB on either transport, and a
 * larger one is `downstream-message-too-large`.
 */

const MIB = 1024 * 1024;
const OVER = 12 * MIB;
const UNDER = 9 * MIB;
const INIT = {
  protocolVersion: "2024-11-05",
  capabilities: { tools: {} },
  serverInfo: { name: "big", version: "0.0.0" },
};
const TOOL = { name: "echo", description: "says it back", inputSchema: { type: "object" } };
const caller = { brain: "brain-1", scopes: new Set<string>() };

const servers: HttpServer[] = [];
const dirs: string[] = [];

after(async () => {
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise<void>((r) => s.close(() => r()));
  }
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

type Answer = { result: unknown; sse?: boolean };

/** An HTTP MCP server that answers each method with `answer(method)`, as JSON or as one SSE event. */
async function httpChild(answer: (method: string) => Answer): Promise<string> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let msg: { id?: unknown; method?: string } = {};
    try {
      msg = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as typeof msg;
    } catch {
      /* a GET or DELETE carries no body */
    }
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }
    const method = String(msg.method ?? "");
    if (method.startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    const { result, sse } = answer(method);
    const body = JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? 1, result });
    if (sse) {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(`event: message\ndata: ${body}\n\n`);
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

function textResult(bytes: number): unknown {
  return { content: [{ type: "text", text: "x".repeat(bytes) }] };
}

/** A stdio MCP server whose `tools/list` or `tools/call` answer is one line of `bytes`. */
function stdioChild(where: "tools/list" | "tools/call", bytes: number): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-r26-bound-"));
  dirs.push(dir);
  const script = join(dir, "child.mjs");
  writeFileSync(
    script,
    `import { createInterface } from "node:readline";
const INIT = ${JSON.stringify(INIT)};
const TOOL = ${JSON.stringify(TOOL)};
const big = "x".repeat(${bytes});
const say = (id, result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\\n");
createInterface({ input: process.stdin }).on("line", (line) => {
  const msg = JSON.parse(line);
  if (msg.id === undefined) return;
  if (msg.method === "initialize") return say(msg.id, INIT);
  if (msg.method === "tools/list") return say(msg.id, { tools: [${where === "tools/list" ? "{ ...TOOL, description: big }" : "TOOL"}] });
  if (msg.method === "tools/call") return say(msg.id, { content: [{ type: "text", text: ${where === "tools/call" ? "big" : '"ok"'} }] });
});
`,
    "utf8",
  );
  return script;
}

async function callOnce(spec: Parameters<typeof openDownstream>[0]): Promise<{ ms: number; text: string }> {
  const session = await openDownstream(spec);
  try {
    const t0 = Date.now();
    const out = await session.tools[0]!.fn({ name: `${spec.prefix}.echo`, arguments: {} }, caller, "r-1");
    return { ms: Date.now() - t0, text: out.content.map((c) => c.text).join("") };
  } finally {
    await session.close();
  }
}

describe("R26 one message from a downstream child is bounded", { timeout: 120_000 }, () => {
  it("HTTP: a tools/call answer over the bound is refused by name, not kept", async () => {
    const url = await httpChild((m) =>
      m === "initialize" ? { result: INIT } : m === "tools/list" ? { result: { tools: [TOOL] } } : { result: textResult(OVER) },
    );
    await assert.rejects(
      () => callOnce({ prefix: "big", url, timeoutMs: 15_000 }),
      /downstream-call-failed:big\.echo:downstream-message-too-large/,
    );
  });

  it("HTTP: an answer sent as one SSE event over the bound is refused by name, before the call's timeout", async () => {
    const url = await httpChild((m) =>
      m === "initialize"
        ? { result: INIT }
        : m === "tools/list"
          ? { result: { tools: [TOOL] } }
          : { result: textResult(OVER), sse: true },
    );
    const t0 = Date.now();
    await assert.rejects(
      () => callOnce({ prefix: "big", url, timeoutMs: 15_000 }),
      /downstream-call-failed:big\.echo:downstream-message-too-large/,
    );
    assert.ok(Date.now() - t0 < 10_000, "the refusal waited for the call's timeout");
  });

  it("HTTP: a tools/list answer over the bound stops the attach by name", async () => {
    const url = await httpChild((m) =>
      m === "initialize" ? { result: INIT } : { result: { tools: [{ ...TOOL, description: "d".repeat(OVER) }] } },
    );
    await assert.rejects(() => openDownstream({ prefix: "big", url, timeoutMs: 15_000 }), /^Error: downstream-message-too-large:big$/);
  });

  it("HTTP: an answer under the bound still comes back, as JSON and as an SSE event", async () => {
    for (const sse of [false, true]) {
      const url = await httpChild((m) =>
        m === "initialize"
          ? { result: INIT }
          : m === "tools/list"
            ? { result: { tools: [TOOL] } }
            : { result: textResult(UNDER), sse },
      );
      const got = await callOnce({ prefix: "ok", url, timeoutMs: 30_000 });
      assert.equal(got.text.length, UNDER, sse ? "sse" : "json");
    }
  });

  it("HTTP: after an oversized answer the child stays detached and says why", async () => {
    let calls = 0;
    const url = await httpChild((m) => {
      if (m === "initialize") return { result: INIT };
      if (m === "tools/list") return { result: { tools: [TOOL] } };
      calls += 1;
      return { result: calls === 1 ? textResult(OVER) : textResult(8) };
    });
    const session = await openDownstream({ prefix: "big", url, timeoutMs: 15_000 });
    try {
      const call = () => session.tools[0]!.fn({ name: "big.echo", arguments: {} }, caller, "r-1");
      await assert.rejects(call, /downstream-message-too-large/);
      await assert.rejects(call, /downstream-call-failed:big\.echo:downstream-message-too-large/);
      assert.equal(calls, 1, "a detached child was called again");
    } finally {
      await session.close();
    }
  });

  it("stdio: a tools/call line over the bound is refused by the same name", async () => {
    const script = stdioChild("tools/call", OVER);
    await assert.rejects(
      () => callOnce({ prefix: "big", command: process.execPath, args: [script], trust: "same-user", timeoutMs: 15_000 }),
      /downstream-call-failed:big\.echo:downstream-message-too-large/,
    );
  });

  it("stdio: a tools/list line over the bound stops the attach by the same name", async () => {
    const script = stdioChild("tools/list", OVER);
    await assert.rejects(
      () => openDownstream({ prefix: "big", command: process.execPath, args: [script], trust: "same-user", timeoutMs: 15_000 }),
      /^Error: downstream-message-too-large:big$/,
    );
  });

  it("stdio: a line under the bound still comes back", async () => {
    const script = stdioChild("tools/call", UNDER);
    const got = await callOnce({
      prefix: "ok",
      command: process.execPath,
      args: [script],
      trust: "same-user",
      timeoutMs: 30_000,
    });
    assert.equal(got.text.length, UNDER);
  });
});
