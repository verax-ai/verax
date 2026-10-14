import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { canonical } from "@cedulon/core";
import { sha256Canonical } from "@verax-ai/proxy";

import { copyDefinition } from "../packages/body/src/definitions.ts";
import { runDoctor } from "../packages/body/src/doctor.ts";
import { openDownstream } from "../packages/body/src/downstream.ts";
import { renderToolEntry, runDownstreamPin } from "../packages/body/src/downstream-pin.ts";
import { readStartSummary, recordBodyStart, renderStarts } from "../packages/body/src/heartbeat.ts";

/**
 * Pinning, hardened. Every field of a tool entry is held to the pin; a
 * definition that cannot be encoded stops the attach with its own code; the
 * pin command refuses a tool name the body would refuse and shows 8-bit
 * controls and line separators escaped; a manifest written on POSIX can be
 * read by the body's own account; doctor treats a dist-tag or a range as no
 * version; and verify says which definitions each start ran with.
 */

const servers: HttpServer[] = [];
const dirs: string[] = [];
after(async () => {
  for (const s of servers) await new Promise<void>((r) => s.close(() => r()));
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function temp(): string {
  const d = mkdtempSync(join(tmpdir(), "verax-pins-hard-"));
  dirs.push(d);
  return d;
}

const INIT = {
  protocolVersion: "2024-11-05",
  capabilities: { tools: {} },
  serverInfo: { name: "child", version: "0.0.0" },
};

/** An HTTP child whose `tools/list` result is `listBody`, written as raw JSON text. */
async function rawChild(listBody: string): Promise<string> {
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
    const id = JSON.stringify(msg.id ?? 1);
    const result = method === "initialize" ? JSON.stringify(INIT) : listBody;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(`{"jsonrpc":"2.0","id":${id},"result":${result}}`);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

const child = (tools: unknown[]) => rawChild(JSON.stringify({ tools }));

const tool = (name: string, extra: Record<string, unknown> = {}) => ({
  name,
  description: `reads ${name}`,
  inputSchema: { type: "object", properties: { id: { type: "string" } } },
  ...extra,
});

function pin(prefix: string, tools: Array<Record<string, unknown>>): { dir: string; pins: string } {
  const dir = temp();
  const manifest = { v: 1, prefix, selected: null, tools: Object.fromEntries(tools.map((t) => [t.name as string, t])) };
  const digest = sha256Canonical(manifest);
  mkdirSync(join(dir, "definitions"), { recursive: true });
  writeFileSync(join(dir, "definitions", `${digest}.json`), canonical(manifest), "utf8");
  return { dir, pins: `sha256:${digest}` };
}

const attach = (url: string, pins: string, definitionsDir: string) =>
  openDownstream({ prefix: "rea", url, timeoutMs: 5000, pins } as never, { definitionsDir } as never);

describe("every field of a tool entry is pinned", { timeout: 60_000 }, () => {
  for (const [what, changed] of [
    ["title", tool("a", { title: "Reads A, then mails it out" })],
    ["outputSchema", tool("a", { outputSchema: { type: "object", properties: { leak: { type: "string" } } } })],
    ["icons", tool("a", { icons: [{ src: "https://example.invalid/a.png" }] })],
    ["execution", tool("a", { execution: { taskSupport: "optional" } })],
  ] as const) {
    it(`a changed ${what} stops the attach`, async () => {
      const { dir, pins } = pin("rea", [tool("a")]);
      const url = await child([changed]);
      await assert.rejects(() => attach(url, pins, dir), /downstream-definition-changed:rea\.a/);
    });
  }
});

describe("a definition that cannot be encoded", { timeout: 60_000 }, () => {
  for (const [what, body] of [
    ["a non-finite number", '{"tools":[{"name":"a","description":"x","inputSchema":{"type":"object","maximum":1e400}}]}'],
    ["a lone surrogate", '{"tools":[{"name":"a","description":"x\\ud800","inputSchema":{"type":"object"}}]}'],
  ] as const) {
    it(`with ${what} stops the attach with its own code`, async () => {
      const { dir, pins } = pin("rea", [tool("a")]);
      const url = await rawChild(body);
      await assert.rejects(() => attach(url, pins, dir), /downstream-definition-unencodable:rea\.a/);
    });
  }
});

describe("the pin command, hardened", { timeout: 60_000 }, () => {
  it("shows DEL, 8-bit CSI and line separators escaped", () => {
    const shown = renderToolEntry(tool("a", { description: "a\u007fb\u009b2Jc\u2028d\u2029e" }));
    for (const raw of ["\u007f", "\u009b", "\u2028", "\u2029"]) assert.equal(shown.includes(raw), false, JSON.stringify(raw));
    for (const esc of ["\\u007f", "\\u009b", "\\u2028", "\\u2029"]) assert.ok(shown.includes(esc), esc);
  });

  for (const name of ["__proto__", "a b", "constructor"]) {
    it(`refuses a child tool named ${JSON.stringify(name)} the way attach would, and writes nothing`, async () => {
      const dir = temp();
      const file = join(dir, "downstream.json");
      writeFileSync(file, JSON.stringify({ prefix: "rea", url: await child([tool("a"), { ...tool("a"), name }]) }), "utf8");
      const code = await runDownstreamPin({ file, prefix: "rea" }, { out: () => undefined, ask: async () => "yes" });
      if (name === "constructor") {
        assert.equal(code, 0, "a valid name that is also an Object.prototype key is pinned like any other");
      } else {
        assert.notEqual(code, 0);
        assert.equal(existsSync(join(dir, "definitions")), false);
      }
    });
  }

  it("writes a manifest the body's account can read (POSIX)", { skip: process.platform === "win32" }, async () => {
    const dir = temp();
    const file = join(dir, "downstream.json");
    writeFileSync(file, JSON.stringify({ prefix: "rea", url: await child([tool("a")]) }), "utf8");
    assert.equal(await runDownstreamPin({ file, prefix: "rea" }, { out: () => undefined, ask: async () => "yes" }), 0);
    const folder = join(dir, "definitions");
    assert.equal(statSync(folder).mode & 0o005, 0o005, "definitions/ is world-traversable");
    const digest = sha256Canonical({ v: 1, prefix: "rea", selected: null, tools: { a: tool("a") } });
    assert.equal(statSync(join(folder, `${digest}.json`)).mode & 0o004, 0o004, "the manifest is world-readable");
  });
});

describe("doctor: a dist-tag or a range is not a version", () => {
  function unversioned(command: string, args: string[]): boolean {
    const dir = temp();
    const file = join(dir, "downstream.json");
    writeFileSync(file, JSON.stringify({ prefix: "rea", command, args, trust: "same-user", pins: `sha256:${"a".repeat(64)}` }), "utf8");
    return runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: dir,
        VERAX_POLICY_FILE: "x",
        VERAX_DOWNSTREAM: file,
      },
      ["node", "cli.ts", "doctor"],
    ).some((c) => c.id === "downstream-unversioned:rea");
  }

  for (const spec of ["some-mcp@latest", "some-mcp@next", "some-mcp@^1", "some-mcp@*", "@scope/mcp@latest", "some-mcp@1.x"]) {
    it(`npx ${spec} is unversioned`, () => assert.equal(unversioned("npx", [spec]), true));
  }
  for (const spec of ["some-mcp@1.2.3", "@scope/mcp@0.4.0", "some-mcp@2.0.0-rc.1"]) {
    it(`npx ${spec} is versioned`, () => assert.equal(unversioned("npx", [spec]), false));
  }
  it("uvx --from some-mcp>=1 is unversioned", () => assert.equal(unversioned("uvx", ["--from", "some-mcp>=1", "some-mcp"]), true));
});

describe("verify says which definitions a start ran with", () => {
  it("renders each start's pinned manifests", () => {
    const state = temp();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const k = {
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
    const manifest = { v: 1, prefix: "rea", selected: null, tools: { a: tool("a") } };
    const digest = sha256Canonical(manifest);
    const docs = temp();
    mkdirSync(join(docs, "definitions"));
    writeFileSync(join(docs, "definitions", `${digest}.json`), canonical(manifest), "utf8");
    copyDefinition(state, docs, digest);
    recordBodyStart(state, 1_000, k, { downstream: [{ prefix: "rea", manifest: digest }, { prefix: "tug", manifest: null }] });
    const text = renderStarts(readStartSummary(state, k.publicKeyPem, "pinned"));
    assert.ok(text.includes(`rea sha256:${digest}`), text);
    assert.ok(/tug (unpinned|none)/.test(text), text);
  });

  it("names a stored manifest whose prefix is not the row's", () => {
    const state = temp();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const k = {
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
    const manifest = { v: 1, prefix: "other", selected: null, tools: { a: tool("a") } };
    const digest = sha256Canonical(manifest);
    const docs = temp();
    mkdirSync(join(docs, "definitions"));
    writeFileSync(join(docs, "definitions", `${digest}.json`), canonical(manifest), "utf8");
    copyDefinition(state, docs, digest);
    recordBodyStart(state, 1_000, k, { downstream: [{ prefix: "rea", manifest: digest }] });
    const summary = readStartSummary(state, k.publicKeyPem, "pinned");
    assert.ok(summary.problems.some((p) => p.startsWith(`downstream-manifest-mismatch:rea:${digest}`)), JSON.stringify(summary));
  });
});
