import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { canonical } from "@cedulon/core";
import { sha256Canonical } from "@verax-ai/proxy";

import { runDoctor } from "../packages/body/src/doctor.ts";
import { renderToolEntry, runDownstreamPin } from "../packages/body/src/downstream-pin.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

/**
 * The operator's side of pinning, and the start that uses it. The pin command
 * shows a child's tool entries escaped, writes the manifest of exactly what it
 * showed only after a typed yes, and never edits the downstream document. A
 * body started with pins copies the manifest into its state directory and names
 * it in the start row. Doctor names a child with no pins and a command that
 * fetches a package with no version.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests", "fixtures", "downstream-echo.mjs");

const servers: HttpServer[] = [];
const dirs: string[] = [];
after(async () => {
  for (const s of servers) await new Promise<void>((r) => s.close(() => r()));
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function temp(): string {
  const d = mkdtempSync(join(tmpdir(), "verax-pins-cli-"));
  dirs.push(d);
  return d;
}

const INIT = {
  protocolVersion: "2024-11-05",
  capabilities: { tools: {} },
  serverInfo: { name: "child", version: "0.0.0" },
};

/** An HTTP child whose `tools/list` answer is the next item of `answers` (the last one repeats). */
async function child(answers: unknown[][]): Promise<string> {
  let listed = 0;
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
    let result: unknown = INIT;
    if (method === "tools/list") {
      result = { tools: answers[Math.min(listed, answers.length - 1)] };
      listed += 1;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? 1, result }));
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

const tool = (name: string, description = `reads ${name}`) => ({
  name,
  description,
  inputSchema: { type: "object", properties: { id: { type: "string" } } },
});

function io(answer: string) {
  const lines: string[] = [];
  return { lines, io: { out: (s: string) => void lines.push(s), ask: async () => answer } };
}

describe("verax downstream pin", { timeout: 60_000 }, () => {
  it("shows control, bidirectional and zero-width characters escaped, and the whole description", () => {
    const long = "x".repeat(5000);
    const shown = renderToolEntry(tool("a", `clear\u001b[2J\u001b]52;c;Zm9v\u0007 ‮ ​ ${long}`));
    assert.equal(shown.includes("\u001b"), false);
    assert.equal(shown.includes("‮"), false);
    assert.equal(shown.includes("​"), false);
    assert.ok(shown.includes("\\u001b"), shown.slice(0, 200));
    assert.ok(shown.includes("\\u202e"), shown.slice(0, 200));
    assert.ok(shown.includes(long), "the description is not cut");
  });

  it("writes nothing without a typed yes", async () => {
    const dir = temp();
    const file = join(dir, "downstream.json");
    writeFileSync(file, JSON.stringify({ prefix: "rea", url: await child([[tool("a")]]) }), "utf8");
    const { io: x } = io("no");
    const code = await runDownstreamPin({ file, prefix: "rea" }, x);
    assert.notEqual(code, 0);
    assert.equal(existsSync(join(dir, "definitions")), false);
  });

  it("pins exactly what it showed, prints the line, and leaves the document alone", async () => {
    const dir = temp();
    const file = join(dir, "downstream.json");
    const shownTools = [tool("a")];
    const url = await child([shownTools, [tool("a", "changed after it was shown")]]);
    const doc = JSON.stringify({ prefix: "rea", url });
    writeFileSync(file, doc, "utf8");
    const { lines, io: x } = io("yes");
    const code = await runDownstreamPin({ file, prefix: "rea" }, x);
    assert.equal(code, 0);
    assert.equal(readFileSync(file, "utf8"), doc);
    const written = readdirSync(join(dir, "definitions"));
    assert.equal(written.length, 1);
    const manifest = { v: 1, prefix: "rea", selected: null, tools: { a: shownTools[0] } };
    const digest = sha256Canonical(manifest);
    assert.equal(written[0], `${digest}.json`);
    assert.equal(readFileSync(join(dir, "definitions", written[0]!), "utf8"), canonical(manifest));
    assert.ok(lines.some((l) => l.includes(`"pins": "sha256:${digest}"`)), lines.join("\n"));
  });
});

describe("a start with pins", { timeout: 60_000 }, () => {
  it("copies the manifest into the state directory and names it in the start row", async () => {
    const work = temp();
    const stateDir = join(work, "state");
    mkdirSync(stateDir);
    const docs = join(work, "docs");
    mkdirSync(join(docs, "definitions"), { recursive: true });
    const ping = {
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
    };
    const manifest = { v: 1, prefix: "echo", selected: null, tools: { ping } };
    const digest = sha256Canonical(manifest);
    writeFileSync(join(docs, "definitions", `${digest}.json`), canonical(manifest), "utf8");
    const downstreamFile = join(docs, "downstream.json");
    writeFileSync(
      downstreamFile,
      JSON.stringify({ prefix: "echo", command: process.execPath, args: [fixture], trust: "same-user", pins: `sha256:${digest}` }),
      "utf8",
    );
    const policyFile = join(work, "policy.json");
    writeFileSync(policyFile, JSON.stringify({ version: 1, default: "deny", rules: [] }), "utf8");
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    try {
      const server = await listen({
        issuer: issuer.issuer,
        jwksUrl: issuer.jwksUrl,
        audience,
        stateDir,
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile,
        tlsTerminated: false,
        downstreamFile,
      });
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    } finally {
      await issuer.close();
    }
    assert.equal(readFileSync(join(stateDir, "definitions", `${digest}.json`), "utf8"), canonical(manifest));
    const rows = readFileSync(join(stateDir, "starts.jsonl"), "utf8").trim().split("\n");
    const last = JSON.parse(rows[rows.length - 1]!) as { downstream?: unknown };
    assert.deepEqual(last.downstream, [{ prefix: "echo", manifest: digest }]);
  });
});

describe("doctor on pins", () => {
  function checks(doc: unknown) {
    const dir = temp();
    const file = join(dir, "downstream.json");
    writeFileSync(file, JSON.stringify(doc), "utf8");
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
    );
  }

  it("names a child with no pins", () => {
    const c = checks({ prefix: "rea", url: "http://127.0.0.1:1/mcp" });
    assert.equal(c.find((x) => x.id === "downstream-unpinned:rea")?.level, "warn");
  });

  it("names a command that fetches a package with no version", () => {
    for (const args of [["some-mcp"], ["-y", "some-mcp"]]) {
      const c = checks({ prefix: "rea", command: "npx", args, trust: "same-user", pins: `sha256:${"a".repeat(64)}` });
      assert.equal(c.find((x) => x.id === "downstream-unversioned:rea")?.level, "warn", JSON.stringify(args));
    }
    const u = checks({ prefix: "rea", command: "uvx", args: ["some-mcp"], trust: "same-user" });
    assert.equal(u.find((x) => x.id === "downstream-unversioned:rea")?.level, "warn");
  });

  it("does not name a command whose package carries a version", () => {
    for (const [command, args] of [
      ["npx", ["some-mcp@1.2.3"]],
      ["npx", ["--package", "some-mcp@1.2.3", "some-mcp"]],
      ["uvx", ["--from", "some-mcp==1.2.3", "some-mcp"]],
      ["node", ["server.js"]],
    ] as const) {
      const c = checks({ prefix: "rea", command, args, trust: "same-user", pins: `sha256:${"a".repeat(64)}` });
      assert.equal(c.find((x) => x.id === "downstream-unversioned:rea"), undefined, `${command} ${args.join(" ")}`);
    }
  });
});
