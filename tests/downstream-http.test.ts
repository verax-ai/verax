import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { parseDownstreamDocument } from "../packages/body/src/downstream.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

/**
 * The stdio attach cannot reach the servers this is actually for: a live
 * Conarium or Tugra runs behind a URL, and the local stdio Conarium holds a
 * single-writer audit lock that a body spawning its own copy would collide
 * with. This file covers the HTTP transport: same document, same prefixing,
 * same gate, different way in.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests", "fixtures", "downstream-http-child.mjs");

const LOOKUP_POLICY = JSON.stringify({
  version: 1,
  default: "deny",
  rules: [
    {
      id: "kb-lookup",
      tool: "kb.lookup",
      requires: ["verax:read"],
      text: "Calling the downstream lookup needs the read scope.",
    },
  ],
});

const cocuklar: ChildProcess[] = [];

after(() => {
  for (const c of cocuklar) c.kill();
});

/** Starts the fixture child and waits for the URL it prints. */
async function cocukBaslat(env: Record<string, string> = {}): Promise<string> {
  const child = spawn(process.execPath, [fixture], {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  cocuklar.push(child);
  return await new Promise<string>((resolve, reject) => {
    const zamanAsimi = setTimeout(() => reject(new Error("çocuk URL yazmadı")), 20_000);
    let tampon = "";
    child.stdout?.on("data", (d: Buffer) => {
      tampon += d.toString("utf8");
      const m = /url=(\S+)/.exec(tampon);
      if (m) {
        clearTimeout(zamanAsimi);
        resolve(m[1]!);
      }
    });
    child.once("error", reject);
  });
}

async function rpc(
  url: string,
  token: string,
  method: string,
  params: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return (await res.json().catch(() => null)) as Record<string, unknown> | null;
}

async function withBody(
  downstream: unknown,
  fn: (ctx: { mcp: string; stateDir: string; token: () => Promise<string> }) => Promise<void>,
): Promise<void> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-http-down-"));
  const policyFile = join(stateDir, "policy.json");
  writeFileSync(policyFile, `${LOOKUP_POLICY}\n`, "utf8");
  const downstreamFile = join(stateDir, "downstream.json");
  writeFileSync(downstreamFile, `${JSON.stringify(downstream)}\n`, "utf8");
  const audience = "http://127.0.0.1/verax-test";
  const issuer = await startDevIssuer(0, audience);
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
  const port = (server.address() as { port: number }).port;
  try {
    await fn({
      mcp: `http://127.0.0.1:${port}/mcp`,
      stateDir,
      token: () => issuer.sign({ scope: "verax:read" }),
    });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await issuer.close();
  }
}

describe("downstream over HTTP", { timeout: 60_000 }, () => {
  it("attaches a child named by url and publishes its tool under the prefix", async () => {
    const url = await cocukBaslat();
    await withBody({ prefix: "kb", url }, async ({ mcp, token }) => {
      const listed = await rpc(mcp, await token(), "tools/list", {});
      const tools = ((listed?.result as { tools?: { name: string; description?: string }[] })?.tools ?? []);
      const names = tools.map((t) => t.name);
      assert.ok(names.includes("kb.lookup"), names.join(","));
      assert.match(tools.find((t) => t.name === "kb.lookup")?.description ?? "", /found/i);
    });
  });

  it("forwards a call through the gate and records it under the prefixed name", async () => {
    const url = await cocukBaslat();
    await withBody({ prefix: "kb", url }, async ({ mcp, stateDir, token }) => {
      const called = await rpc(mcp, await token(), "tools/call", {
        name: "kb.lookup",
        arguments: { q: "fatura-2026-09" },
      });
      const result = called?.result as { isError?: boolean; content?: { text?: string }[] };
      assert.equal(result?.isError, false, JSON.stringify(called));
      const text = (result?.content ?? []).map((c) => c.text ?? "").join("");
      assert.match(text, /"found":true/);
      assert.match(text, /fatura-2026-09/);

      const { readFileSync } = await import("node:fs");
      const decisions = readFileSync(join(stateDir, "decisions.jsonl"), "utf8");
      assert.match(decisions, /"subject":"kb\.lookup"/);
      const effects = readFileSync(join(stateDir, "effects.jsonl"), "utf8");
      assert.match(effects, /"effectClass":"kb\.lookup"/);
    });
  });

  it("sends the operator's headers to the child, and the body's own token never goes", async () => {
    const url = await cocukBaslat({ VERAX_CHILD_TOKEN: "cocuk-anahtari" });
    await withBody(
      { prefix: "kb", url, headers: { Authorization: "Bearer cocuk-anahtari" } },
      async ({ mcp, token }) => {
        const called = await rpc(mcp, await token(), "tools/call", {
          name: "kb.lookup",
          arguments: { q: "yetkili" },
        });
        const result = called?.result as { isError?: boolean; content?: { text?: string }[] };
        assert.equal(result?.isError, false, JSON.stringify(called));
        assert.match((result?.content ?? []).map((c) => c.text ?? "").join(""), /"found":true/);
      },
    );
  });

  it("a child that wants a header the document does not carry cannot attach", async () => {
    const url = await cocukBaslat({ VERAX_CHILD_TOKEN: "baska-anahtar" });
    const stateDir = mkdtempSync(join(tmpdir(), "verax-http-down-401-"));
    const policyFile = join(stateDir, "policy.json");
    writeFileSync(policyFile, `${LOOKUP_POLICY}\n`, "utf8");
    const downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(downstreamFile, `${JSON.stringify({ prefix: "kb", url })}\n`, "utf8");
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    let started: Awaited<ReturnType<typeof listen>> | null = null;
    try {
      await assert.rejects(async () => {
        started = await listen({
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
      }, /downstream-attach-failed:kb:/);
    } finally {
      if (started !== null) {
        await new Promise<void>((resolve) => {
          (started as unknown as { close: (cb: () => void) => void }).close(() => resolve());
        });
      }
      await issuer.close();
    }
  });

  it("the document must name exactly one way in: url or command, never both or neither", () => {
    assert.throws(
      () => parseDownstreamDocument(JSON.stringify({ prefix: "kb", url: "http://x/mcp", command: "node" })),
      /downstream-transport-ambiguous/,
    );
    assert.throws(() => parseDownstreamDocument(JSON.stringify({ prefix: "kb" })), /downstream-transport-missing/);
    assert.throws(
      () => parseDownstreamDocument(JSON.stringify({ prefix: "kb", url: "ftp://x/mcp" })),
      /downstream-url-invalid/,
    );
    const spec = parseDownstreamDocument(JSON.stringify({ prefix: "kb", url: "https://x.example/mcp" }))[0]!;
    assert.equal(spec.url, "https://x.example/mcp");
    assert.equal(spec.command, undefined);
  });
});
