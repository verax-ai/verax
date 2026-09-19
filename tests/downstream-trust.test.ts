import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import {
  openDownstream,
  parseDownstreamDocument,
  parseDownstreamJson,
} from "../packages/body/src/downstream.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests", "fixtures", "downstream-echo.mjs");

const sunucular: HttpServer[] = [];

after(async () => {
  for (const s of sunucular) await new Promise<void>((r) => s.close(() => r()));
});

/**
 * Starts an HTTP server that counts every request. Pattern from
 * `tests/downstream-hostile-child.test.ts` (`cocukKur`): echo the request
 * id, 202 on `notifications/*`.
 */
async function cocukKur(onRequest: () => void): Promise<string> {
  const server = createServer(async (req, res) => {
    onRequest();
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let istek: { id?: unknown; method?: string } = {};
    try {
      istek = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as typeof istek;
    } catch {
      /* empty body */
    }
    const method = String(istek.method ?? "");
    if (method.startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        jsonrpc: "2.0",
        id: istek.id ?? 1,
        result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "probe", version: "0.0.0" } },
      }),
    );
  });
  sunucular.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`;
}

describe("downstream stdio trust ack", { timeout: 60_000 }, () => {
  it("stdio without trust is downstream-stdio-trust-required", () => {
    assert.throws(
      () => parseDownstreamJson(JSON.stringify({ prefix: "kb", command: "node" })),
      /downstream-stdio-trust-required/,
    );
  });

  it("stdio with trust same-user parses", () => {
    const spec = parseDownstreamJson(
      JSON.stringify({ prefix: "kb", command: "node", trust: "same-user" }),
    );
    assert.equal(spec.trust, "same-user");
  });

  it("trust other than same-user is downstream-trust-invalid", () => {
    for (const trust of ["root", true, ""] as const) {
      assert.throws(
        () => parseDownstreamJson(JSON.stringify({ prefix: "kb", command: "node", trust })),
        /downstream-trust-invalid/,
      );
    }
  });

  it("url child with trust is downstream-trust-invalid", () => {
    assert.throws(
      () =>
        parseDownstreamJson(
          JSON.stringify({ prefix: "kb", url: "http://127.0.0.1:9/mcp", trust: "same-user" }),
        ),
      /downstream-trust-invalid/,
    );
  });

  it("url child without trust parses", () => {
    const spec = parseDownstreamJson(JSON.stringify({ prefix: "kb", url: "http://127.0.0.1:9/mcp" }));
    assert.equal(spec.url, "http://127.0.0.1:9/mcp");
    assert.equal(spec.trust, undefined);
  });

  it("structural error is reported before a missing trust ack", () => {
    assert.throws(
      () => parseDownstreamJson(JSON.stringify({ prefix: "kb", command: "node", env: { K: 1 } })),
      /downstream-env-invalid/,
    );
  });

  it("openDownstream without trust does not spawn the child", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-trust-trace-"));
    const izDosyasi = join(dir, "echo-trace.jsonl");
    await assert.rejects(
      () =>
        openDownstream({
          prefix: "echo",
          command: process.execPath,
          args: [fixture],
          env: { VERAX_ECHO_TRACE: izDosyasi },
        }),
      /downstream-stdio-trust-required/,
    );
    assert.equal(existsSync(izDosyasi), false);
  });

  it("listen refuses a stdio child without trust and the body does not come up", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-trust-listen-"));
    const policyFile = join(stateDir, "policy.json");
    writeFileSync(policyFile, `${JSON.stringify({ version: 1, default: "deny", rules: [] })}\n`, "utf8");
    const downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(
      downstreamFile,
      `${JSON.stringify({ prefix: "echo", command: process.execPath, args: [fixture] })}\n`,
      "utf8",
    );
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
      }, /downstream-stdio-trust-required/);
    } finally {
      if (started !== null) {
        await new Promise<void>((resolve) => {
          (started as unknown as { close: (cb: () => void) => void }).close(() => resolve());
        });
      }
      await issuer.close();
    }
  });

  it("an array document is refused before any child is opened", async () => {
    let hits = 0;
    const url = await cocukKur(() => {
      hits += 1;
    });
    assert.throws(
      () =>
        parseDownstreamDocument(
          JSON.stringify([
            { prefix: "remote", url },
            { prefix: "echo", command: "node" },
          ]),
        ),
      /downstream-stdio-trust-required/,
    );
    assert.equal(hits, 0);
  });

  it("names WHICH child lacks the acknowledgement, so a longer document is not a guessing game", () => {
    // Added at the gate: the first version threw the bare code, and with two
    // children in one document the operator could not tell which to fix.
    assert.throws(
      () =>
        parseDownstreamDocument(
          JSON.stringify([
            { prefix: "kb", command: "node", trust: "same-user" },
            { prefix: "raw", command: "node" },
          ]),
        ),
      /downstream-stdio-trust-required:raw/,
    );
    // The name is the operator's own prefix; nothing else about the child.
    assert.throws(
      () => parseDownstreamJson(JSON.stringify({ prefix: "raw", command: "node", args: ["--secret-flag"] })),
      (err: Error) => /:raw$/.test(err.message) && !err.message.includes("--secret-flag") && !err.message.includes("node"),
    );
  });
});
