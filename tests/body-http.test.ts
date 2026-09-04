import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

function noneJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.`;
}

async function rpc(
  url: string,
  token: string | null,
  method: string,
  params: Record<string, unknown>,
  id = 1,
): Promise<{ status: number; www?: string; json: Record<string, unknown> | null }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  let json: Record<string, unknown> | null = null;
  try {
    json = (await res.json()) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, www: res.headers.get("www-authenticate") ?? undefined, json };
}

describe("B5 identity and scope + e2e", () => {
  it("401 without a token leaves the ledger empty; scopes and algs are enforced", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-body-"));
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
    });
    const bodyPort = (server.address() as { port: number }).port;
    const mcp = `http://127.0.0.1:${bodyPort}/mcp`;
    try {
      const health = await fetch(`http://127.0.0.1:${bodyPort}/healthz`);
      assert.equal(health.status, 200);
      assert.deepEqual(await health.json(), { ok: true });

      const none = await rpc(mcp, null, "tools/call", { name: "memory.get", arguments: { id: "x" } });
      assert.equal(none.status, 401);
      assert.match(none.www ?? "", /resource_metadata=/);
      assert.equal(existsSync(join(stateDir, "decisions.jsonl")), false);

      const readOnly = await issuer.sign({ scope: "verax:read" });
      const putDenied = await rpc(mcp, readOnly, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "n1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });
      assert.equal(putDenied.status, 200);
      assert.match(JSON.stringify(putDenied.json), /denied:scope-missing:/);
      assert.match(readFileSync(join(stateDir, "decisions.jsonl"), "utf8"), /"decision":"deny"/);

      const full = await issuer.sign({ scope: "verax:read verax:memory" });
      const listed = await rpc(mcp, full, "tools/list", {});
      const tools = ((listed.json?.result as { tools?: { name: string }[] })?.tools ?? []).map((t) => t.name);
      assert.deepEqual(tools.sort(), ["audit.explain", "memory.get", "memory.put", "message.read"]);

      const putOk = await rpc(mcp, full, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "n1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });
      assert.equal(putOk.status, 200);
      assert.equal((putOk.json?.result as { isError?: boolean })?.isError, false);
      assert.match(readFileSync(join(stateDir, "effects.jsonl"), "utf8"), /memory\.put/);

      const got = await rpc(mcp, full, "tools/call", { name: "memory.get", arguments: { id: "n1" } });
      const gotText = (got.json?.result as { content?: { text?: string }[] })?.content?.[0]?.text ?? "";
      assert.match(gotText, /"id":"n1"/);

      const last = readFileSync(join(stateDir, "decisions.jsonl"), "utf8").trim().split("\n").at(-1) ?? "{}";
      const ref = (JSON.parse(last) as { claims: { ref: string } }).claims.ref;
      const explained = await rpc(mcp, full, "tools/call", { name: "audit.explain", arguments: { ref } });
      assert.match(JSON.stringify(explained.json), /effect-mismatch|conditional|decision/);

      const algNone = noneJwt({
        sub: "brain-1",
        iss: issuer.issuer,
        aud: audience,
        exp: Math.floor(Date.now() / 1000) + 60,
        scope: "verax:read",
      });
      assert.equal((await rpc(mcp, algNone, "tools/list", {})).status, 401);
      assert.equal((await rpc(mcp, await issuer.sign({ aud: "http://127.0.0.1:1" }), "tools/list", {})).status, 401);
      assert.equal((await rpc(mcp, await issuer.sign({ exp: "past" }), "tools/list", {})).status, 401);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
