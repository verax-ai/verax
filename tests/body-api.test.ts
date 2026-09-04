import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

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
  return (await res.json()) as Record<string, unknown>;
}

describe("ledger HTTP surfaces", () => {
  it("GET /api/ledger and POST /api/contest/:ref require verax:read", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-api-"));
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
    const port = (server.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    try {
      const none = await fetch(`${base}/api/ledger?from=0&to=99`);
      assert.equal(none.status, 401);

      const memoryOnly = await issuer.sign({ scope: "verax:memory" });
      const forbidden = await fetch(`${base}/api/ledger?from=0&to=99`, {
        headers: { authorization: `Bearer ${memoryOnly}` },
      });
      assert.equal(forbidden.status, 403);

      const read = await issuer.sign({ scope: "verax:read" });
      const full = await issuer.sign({ scope: "verax:read verax:memory" });
      await rpc(`${base}/mcp`, full, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "n1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });

      const ok = await fetch(`${base}/api/ledger?from=0&to=9999999999999`, {
        headers: { authorization: `Bearer ${read}` },
      });
      assert.equal(ok.status, 200);
      const body = (await ok.json()) as {
        decisions: { claims: { ref: string } }[];
        effects: unknown[];
        policy: { hash: string; document: { rules: unknown[] } };
      };
      assert.ok(Array.isArray(body.decisions));
      assert.ok(body.decisions.length >= 1);
      assert.ok(Array.isArray(body.effects));
      assert.equal(typeof body.policy.hash, "string");
      assert.ok(Array.isArray(body.policy.document.rules));

      const ref = body.decisions[0]?.claims.ref;
      assert.ok(ref);
      const contestNone = await fetch(`${base}/api/contest/${ref}`, { method: "POST" });
      assert.equal(contestNone.status, 401);
      const contest = await fetch(`${base}/api/contest/${encodeURIComponent(ref)}`, {
        method: "POST",
        headers: { authorization: `Bearer ${read}` },
      });
      assert.equal(contest.status, 200);
      const explained = (await contest.json()) as { reAuditedAt: number; finding: { label: string | null } };
      assert.equal(typeof explained.reAuditedAt, "number");
      assert.ok("finding" in explained);
      assert.ok(readFileSync(join(stateDir, "decisions.jsonl"), "utf8").includes(ref));
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
