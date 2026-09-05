import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { parseLedger, type PolicyStore } from "../apps/panel/src/rail/parse.ts";
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

function policyDoc(putText: string): string {
  return `${JSON.stringify({
    version: 1,
    default: "deny",
    rules: [
      {
        id: "memory-put",
        tool: "memory.put",
        requires: ["verax:memory"],
        text: putText,
      },
    ],
  })}\n`;
}

describe("historical policy snapshots", () => {
  it("keeps the A sentence on an old decision after restart with policy B", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-policy-hist-"));
    const policyA = join(stateDir, "policy-a.json");
    const policyB = join(stateDir, "policy-b.json");
    writeFileSync(policyA, policyDoc("Policy A sentence for memory.put."));
    writeFileSync(policyB, policyDoc("Policy B sentence for memory.put."));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);

    const start = async (policyFile: string) => {
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
      return { server, base: `http://127.0.0.1:${port}` };
    };

    const first = await start(policyA);
    try {
      const full = await issuer.sign({ scope: "verax:read verax:memory" });
      await rpc(`${first.base}/mcp`, full, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "n1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });
    } finally {
      await new Promise<void>((resolve, reject) => {
        first.server.close((err) => (err ? reject(err) : resolve()));
      });
    }

    const second = await start(policyB);
    try {
      const read = await issuer.sign({ scope: "verax:read" });
      const res = await fetch(`${second.base}/api/ledger?from=0&to=9999999999999`, {
        headers: { authorization: `Bearer ${read}` },
      });
      assert.equal(res.status, 200);
      const body = (await res.json()) as {
        decisions: { claims: { subject: string; policyHash: string } }[];
        effects: unknown[];
        policies?: Record<string, { rules?: { tool: string; text: string }[] }>;
        policy?: { document: { rules?: { text: string }[] } };
      };
      const old = body.decisions.find((d) => d.claims.subject === "memory.put");
      assert.ok(old);
      const snap = body.policies?.[old.claims.policyHash];
      assert.ok(snap);
      const aRule = snap.rules?.find((r) => r.tool === "memory.put");
      assert.equal(aRule?.text, "Policy A sentence for memory.put.");
      assert.notEqual(aRule?.text, "Policy B sentence for memory.put.");

      const parsed = parseLedger(
        body.decisions.map((x) => JSON.stringify(x)).join("\n"),
        body.effects.map((x) => JSON.stringify(x)).join("\n"),
        (body.policies as PolicyStore | null) ?? null,
      );
      const action = parsed.find((a) => a.record.claims.subject === "memory.put");
      assert.equal(action?.rule && "text" in action.rule ? action.rule.text : null, "Policy A sentence for memory.put.");
    } finally {
      await new Promise<void>((resolve, reject) => {
        second.server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
