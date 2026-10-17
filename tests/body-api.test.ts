import { strict as assert } from "node:assert";
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { parseLedger, type PolicyStore } from "../apps/panel/src/rail/parse.ts";
import { listen } from "../packages/body/src/server.ts";
import { sha256Canonical } from "../packages/proxy/src/hash.ts";
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
  it("GET /api/ledger and POST /api/contest/:ref require verax:audit", async () => {
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

      const read = await issuer.sign({ scope: "verax:read verax:audit" });
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

  it("a brain token cannot open the audit doors and read another subject's rows", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-audit-scope-"));
    const audience = "http://127.0.0.1/verax-audit-scope";
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
      const alice = await issuer.sign({ sub: "alice", scope: "verax:read verax:memory" });
      await rpc(`${base}/mcp`, alice, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "n1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
          _ref: "invoice-1",
        },
      });

      // A second brain on the same body. Nothing about its token says "operator".
      const bob = await issuer.sign({ sub: "bob", scope: "verax:read verax:memory" });
      const ledger = await fetch(`${base}/api/ledger?from=0&to=9999999999999`, {
        headers: { authorization: `Bearer ${bob}` },
      });
      assert.equal(ledger.status, 403, await ledger.clone().text());
      assert.equal((await ledger.text()).includes("invoice-1"), false);

      const ref = JSON.parse(
        readFileSync(join(stateDir, "decisions.jsonl"), "utf8").split("\n").filter((l) => l !== "")[0]!,
      ).claims.ref as string;
      const contest = await fetch(`${base}/api/contest/${encodeURIComponent(ref)}`, {
        method: "POST",
        headers: { authorization: `Bearer ${bob}` },
      });
      assert.equal(contest.status, 403);

      // The operator's own session carries the audit scope and still reads everything.
      const operator = await issuer.sign({ scope: "verax:read verax:audit" });
      const opened = await fetch(`${base}/api/ledger?from=0&to=9999999999999`, {
        headers: { authorization: `Bearer ${operator}` },
      });
      assert.equal(opened.status, 200);
      assert.equal((await opened.text()).includes("invoice-1"), true);
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
      const read = await issuer.sign({ scope: "verax:read verax:audit" });
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

  it("GET /api/ledger shows a bound row from its arguments and an edited row as unbound", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-ledger-bound-"));
    const audience = "http://127.0.0.1/verax-ledger-bound";
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
    const approvedArgs = { amountMinor: 1_000, currency: "TRY", payee: "ads-platform", reference: "verax:d-bound" };
    const approvedHash = sha256Canonical({ name: "spend", arguments: approvedArgs });
    const editedArgs = { ...approvedArgs, amountMinor: 5_000, reference: "verax:d-edited" };
    const row = (
      ref: string,
      args: Record<string, unknown>,
      copies: { amount: number; currency: string; payee: string },
    ) => ({
      ref,
      requestHash: approvedHash,
      subject: "spend",
      args,
      ruleId: "spend-true",
      ruleText: "Spends need operator approval.",
      inputsSummary: { count: 0, ids: [] },
      amount: copies.amount,
      currency: copies.currency,
      payee: copies.payee,
      createdAtMs: 1,
      expiresAtMs: 2,
      status: "approved",
      brain: "brain-1",
      allowRef: `a-${ref}`,
    });
    try {
      appendFileSync(
        join(stateDir, "decisions.jsonl"),
        [
          { claims: { ref: "d-bound", requestHash: approvedHash, timestampMs: 1 } },
          { claims: { ref: "d-edited", requestHash: approvedHash, timestampMs: 2 } },
        ]
          .map((line) => JSON.stringify(line))
          .join("\n") + "\n",
        "utf8",
      );
      writeFileSync(
        join(stateDir, "approvals.jsonl"),
        [
          row("d-bound", approvedArgs, { amount: 5_000, currency: "USD", payee: "other-shop" }),
          row("d-edited", editedArgs, { amount: 5_000, currency: "TRY", payee: "ads-platform" }),
        ]
          .map((line) => JSON.stringify(line))
          .join("\n") + "\n",
        "utf8",
      );
      const read = await issuer.sign({ scope: "verax:read verax:audit" });
      const res = await fetch(`http://127.0.0.1:${port}/api/ledger?from=0&to=9999999999999`, {
        headers: { authorization: `Bearer ${read}` },
      });
      assert.equal(res.status, 200, await res.clone().text());
      const body = (await res.json()) as {
        approvals: Array<{
          ref: string;
          bound?: boolean;
          amount?: unknown;
          currency?: unknown;
          payee?: unknown;
          args?: { amountMinor?: number; currency?: string; payee?: string };
        }>;
      };
      const bound = body.approvals.find((r) => r.ref === "d-bound");
      const edited = body.approvals.find((r) => r.ref === "d-edited");
      assert.equal(bound?.bound, true);
      assert.equal(bound?.amount, 1_000);
      assert.equal(bound?.currency, "TRY");
      assert.equal(bound?.payee, "ads-platform");
      assert.equal(bound?.args?.amountMinor, 1_000);
      assert.equal(edited?.bound, false);
      assert.equal(edited?.amount, undefined);
      assert.equal(edited?.currency, undefined);
      assert.equal(edited?.payee, undefined);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
