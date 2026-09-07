import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createConnection } from "node:net";

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

describe("healthz counts", () => {
  it("unauthenticated healthz answers ok only; decisions is absent", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-healthz-"));
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
    try {
      const health = await fetch(`http://127.0.0.1:${bodyPort}/healthz`);
      assert.equal(health.status, 200);
      const healthBody = (await health.json()) as Record<string, unknown>;
      assert.equal(healthBody.ok, true);
      assert.equal("decisions" in healthBody, false, JSON.stringify(healthBody));
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("counts require verax:audit; a brain read token and a scopeless token see ok only", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-healthz-audit-"));
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
    try {
      const brain = await issuer.sign({ scope: "verax:read" });
      const brainRes = await fetch(`http://127.0.0.1:${bodyPort}/healthz`, {
        headers: { authorization: `Bearer ${brain}` },
      });
      assert.equal(brainRes.status, 200);
      assert.deepEqual(await brainRes.json(), { ok: true });

      const none = await issuer.sign({ scope: "" });
      const noneRes = await fetch(`http://127.0.0.1:${bodyPort}/healthz`, {
        headers: { authorization: `Bearer ${none}` },
      });
      assert.equal(noneRes.status, 200);
      assert.deepEqual(await noneRes.json(), { ok: true });

      const panel = await issuer.sign({ scope: "verax:read verax:audit" });
      const panelRes = await fetch(`http://127.0.0.1:${bodyPort}/healthz`, {
        headers: { authorization: `Bearer ${panel}` },
      });
      assert.equal(panelRes.status, 200);
      const panelBody = (await panelRes.json()) as {
        ok?: boolean;
        decisions?: number;
        effects?: number;
        lastDecisionMs?: number | null;
        lock?: string;
      };
      assert.equal(panelBody.ok, true);
      assert.equal(panelBody.decisions, 0);
      assert.equal(panelBody.effects, 0);
      assert.equal(panelBody.lastDecisionMs, null);
      assert.equal(panelBody.lock, "held");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});

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
      const anonHealth = await fetch(`http://127.0.0.1:${bodyPort}/healthz`);
      assert.equal(anonHealth.status, 200);
      const anonBody = (await anonHealth.json()) as Record<string, unknown>;
      assert.equal(anonBody.ok, true);
      assert.equal("decisions" in anonBody, false);

      const readToken = await issuer.sign({ scope: "verax:read verax:audit" });
      const health = await fetch(`http://127.0.0.1:${bodyPort}/healthz`, {
        headers: { authorization: `Bearer ${readToken}` },
      });
      assert.equal(health.status, 200);
      const healthBody = (await health.json()) as {
        ok?: boolean;
        decisions?: number;
        effects?: number;
        lastDecisionMs?: number | null;
        lock?: string;
      };
      assert.equal(healthBody.ok, true);
      assert.equal(healthBody.decisions, 0);
      assert.equal(healthBody.effects, 0);
      assert.equal(healthBody.lastDecisionMs, null);
      assert.equal(healthBody.lock, "held");

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
      assert.deepEqual(tools.sort(), [
        "audit.explain",
        "memory.get",
        "memory.put",
        "message.read",
        "message.send",
        "spend",
      ]);

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

      const healthAfter = await fetch(`http://127.0.0.1:${bodyPort}/healthz`, {
        headers: { authorization: `Bearer ${readToken}` },
      });
      const afterBody = (await healthAfter.json()) as {
        decisions?: number;
        effects?: number;
        lastDecisionMs?: number | null;
        lock?: string;
      };
      const decisionLines = readFileSync(join(stateDir, "decisions.jsonl"), "utf8")
        .trim()
        .split("\n")
        .filter((l) => l !== "");
      const effectLines = readFileSync(join(stateDir, "effects.jsonl"), "utf8")
        .trim()
        .split("\n")
        .filter((l) => l !== "");
      assert.equal(afterBody.decisions, decisionLines.length);
      assert.equal(afterBody.effects, effectLines.length);
      const lastDecision = JSON.parse(decisionLines[decisionLines.length - 1] ?? "{}") as {
        claims: { timestampMs: number };
      };
      assert.equal(afterBody.lastDecisionMs, lastDecision.claims.timestampMs);
      assert.equal(afterBody.lock, "held");

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

function rawGet(port: number, hostHeader: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const sock = createConnection({ host: "127.0.0.1", port }, () => {
      sock.write(`GET /healthz HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`);
    });
    const chunks: Buffer[] = [];
    const finish = (err?: Error) => {
      sock.removeAllListeners();
      sock.destroy();
      if (err) {
        reject(err);
        return;
      }
      const text = Buffer.concat(chunks).toString("utf8");
      const status = Number(/HTTP\/1\.\d (\d+)/.exec(text)?.[1] ?? 0);
      resolve({ status, body: text });
    };
    sock.on("data", (c) => {
      chunks.push(c as Buffer);
      const text = Buffer.concat(chunks).toString("utf8");
      if (text.includes("\r\n\r\n")) finish();
    });
    sock.on("end", () => finish());
    sock.on("error", (err) => finish(err));
    sock.setTimeout(3_000, () => finish(new Error("timeout waiting for response")));
  });
}

describe("P1-3 broken Host", () => {
  it("returns 400 for Host: [ and does not emit unhandledRejection", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-host-"));
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
    const onUnhandled = (reason: unknown) => {
      throw reason instanceof Error ? reason : new Error(String(reason));
    };
    process.once("unhandledRejection", onUnhandled);
    try {
      const got = await Promise.race([
        rawGet(port, "["),
        new Promise<never>((_, reject) => {
          process.once("unhandledRejection", (reason) => {
            reject(reason instanceof Error ? reason : new Error(String(reason)));
          });
        }),
      ]);
      assert.equal(got.status, 400);
      assert.match(got.body, /bad-request/);
    } finally {
      process.removeListener("unhandledRejection", onUnhandled);
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
