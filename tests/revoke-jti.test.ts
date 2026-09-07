import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

async function rpc(url: string, token: string, method: string, params: Record<string, unknown>) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return res.status;
}

describe("S3 jti revoke", () => {
  it("revoked jti is 401 and leaves no decision record", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-revoke-"));
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
    const mcp = `http://127.0.0.1:${port}/mcp`;
    try {
      const token = await issuer.sign({ jti: "tok-revoked-1", scope: "verax:read" });
      await issuer.revoke("tok-revoked-1", stateDir);
      const status = await rpc(mcp, token, "tools/list", {});
      assert.equal(status, 401);
      assert.equal(existsSync(join(stateDir, "decisions.jsonl")), false);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("missing jti is 401 and leaves no decision record", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-nojti-"));
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
    const mcp = `http://127.0.0.1:${port}/mcp`;
    try {
      const token = await issuer.sign({ omitJti: true, scope: "verax:read" });
      const status = await rpc(mcp, token, "tools/list", {});
      assert.equal(status, 401);
      assert.equal(existsSync(join(stateDir, "decisions.jsonl")), false);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("revoked jti reads no ledger counts from /healthz", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-revoke-healthz-"));
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
    try {
      const token = await issuer.sign({ jti: "tok-revoked-healthz", scope: "verax:read" });
      const before = await fetch(`http://127.0.0.1:${port}/healthz`, {
        headers: { authorization: `Bearer ${token}` },
      });
      // Control: the scope really does open the counts, so the assertion below
      // is not passing for the wrong reason.
      assert.equal(typeof ((await before.json()) as { decisions?: number }).decisions, "number");

      await issuer.revoke("tok-revoked-healthz", stateDir);
      const after = await fetch(`http://127.0.0.1:${port}/healthz`, {
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(after.status, 200);
      // A revoked token is an unauthenticated probe: liveness only, no counts,
      // no last-decision time, no lock state.
      assert.deepEqual(await after.json(), { ok: true });
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
