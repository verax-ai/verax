import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createProxy, explain, FileLedger, loadPolicy } from "@verax-ai/proxy";

import { createBodyServices } from "../packages/body/src/wiring.ts";
import { runDoctor } from "../packages/body/src/doctor.ts";
import { listen } from "../packages/body/src/server.ts";
import { diskProbe } from "../packages/proxy/src/disk.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "../packages/proxy/tests/helpers.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const policy = loadPolicy(readFileSync(policyFile, "utf8"));

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("pilot drills", () => {
  it("1 stolen token: a revoked jti is 401 on MCP and /api/* and a liveness-only /healthz", async () => {
    // Expect: revoked jti cannot list tools, cannot open /api/ledger, and
    // /healthz answers { ok: true } with no ledger counts.
    const stateDir = mkdtempSync(join(tmpdir(), "verax-drill-jti-"));
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
      const token = await issuer.sign({ jti: "drill-stolen", scope: "verax:read verax:audit" });
      await issuer.revoke("drill-stolen", stateDir);
      const mcp = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
      assert.equal(mcp.status, 401);
      const api = await fetch(`http://127.0.0.1:${port}/api/ledger`, {
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(api.status, 401);
      const health = await fetch(`http://127.0.0.1:${port}/healthz`, {
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(health.status, 200);
      assert.deepEqual(await health.json(), { ok: true });
      assert.equal(existsSync(join(stateDir, "decisions.jsonl")), false);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("2 hostile tool: an inner throw is a signed :threw effect; extra fields still record", async () => {
    // Expect: throw → allow record + effectClass memory.put:threw. Extra
    // result fields are hashed into resultHash, not dropped silently.
    const ledger = new FileLedger(mkdtempSync(join(tmpdir(), "verax-drill-hostile-")));
    try {
      const proxy = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["h-throw", "h-extra"]),
        inner: async (call) => {
          if (call.name === "memory.put") throw new Error("hostile-inner");
          return { content: [{ type: "text", text: "ok" }], isError: false, extra: { sneaky: 1 } };
        },
      });
      await assert.rejects(
        () =>
          proxy.call(
            {
              name: "memory.put",
              arguments: {
                id: "x",
                body: { t: 1 },
                source: { uri: "file://t", retrievedAtMs: 1 },
                validUntilMs: 9_999,
              },
            },
            { brain: "brain-1", scopes: new Set(["verax:memory"]) },
          ),
        /hostile-inner/,
      );
      const threw = (await ledger.effects()).find((e) => e.row.ref === "h-throw");
      assert.equal(threw?.row.effectClass, "memory.put:threw");
      assert.equal(typeof threw?.resultHash, "string");
      const extra = await proxy.call(
        { name: "memory.get", arguments: { id: "x" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      assert.equal(extra.isError, false);
      const row = (await ledger.effects()).find((e) => e.row.ref === "h-extra");
      assert.equal(row?.row.effectClass, "memory.get");
      assert.equal(typeof row?.resultHash, "string");
    } finally {
      ledger.close();
    }
  });

  it("3 another customer's record: B cannot read or explain A's id; spoken not-found, written tenant-mismatch", async () => {
    // Expect: signed deny tenant-mismatch with no body; spoken family is not-found.
    const dir = mkdtempSync(join(tmpdir(), "verax-drill-tenant-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      now: () => 4_000,
      nonce: queuedNonce(["ten-put", "ten-get", "ten-x"]),
    });
    try {
      const put = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "note-1",
            body: { secret: "alice" },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999_999,
          },
        },
        { brain: "alice", scopes: new Set(["verax:memory", "verax:read"]), iss: "https://a.example" },
      );
      assert.equal(put.isError, false);
      const got = await services.proxy.call(
        { name: "memory.get", arguments: { id: "note-1" } },
        { brain: "bob", scopes: new Set(["verax:read"]), iss: "https://b.example" },
      );
      assert.equal(got.isError, true);
      assert.deepEqual(JSON.parse(got.content[0]?.text ?? "{}"), { error: "not-found", id: "note-1" });
      const decisions = await services.ledger.decisions();
      const deny = decisions.find((d) => d.claims.reasonCode === "tenant-mismatch");
      assert.ok(deny);
      const denyRef = deny.claims.ref;
      assert.equal(typeof denyRef, "string");
      const operator = await explain(services.ledger, denyRef as string);
      assert.equal(operator.record.claims.reasonCode, "tenant-mismatch");
    } finally {
      services.ledger.close();
    }
  });

  it("4 repeated op: the same _ref twice is duplicate-effect / already resolved, not a second allow", async () => {
    // Expect: second call with the same _ref does not write a second allow effect.
    const dir = mkdtempSync(join(tmpdir(), "verax-drill-replay-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const args = {
        id: "note-r",
        body: { t: 1 },
        source: { uri: "file://t", retrievedAtMs: 1 },
        validUntilMs: 9_999,
        _ref: "replay-1",
      };
      const first = await services.proxy.call(
        { name: "memory.put", arguments: args },
        { brain: "brain-1", scopes: new Set(["verax:memory"]) },
      );
      assert.equal(first.isError, false);
      const second = await services.proxy.call(
        { name: "memory.put", arguments: args },
        { brain: "brain-1", scopes: new Set(["verax:memory"]) },
      );
      assert.equal(second.isError, false);
      const effects = await services.ledger.effects();
      const primary = effects.filter((e) => e.row.effectClass === "memory.put");
      assert.equal(primary.length, 1);
      const reuse = await services.proxy.call(
        {
          name: "memory.put",
          arguments: { ...args, body: { t: 2 } },
        },
        { brain: "brain-1", scopes: new Set(["verax:memory"]) },
      );
      assert.equal(reuse.isError, true);
      assert.match(reuse.content[0]?.text ?? "", /denied:ref-reuse/);
    } finally {
      services.ledger.close();
    }
  });

  it("5 tampered memory: a wrong versionHash is input-invalid; a hand-corrupt file is not returned as the old body", async () => {
    // Expect: _inputs versionHash mismatch → deny input-invalid. After the
    // file bytes change, memory.get does not return the original secret.
    const dir = mkdtempSync(join(tmpdir(), "verax-drill-mem-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      nonce: queuedNonce(["m-put", "m-bad", "m-get"]),
    });
    try {
      const put = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "note-t",
            body: { secret: "original" },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999_999,
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:memory", "verax:read"]) },
      );
      const versionHash = (JSON.parse(put.content[0]?.text ?? "{}") as { versionHash?: string }).versionHash;
      assert.equal(typeof versionHash, "string");
      const bad = await services.proxy.call(
        {
          name: "memory.get",
          arguments: {
            id: "note-t",
            _inputs: [{ id: "note-t", versionHash: "ab".repeat(32) }],
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      assert.equal(bad.isError, true);
      assert.match(bad.content[0]?.text ?? "", /denied:input-invalid/);
      const tenantRoot = join(dir, "tenants");
      const files: string[] = [];
      const walk = (p: string) => {
        for (const name of readdirSync(p, { withFileTypes: true })) {
          const full = join(p, name.name);
          if (name.isDirectory()) walk(full);
          else if (name.name === "note-t.json") files.push(full);
        }
      };
      walk(tenantRoot);
      assert.equal(files.length, 1);
      writeFileSync(files[0]!, `${JSON.stringify({ id: "note-t", body: { secret: "tampered" } })}\n`);
      const got = await services.proxy.call(
        { name: "memory.get", arguments: { id: "note-t" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      const text = got.content[0]?.text ?? "";
      assert.equal(text.includes("original"), false);
    } finally {
      services.ledger.close();
    }
  });

  it("6 full disk: ledger-disk-low is HTTP 507 and disk_deny_unrecorded when the deny cannot append", async () => {
    // Expect: 507, metrics.disk_deny_unrecorded = 1, no silent drop, no decisions file.
    const stateDir = mkdtempSync(join(tmpdir(), "verax-drill-disk-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const origFree = diskProbe.freeBytes;
    const origFail = diskProbe.failAppend;
    diskProbe.freeBytes = (dir) => (dir === stateDir ? 0 : origFree(dir));
    diskProbe.failAppend = true;
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
      const token = await issuer.sign({ scope: "verax:read" });
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "memory.get", arguments: { id: "a" } },
        }),
      });
      assert.equal(res.status, 507);
      const metrics = JSON.parse(readFileSync(join(stateDir, "metrics.json"), "utf8")) as {
        disk_deny_unrecorded?: number;
      };
      assert.equal(metrics.disk_deny_unrecorded, 1);
      assert.equal(existsSync(join(stateDir, "decisions.jsonl")), false);
    } finally {
      diskProbe.freeBytes = origFree;
      diskProbe.failAppend = origFail;
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("7 silenced evidence service: a cut heartbeat is silent in verax doctor", async () => {
    // Expect: after writes stop and heartbeat ages out, doctor fail/heartbeat says silent.
    const dir = mkdtempSync(join(tmpdir(), "verax-drill-silent-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      nonce: () => "sil-1",
    });
    try {
      const put = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "note-s",
            body: { t: 1 },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999,
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:memory"]) },
      );
      assert.equal(put.isError, false);
    } finally {
      services.ledger.close();
    }
    writeFileSync(
      join(dir, "heartbeat.json"),
      `${JSON.stringify({ atMs: 1, pid: 1, lastDecisionN: 1, lastEffectN: 1 })}\n`,
    );
    writeFileSync(join(dir, "evidence-copy", "decisions.jsonl"), "");
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: dir,
        VERAX_POLICY_FILE: policyFile,
        VERAX_HEARTBEAT_MAX_MS: "50",
      },
      ["node", "cli.ts", "doctor"],
    );
    const pulse = checks.find((c) => c.id === "heartbeat");
    assert.equal(pulse?.level, "fail");
    assert.match(pulse?.detail ?? "", /silent/);
    const copy = checks.find((c) => c.id === "evidence-copy");
    assert.equal(copy?.level, "fail");
  });
});
