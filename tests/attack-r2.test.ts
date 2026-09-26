// R2: breaks the previous passes did not cover. Each `it` asserts the safe
// behaviour. On 85b297d the implementation does the unsafe thing, so the
// assertion fails. A fix should turn that assertion green without weakening it.

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { loadConfig } from "../packages/body/src/config.ts";
import { systemToolEnv, systemToolPath } from "../packages/body/src/install.ts";
import { envFileJwksMissing, loadEnvFile } from "../packages/body/src/init-local.ts";
import { listen, loopbackHostDecision } from "../packages/body/src/server.ts";
import { spentTodayMinorOf } from "../packages/proxy/src/approvals.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

function httpGet(
  port: number,
  hostHeader: string,
  path: string,
  extraHeaders: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: "GET",
        headers: { host: hostHeader, connection: "close", ...extraHeaders },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function runScripts(yml: string): string[] {
  const lines = yml.split(/\n/);
  const scripts: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const header = /^([ \t]+)run: *\|[ \t]*$/.exec(lines[i] ?? "");
    if (!header) continue;
    const indent = header[1]!.length;
    const body: string[] = [];
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j] ?? "";
      if (line.trim() === "") {
        body.push(line);
        continue;
      }
      const lead = /^[ \t]*/.exec(line)?.[0].length ?? 0;
      if (lead <= indent) break;
      body.push(line);
    }
    scripts.push(body.join("\n"));
  }
  return scripts;
}

describe("attack R2", () => {
  it("R2-1 rejects a foreign Host on loopback so a rebound browser learns nothing", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r2-host-"));
    const init = spawnSync(process.execPath, ["--experimental-strip-types", cli, "init", "--local", stateDir], {
      encoding: "utf8",
    });
    assert.equal(init.status, 0, init.stderr);
    const env: NodeJS.ProcessEnv = {};
    assert.equal(loadEnvFile(join(stateDir, "verax.env"), env).ok, true);
    env.VERAX_BIND = "127.0.0.1:0";
    const loaded = loadConfig(env);
    if (!loaded.ok) throw new Error(loaded.reason);
    const http = await listen(loaded.value);
    try {
      const port = (http.address() as { port: number }).port;
      const health = await httpGet(port, "rebind.example", "/healthz");
      assert.equal(health.status, 400, health.body);
      const meta = await httpGet(port, "rebind.example", "/.well-known/oauth-protected-resource");
      assert.equal(meta.status, 400, meta.body);
    } finally {
      await new Promise<void>((resolve, reject) => {
        http.close((err) => (err ? reject(err) : resolve()));
      });
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });

  it(
    "R2-2 ownerOnly sets a Windows DACL, chmod 0o600 is not the restriction",
    { skip: process.platform === "win32" ? false : "POSIX keeps chmod; the existing 0600 mode test covers owner-only files" },
    () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r2-acl-"));
      try {
        const init = spawnSync(process.execPath, ["--experimental-strip-types", cli, "init", "--local", stateDir], {
          encoding: "utf8",
        });
        assert.equal(init.status, 0, init.stderr);
        const key = join(stateDir, "local-issuer", "key.pem");
        const acl = spawnSync(systemToolPath("icacls", "win32"), [key], {
          encoding: "utf8",
          shell: false,
          env: systemToolEnv("win32"),
        });
        assert.equal(acl.status, 0, acl.stderr);
        const text = acl.stdout ?? "";
        assert.doesNotMatch(text, /BUILTIN\\Users/i);
        assert.doesNotMatch(text, /Authenticated Users/i);
        assert.doesNotMatch(text, /Everyone/i);
      } finally {
        rmSync(stateDir, { recursive: true, force: true });
      }
    },
  );

  it("R2-3 workflow_dispatch confirm is not expanded inside a shell run script", () => {
    for (const name of ["release.yml", "mcp-registry.yml"]) {
      const yml = readFileSync(join(root, ".github", "workflows", name), "utf8");
      const scripts = runScripts(yml);
      assert.ok(scripts.length > 0, `${name} has no run scripts`);
      for (const script of scripts) {
        assert.doesNotMatch(
          script,
          /\$\{\{\s*inputs\./,
          `${name} interpolates a workflow input into a shell script`,
        );
      }
    }
  });

  it("R2-4 --env-file replaces ambient VERAX_* instead of merging over them", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-attack-r2-env-"));
    const path = join(dir, "verax.env");
    try {
      writeFileSync(path, "export VERAX_ISSUER=from-file\nVERAX_BIND=127.0.0.1:8787\n");
      const env: NodeJS.ProcessEnv = {
        VERAX_ISSUER: "from-process",
        VERAX_DOWNSTREAM: join(dir, "hostile.json"),
        VERAX_TLS_TERMINATED: "1",
      };
      assert.equal(loadEnvFile(path, env).ok, true);
      assert.equal(env.VERAX_ISSUER, "from-file");
      assert.equal(env.VERAX_DOWNSTREAM, undefined);
      assert.equal(env.VERAX_TLS_TERMINATED, undefined);
      assert.equal(envFileJwksMissing(env), "env file sets neither VERAX_JWKS_FILE nor VERAX_JWKS_URL");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R2-4 refuses NODE_OPTIONS in the env file", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-attack-r2-node-"));
    const path = join(dir, "verax.env");
    try {
      writeFileSync(path, "NODE_OPTIONS=--inspect\nVERAX_ISSUER=from-file\n");
      const loaded = loadEnvFile(path, {});
      assert.equal(loaded.ok, false);
      if (loaded.ok) return;
      assert.match(loaded.reason, /NODE_OPTIONS/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loopbackHostDecision matches the listening port when bind was ephemeral", () => {
    const listening = 49152;
    assert.equal(loopbackHostDecision(`127.0.0.1:${listening}`, listening), "allow");
    assert.equal(loopbackHostDecision(`localhost:${listening}`, listening), "allow");
    assert.equal(loopbackHostDecision(`[::1]:${listening}`, listening), "allow");
    assert.equal(loopbackHostDecision("127.0.0.1:0", listening), "deny");
    assert.equal(loopbackHostDecision("127.0.0.1", listening), "deny");
    assert.equal(loopbackHostDecision("127.0.0.1", 80), "allow");
  });

  it("R2-1 Origin is refused unless it is listed, and a missing Origin still works", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r2-origin-"));
    const init = spawnSync(process.execPath, ["--experimental-strip-types", cli, "init", "--local", stateDir], {
      encoding: "utf8",
    });
    assert.equal(init.status, 0, init.stderr);
    const env: NodeJS.ProcessEnv = {};
    assert.equal(loadEnvFile(join(stateDir, "verax.env"), env).ok, true);
    env.VERAX_BIND = "127.0.0.1:0";
    const panel = "http://127.0.0.1:5173";
    env.VERAX_ALLOWED_ORIGINS = panel;
    const loaded = loadConfig(env);
    if (!loaded.ok) throw new Error(loaded.reason);
    const http = await listen(loaded.value);
    try {
      const port = (http.address() as { port: number }).port;
      const host = `127.0.0.1:${port}`;
      const open = await httpGet(port, host, "/healthz");
      assert.equal(open.status, 200, open.body);
      const evil = await httpGet(port, host, "/healthz", { origin: "https://evil.example" });
      assert.equal(evil.status, 403, evil.body);
      assert.match(evil.body, /origin-not-allowed/);
      const listed = await httpGet(port, host, "/healthz", { origin: panel });
      assert.equal(listed.status, 200, listed.body);
    } finally {
      await new Promise<void>((resolve, reject) => {
        http.close((err) => (err ? reject(err) : resolve()));
      });
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });

  it("R2-5 a second spend rule is rejected instead of silently ignored", () => {
    const spend = (id: string, payee: string, max: number) => ({
      id,
      tool: "spend",
      requires: ["verax:pay"],
      mode: "approve" as const,
      text: `Hold spend ${id}.`,
      spend: { maxAmountMinor: max, currency: "USD", payees: [payee], dailyMaxMinor: max },
    });
    assert.throws(
      () =>
        loadPolicy({
          version: 1,
          default: "deny",
          rules: [spend("loose", "mallory", 1_000_000), spend("tight", "acme", 100)],
        }),
      /spend/,
    );
  });

  it("R2-6 daily spend counted on one operator-local day does not reset at UTC midnight", () => {
    // 2026-09-25 01:00 and 04:00 in UTC+3 are the same local calendar day
    // and two different UTC dates. The cap is one day for the operator.
    const earlier = Date.parse("2026-09-24T22:00:00.000Z");
    const later = Date.parse("2026-09-25T01:00:00.000Z");
    const sum = spentTodayMinorOf(
      [
        {
          subject: "spend",
          status: "approved",
          createdAtMs: earlier,
          expiresAtMs: earlier + 86_400_000,
          args: { amountMinor: 80, currency: "USD" },
        },
      ],
      later,
      "USD",
      86_400_000,
      180,
    );
    assert.equal(sum, 80);
  });
});
