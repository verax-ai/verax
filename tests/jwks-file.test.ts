import { strict as assert } from "node:assert";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { exportPKCS8, generateKeyPair, importPKCS8, SignJWT } from "jose";

import { loadConfig } from "../packages/body/src/config.ts";
import { loadEnvFile } from "../packages/body/src/init-local.ts";
import { listen } from "../packages/body/src/server.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

function init(stateDir: string): void {
  const r = spawnSync(process.execPath, ["--experimental-strip-types", cli, "init", "--local", stateDir], {
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
}

function envFromFile(stateDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const loaded = loadEnvFile(join(stateDir, "verax.env"), env);
  assert.equal(loaded.ok, true);
  return env;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close(() => reject(new Error("free-port")));
        return;
      }
      const port = addr.port;
      server.close(() => resolve(port));
    });
    server.once("error", reject);
  });
}

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
  let json: Record<string, unknown> | null = null;
  try {
    json = (await res.json()) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

function textOf(json: Record<string, unknown> | null): string {
  const result = json?.result as { content?: { text?: string }[] } | undefined;
  return (result?.content ?? []).map((c) => c.text ?? "").join("");
}

describe("VERAX_JWKS_FILE", () => {
  it("accepts the init token and refuses a token from another key", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-jwks-"));
    let http: Awaited<ReturnType<typeof listen>> | undefined;
    try {
      init(stateDir);
      const env = envFromFile(stateDir);
      env.VERAX_BIND = "127.0.0.1:0";
      const loaded = loadConfig(env);
      assert.equal(loaded.ok, true, loaded.ok ? "" : loaded.reason);
      if (!loaded.ok) return;
      http = await listen(loaded.value);
      const port = (http.address() as { port: number }).port;
      const mcp = `http://127.0.0.1:${port}/mcp`;
      const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      const ok = await rpc(mcp, token, "tools/list", {});
      assert.equal(ok.status, 200, JSON.stringify(ok.json));

      const { privateKey } = await generateKeyPair("ES256", { extractable: true });
      const pem = await exportPKCS8(privateKey);
      const other = await importPKCS8(pem, "ES256");
      const forged = await new SignJWT({ scope: "verax:read verax:memory" })
        .setProtectedHeader({ alg: "ES256", kid: "other" })
        .setIssuer("verax-local")
        .setAudience("http://127.0.0.1:8787")
        .setSubject("local-agent")
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(other);
      const refused = await rpc(mcp, forged, "tools/list", {});
      assert.equal(refused.status, 401);
    } finally {
      if (http) {
        await new Promise<void>((resolve) => {
          http?.close(() => resolve());
        });
      }
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });

  it("refuses a JWKS file on a non-loopback bind even when TLS is terminated", () => {
    const loaded = loadConfig({
      VERAX_ISSUER: "verax-local",
      VERAX_JWKS_FILE: join(tmpdir(), "missing-jwks.json"),
      VERAX_AUDIENCE: "http://127.0.0.1:8787",
      VERAX_STATE_DIR: tmpdir(),
      VERAX_POLICY_FILE: join(tmpdir(), "policy.json"),
      VERAX_BIND: "0.0.0.0:8787",
      VERAX_TLS_TERMINATED: "1",
    });
    assert.equal(loaded.ok, false);
    if (!loaded.ok) assert.equal(loaded.reason, "VERAX_JWKS_FILE needs a loopback bind");
  });

  it("refuses both a JWKS URL and a JWKS file", () => {
    const loaded = loadConfig({
      VERAX_ISSUER: "verax-local",
      VERAX_JWKS_URL: "http://127.0.0.1:1/jwks",
      VERAX_JWKS_FILE: join(tmpdir(), "jwks.json"),
      VERAX_AUDIENCE: "http://127.0.0.1:8787",
      VERAX_STATE_DIR: tmpdir(),
      VERAX_POLICY_FILE: join(tmpdir(), "policy.json"),
    });
    assert.equal(loaded.ok, false);
    if (!loaded.ok) assert.equal(loaded.reason, "both VERAX_JWKS_URL and VERAX_JWKS_FILE");
  });

  it("serves memory through the env file and holds spend", { timeout: 60_000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-jwks-e2e-"));
    const port = await freePort();
    let child: ChildProcess | undefined;
    try {
      init(stateDir);
      const policyPath = join(stateDir, "policy.json");
      const policy = JSON.parse(readFileSync(policyPath, "utf8")) as { rules: unknown[] };
      policy.rules.push({
        id: "spend",
        tool: "spend",
        requires: ["verax:memory"],
        mode: "approve",
        text: "A payment is held for an operator.",
        spend: {
          maxAmountMinor: 5000,
          currency: "USD",
          payees: ["sample-merchant"],
          dailyMaxMinor: 10_000,
        },
      });
      writeFileSync(policyPath, `${JSON.stringify(policy)}\n`);
      const envPath = join(stateDir, "verax.env");
      const envText = readFileSync(envPath, "utf8").replace(/^VERAX_BIND=.*$/m, `VERAX_BIND=127.0.0.1:${port}`);
      writeFileSync(envPath, envText);
      const clean: NodeJS.ProcessEnv = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (typeof v === "string" && !k.startsWith("VERAX_")) clean[k] = v;
      }
      child = spawn(process.execPath, ["--experimental-strip-types", cli, "serve", "--env-file", envPath], {
        env: clean,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      let log = "";
      child.stdout?.on("data", (c) => {
        log += String(c);
      });
      child.stderr?.on("data", (c) => {
        log += String(c);
      });
      const until = Date.now() + 20_000;
      let up = false;
      while (Date.now() < until) {
        try {
          const res = await fetch(`http://127.0.0.1:${port}/healthz`);
          if (res.status === 401 || res.status === 200) {
            up = true;
            break;
          }
        } catch {
          // not listening yet
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.equal(up, true, log);
      const mcp = `http://127.0.0.1:${port}/mcp`;
      const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      const put = await rpc(mcp, token, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "local-1",
          body: { note: "hello" },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });
      assert.equal(put.status, 200, JSON.stringify(put.json));
      assert.equal((put.json?.result as { isError?: boolean } | undefined)?.isError, false, textOf(put.json));
      const got = await rpc(mcp, token, "tools/call", {
        name: "memory.get",
        arguments: { id: "local-1" },
      });
      assert.equal(got.status, 200, JSON.stringify(got.json));
      assert.equal((got.json?.result as { isError?: boolean } | undefined)?.isError, false, textOf(got.json));
      const decisions = readFileSync(join(stateDir, "decisions.jsonl"), "utf8")
        .split("\n")
        .filter((line) => line !== "");
      assert.equal(decisions.length, 2);
      for (const line of decisions) {
        const row = JSON.parse(line) as { claims: { decision: string }; coseHex?: string };
        assert.equal(row.claims.decision, "allow");
        assert.equal(typeof row.coseHex, "string");
        assert.ok((row.coseHex ?? "").length > 0);
      }
      const spend = await rpc(mcp, token, "tools/call", {
        name: "spend",
        arguments: { amountMinor: 100, currency: "USD", payee: "sample-merchant", reference: "local-1" },
      });
      const spendText = textOf(spend.json);
      assert.match(spendText, /^deferred:approval-required:/);
      assert.equal(spendText.startsWith("allowed:"), false);
    } finally {
      if (child?.pid) {
        if (process.platform === "win32") {
          spawnSync("taskkill", ["/T", "/PID", String(child.pid), "/F"], { windowsHide: true, stdio: "ignore" });
        } else {
          try {
            process.kill(child.pid, "SIGTERM");
          } catch {
            // gone
          }
        }
      }
      rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
