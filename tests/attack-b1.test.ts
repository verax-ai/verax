// B1: a token minted from the local issuer key must not open approve or audit
// over HTTP, and `verax approve` must not approve from a non-interactive shell.

import { strict as assert } from "node:assert";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { importPKCS8, SignJWT } from "jose";

import { loadConfig } from "../packages/body/src/config.ts";
import { loadEnvFile } from "../packages/body/src/init-local.ts";
import { listen } from "../packages/body/src/server.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

type DecisionRow = { claims: { decision: string; ref?: string; subject?: string } };

function init(stateDir: string): void {
  const r = spawnSync(process.execPath, ["--experimental-strip-types", cli, "init", "--local", stateDir], {
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
}

function readDecisions(stateDir: string): DecisionRow[] {
  const path = join(stateDir, "decisions.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as DecisionRow);
}

function textOf(json: Record<string, unknown> | null): string {
  const result = json?.result as { content?: { text?: string }[] } | undefined;
  return (result?.content ?? []).map((c) => c.text ?? "").join("");
}

describe("attack B1", () => {
  it("local approve scope is 403 and a non-TTY approve exits 78", { timeout: 60_000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-b1-"));
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
    const env: NodeJS.ProcessEnv = {};
    const loadedEnv = loadEnvFile(join(stateDir, "verax.env"), env);
    assert.equal(loadedEnv.ok, true);
    env.VERAX_BIND = "127.0.0.1:0";
    const loaded = loadConfig(env);
    if (!loaded.ok) throw new Error(loaded.reason);
    const http = await listen(loaded.value);
    const port = (http.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    try {
      const agent = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      const spent = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${agent}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "spend",
            arguments: {
              amountMinor: 100,
              currency: "USD",
              payee: "sample-merchant",
              reference: "local-1",
              _ref: "held-1",
            },
          },
        }),
      });
      const spentJson = (await spent.json()) as Record<string, unknown>;
      const heldText = textOf(spentJson);
      assert.match(heldText, /^deferred:approval-required:/, heldText);
      const approvals = readFileSync(join(stateDir, "approvals.jsonl"), "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as { ref: string; requestHash: string; status?: string });
      const waiting = approvals.find((row) => row.status === "pending" || row.status === undefined);
      assert.ok(waiting, "no held approval");

      const pem = readFileSync(join(stateDir, "local-issuer", "key.pem"), "utf8");
      const jwks = JSON.parse(readFileSync(join(stateDir, "local-issuer", "jwks.json"), "utf8")) as {
        keys: { kid?: string }[];
      };
      const kid = String(jwks.keys[0]?.kid ?? "");
      const privateKey = await importPKCS8(pem, "ES256");
      const operator = await new SignJWT({ scope: "verax:approve verax:audit" })
        .setProtectedHeader({ alg: "ES256", kid })
        .setSubject("agent-self")
        .setIssuer("verax-local")
        .setAudience(env.VERAX_AUDIENCE ?? "")
        .setIssuedAt()
        .setExpirationTime("1h")
        .setJti(crypto.randomUUID())
        .sign(privateKey);

      const approve = await fetch(`${base}/api/approve`, {
        method: "POST",
        headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
        body: JSON.stringify({ ref: waiting.ref, requestHash: waiting.requestHash }),
      });
      const approveBody = (await approve.json()) as { error?: string };
      assert.equal(approve.status, 403, JSON.stringify(approveBody));
      assert.equal(approveBody.error, "local-mode-operator-scope");
      const ledger = await fetch(`${base}/api/ledger`, {
        headers: { authorization: `Bearer ${operator}` },
      });
      const ledgerBody = (await ledger.json()) as { error?: string };
      assert.equal(ledger.status, 403, JSON.stringify(ledgerBody));
      assert.equal(ledgerBody.error, "local-mode-operator-scope");
      const allows = readDecisions(stateDir).filter((row) => row.claims.decision === "allow");
      assert.deepEqual(allows, [], JSON.stringify(readDecisions(stateDir)));
    } finally {
      await new Promise<void>((resolve, reject) => {
        http.close((err) => (err ? reject(err) : resolve()));
      });
    }

    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "approve", stateDir, "held-1"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 78, stderr);
    assert.match(stderr, /verax approve needs a terminal/);
    const allows = readDecisions(stateDir).filter((row) => row.claims.decision === "allow");
    assert.deepEqual(allows, [], JSON.stringify(readDecisions(stateDir)));
    rmSync(stateDir, { recursive: true, force: true });
  });
});
