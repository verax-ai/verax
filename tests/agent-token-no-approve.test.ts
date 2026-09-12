import { strict as assert } from "node:assert";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { listen } from "../packages/body/src/server.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts", "dev-issuer.mjs");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;
const LOCAL_FETCH_MS = 10_000;

function decodePayload(token: string): { scope?: string; sub?: string } {
  const body = token.split(".")[1];
  assert.ok(body, "token-shape");
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as {
    scope?: string;
    sub?: string;
  };
}

function listeningPort(getStderr: () => string, ms = 8_000): Promise<string> {
  return (async () => {
    const until = Date.now() + ms;
    while (Date.now() < until) {
      const match = LISTENING.exec(getStderr());
      if (match) return match[1] ?? "";
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return "";
  })();
}

function approvePolicyFile(dir: string): string {
  const path = join(dir, "approve-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "put-approve",
          tool: "memory.put",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Writes need operator approval.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

/**
 * The file written for the agent used to carry whatever VERAX_DEV_SCOPE said,
 * including verax:approve. Approving from that token is the brain approving
 * itself. The strip has to be visible in the file and at the body, not only
 * in the source.
 */
describe("agent token never carries approve", () => {
  it(
    "strips verax:approve from --out, and that token cannot POST /api/approve",
    { timeout: 60_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-agent-no-approve-"));
      const outPath = join(stateDir, "token");
      const audience = "http://127.0.0.1/verax-agent-no-approve";
      const child = spawn(process.execPath, [script, "--out", outPath], {
        env: {
          ...process.env,
          VERAX_STATE_DIR: stateDir,
          NODE_ENV: "development",
          VERAX_DEV_ISSUER_PORT: "0",
          VERAX_AUDIENCE: audience,
          VERAX_ISSUER: "http://127.0.0.1:8790",
          VERAX_DEV_SCOPE: "verax:read verax:memory verax:audit verax:approve",
          VERAX_DEV_SUB: "dev-brain",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += String(chunk);
      });
      const closed = new Promise<number>((resolve) => {
        child.once("close", (code) => resolve(code ?? 1));
      });
      const ready = listeningPort(() => stderr);
      const outcome = await Promise.race([
        closed.then((code) => ({ kind: "closed" as const, code })),
        ready.then((port) => ({ kind: "ready" as const, port })),
      ]);
      try {
        if (outcome.kind === "closed") {
          assert.fail(`issuer exited ${outcome.code}: ${stderr}`);
        }
        const origin = `http://127.0.0.1:${outcome.port}`;
        const agentToken = readFileSync(outPath, "utf8").trim();
        const claims = decodePayload(agentToken);
        assert.equal(claims.sub, "dev-brain");
        assert.equal(
          typeof claims.scope === "string" && claims.scope.split(/\s+/).includes("verax:approve"),
          false,
          `agent token still carries approve: ${claims.scope}`,
        );

        const jwks = createRemoteJWKSet(new URL(`${origin}/.well-known/jwks.json`));
        const verified = await jwtVerify(agentToken, jwks, {
          issuer: "http://127.0.0.1:8790",
          audience,
        });
        assert.equal(verified.payload.sub, "dev-brain");

        const verifier = randomBytes(32).toString("base64url");
        const challenge = createHash("sha256").update(verifier).digest("base64url");
        const redirect = "http://127.0.0.1:5173/";
        const authorized = await fetch(
          `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
          { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
        );
        const code = new URL(authorized.headers.get("location") ?? "", origin).searchParams.get("code");
        assert.ok(code, "no session code");
        const exchanged = await fetch(`${origin}/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirect,
            code_verifier: verifier,
            client_id: "verax-panel",
          }),
          signal: AbortSignal.timeout(LOCAL_FETCH_MS),
        });
        assert.equal(exchanged.status, 200);
        const session = (await exchanged.json()) as { access_token?: string };
        assert.ok(session.access_token);
        const sessionClaims = decodePayload(session.access_token);
        assert.equal(sessionClaims.sub, "operator-1");
        assert.notEqual(sessionClaims.sub, claims.sub);

        const body = await listen({
          issuer: "http://127.0.0.1:8790",
          jwksUrl: `${origin}/.well-known/jwks.json`,
          audience,
          stateDir: join(stateDir, "body"),
          bindHost: "127.0.0.1",
          bindPort: 0,
          policyFile: approvePolicyFile(stateDir),
          tlsTerminated: false,
        });
        const bodyPort = (body.address() as { port: number }).port;
        const base = `http://127.0.0.1:${bodyPort}`;
        try {
          await fetch(`${base}/mcp`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json, text/event-stream",
              authorization: `Bearer ${agentToken}`,
            },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: "tools/call",
              params: {
                name: "memory.put",
                arguments: {
                  id: "n1",
                  body: { t: 1 },
                  source: { uri: "file://t", retrievedAtMs: 1 },
                  validUntilMs: Date.now() + 60_000,
                },
              },
            }),
          });
          const listed = await fetch(`${base}/api/ledger?from=0&to=${Number.MAX_SAFE_INTEGER}`, {
            headers: { authorization: `Bearer ${agentToken}` },
          });
          assert.equal(listed.status, 200);
          const ledger = (await listed.json()) as {
            approvals?: { ref: string; requestHash: string; status?: string }[];
          };
          const waiting = (ledger.approvals ?? []).find((a) => a.status === "pending" || a.status === undefined);
          assert.ok(waiting, "nothing is waiting");
          const forbidden = await fetch(`${base}/api/approve`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${agentToken}`,
            },
            body: JSON.stringify({ ref: waiting.ref, requestHash: waiting.requestHash }),
          });
          assert.equal(forbidden.status, 403, `agent token approved: ${forbidden.status}`);
        } finally {
          await new Promise<void>((resolve, reject) => {
            body.close((err) => (err ? reject(err) : resolve()));
          });
        }
      } finally {
        child.kill("SIGTERM");
        await closed;
      }
    },
  );
});
