import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts", "dev-issuer.mjs");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;

describe("6 dev-issuer.mjs", () => {
  it("serves JWKS on the bound VERAX_DEV_ISSUER_PORT and writes a token jose can verify", { timeout: 10000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-issuer-"));
    const outPath = join(stateDir, "token");
    const child = spawn(process.execPath, [script, "--out", outPath], {
      env: {
        ...process.env,
        VERAX_STATE_DIR: stateDir,
        NODE_ENV: "development",
        VERAX_DEV_ISSUER_PORT: "0",
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
    const ready = (async () => {
      for (let i = 0; i < 40; i += 1) {
        const match = LISTENING.exec(stderr);
        if (match) return match[1] ?? "";
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return "";
    })();
    const outcome = await Promise.race([
      closed.then((code) => ({ kind: "closed" as const, code })),
      ready.then((port) => ({ kind: "ready" as const, port })),
    ]);
    try {
      if (outcome.kind === "closed") {
        if (/EADDRINUSE/.test(stderr)) assert.fail("port busy");
        assert.fail(`issuer exited ${outcome.code}: ${stderr}`);
      }
      const port = Number(outcome.port);
      assert.equal(Number.isInteger(port) && port > 0, true, `issuer did not bind a real port: stderr=${stderr}`);
      const origin = `http://127.0.0.1:${port}`;
      const jwks = `${origin}/.well-known/jwks.json`;
      const jwksRes = await fetch(jwks, { signal: AbortSignal.timeout(1000) });
      assert.equal(jwksRes.status, 200);
      const token = readFileSync(outPath, "utf8").trim();
      assert.equal(token.length > 0, true);
      const { payload } = await jwtVerify(token, createRemoteJWKSet(new URL(jwks)), {
        issuer: "http://127.0.0.1:8790",
        audience: "http://127.0.0.1:8787",
      });
      assert.equal(payload.sub, "dev-brain");
    } finally {
      child.kill("SIGTERM");
      await closed;
    }
  });
});
