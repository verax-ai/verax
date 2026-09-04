import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts", "dev-issuer.mjs");
const JWKS = "http://127.0.0.1:8790/.well-known/jwks.json";

async function assertPortFree(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const probe = createServer();
    const timer = setTimeout(() => {
      probe.close();
      reject(new Error("port busy"));
    }, 1000);
    probe.once("error", (err) => {
      clearTimeout(timer);
      const code = (err as NodeJS.ErrnoException).code;
      reject(new Error(code === "EADDRINUSE" ? "port busy" : String(err)));
    });
    probe.listen(8790, "127.0.0.1", () => {
      clearTimeout(timer);
      probe.close((closeErr) => (closeErr ? reject(closeErr) : resolve()));
    });
  });
}

describe("6 dev-issuer.mjs", () => {
  it("serves JWKS on 8790 and writes a token jose can verify", { timeout: 10000 }, async () => {
    await assertPortFree();
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-issuer-"));
    const outPath = join(stateDir, "token");
    const child = spawn(process.execPath, [script, "--out", outPath], {
      env: { ...process.env, VERAX_STATE_DIR: stateDir, NODE_ENV: "development" },
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
      for (let i = 0; i < 30; i += 1) {
        try {
          const res = await fetch(JWKS, { signal: AbortSignal.timeout(200) });
          if (res.status === 200) return true;
        } catch {
          /* not up */
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return false;
    })();
    const outcome = await Promise.race([
      closed.then((code) => ({ kind: "closed" as const, code })),
      ready.then((ok) => ({ kind: "ready" as const, ok })),
    ]);
    try {
      if (outcome.kind === "closed") {
        if (/EADDRINUSE/.test(stderr)) assert.fail("port busy");
        assert.fail(`issuer exited ${outcome.code}: ${stderr}`);
      }
      assert.equal(outcome.ok, true, `issuer did not listen: stderr=${stderr}`);
      const jwksRes = await fetch(JWKS, { signal: AbortSignal.timeout(1000) });
      assert.equal(jwksRes.status, 200);
      const token = readFileSync(outPath, "utf8").trim();
      assert.equal(token.length > 0, true);
      const { payload } = await jwtVerify(token, createRemoteJWKSet(new URL(JWKS)), {
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
