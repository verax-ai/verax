import { strict as assert } from "node:assert";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts", "dev-issuer.mjs");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;

/**
 * Waits for the issuer to say which port it bound. The old inline version gave up
 * after 2 s and returned "", which built `http://127.0.0.1:` and hit port 80 on a
 * loaded machine: a flake that read as ECONNREFUSED instead of "did not start".
 * The wait stays under the tightest test timeout here (10 s) so the assertion
 * below is what fails, with the issuer's own stderr in the message.
 */
/**
 * How long a request to a server on this machine may take before the test
 * gives up. This is a guard against a hung request, not a claim about
 * latency: nothing here asserts that the issuer is fast, only that it
 * answers, and the status and signature checks below carry that.
 *
 * It was one second. The unit runner starts 101 files at once, and on
 * 11 Sep 2026 this test aborted twice at that budget while 24 green runs of
 * the same suite finished it in 281-2227 ms. A second is inside the spread
 * of the machine, so it measured the machine.
 */
const LOCAL_FETCH_MS = 10_000;

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

function assertBound(port: string, stderr: string): void {
  const n = Number(port);
  assert.equal(
    Number.isInteger(n) && n > 0,
    true,
    `issuer never printed a bound port within the wait: stderr=${stderr}`,
  );
}

describe("6 dev-issuer.mjs", () => {
  it("serves JWKS on the bound VERAX_DEV_ISSUER_PORT and writes a token jose can verify", { timeout: 60_000 }, async () => {
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
    const ready = listeningPort(() => stderr);
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
      const jwksRes = await fetch(jwks, { signal: AbortSignal.timeout(LOCAL_FETCH_MS) });
      assert.equal(jwksRes.status, 200);
      const token = readFileSync(outPath, "utf8").trim();
      assert.equal(token.length > 0, true);
      const { payload } = await jwtVerify(token, createRemoteJWKSet(new URL(jwks)), {
        issuer: "http://127.0.0.1:8790",
        audience: "http://127.0.0.1:8787",
      });
      assert.equal(payload.sub, "dev-brain");
      assert.equal(typeof payload.jti, "string");
      assert.equal((payload.jti as string).length > 0, true);

      const revoke = await fetch(`${origin}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jti: payload.jti }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(revoke.status, 200);
      const revokedPath = join(stateDir, "revoked-jti.jsonl");
      assert.equal(existsSync(revokedPath), true);
      assert.match(readFileSync(revokedPath, "utf8"), new RegExp(`"jti":"${payload.jti}"`));
    } finally {
      child.kill("SIGTERM");
      await closed;
    }
  });

  it("authorize without code_challenge fails; plain is refused; S256 mints a one-use code", { timeout: 15000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-pkce-"));
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
    child.stderr.on("data", (chunk: Buffer) => {
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
      assertBound(outcome.port, stderr);
      const origin = `http://127.0.0.1:${outcome.port}`;
      const redirect = "http://127.0.0.1:5173/";
      const missing = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(missing.status >= 400 && missing.status < 500, true, `missing challenge status=${missing.status}`);
      const missingLoc = missing.headers.get("location") ?? "";
      assert.equal(missingLoc.includes("code="), false);

      const plain = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=abc&code_challenge_method=plain`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(plain.status >= 400 && plain.status < 500, true, `plain status=${plain.status}`);
      assert.equal((plain.headers.get("location") ?? "").includes("code="), false);

      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const auth = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256&state=st1`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(auth.status, 302);
      const loc = new URL(auth.headers.get("location") ?? "", origin);
      const code = loc.searchParams.get("code");
      assert.equal(typeof code === "string" && code.length > 0, true);
      assert.equal(loc.searchParams.get("state"), "st1");

      const tokenRes = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: redirect,
          code_verifier: verifier,
          client_id: "verax-panel",
        }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(tokenRes.status, 200);
      const body = (await tokenRes.json()) as { access_token?: string; token_type?: string };
      assert.equal(typeof body.access_token, "string");
      assert.equal((body.access_token as string).length > 0, true);
      assert.equal(body.token_type, "Bearer");
      const { payload } = await jwtVerify(body.access_token!, createRemoteJWKSet(new URL(`${origin}/.well-known/jwks.json`)), {
        issuer: "http://127.0.0.1:8790",
        audience: "http://127.0.0.1:8787",
      });
      assert.equal(payload.sub, "operator-1");
      assert.equal(stderr.includes(body.access_token!), false);

      const replay = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: redirect,
          code_verifier: verifier,
          client_id: "verax-panel",
        }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(replay.status >= 400 && replay.status < 500, true);

      const mismatch = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      const code2 = new URL(mismatch.headers.get("location") ?? "", origin).searchParams.get("code");
      const wrongUri = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code2 ?? "",
          redirect_uri: "http://127.0.0.1/other",
          code_verifier: verifier,
          client_id: "verax-panel",
        }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(wrongUri.status >= 400 && wrongUri.status < 500, true);
    } finally {
      child.kill("SIGTERM");
      await closed;
    }
  });

  it("refuses an unregistered redirect_uri with 400 and no Location", { timeout: 60_000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-redir-"));
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
    child.stderr.on("data", (chunk: Buffer) => {
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
      assertBound(outcome.port, stderr);
      const origin = `http://127.0.0.1:${outcome.port}`;
      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const evil = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent("http://evil.example/steal")}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(evil.status, 400);
      const body = (await evil.json()) as { error?: string };
      assert.equal(body.error, "invalid_request");
      assert.equal(evil.headers.get("location"), null);
    } finally {
      child.kill("SIGTERM");
      await closed;
    }
  });

  it("drops the oldest code when the map is full", { timeout: 20000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-codes-"));
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
    child.stderr.on("data", (chunk: Buffer) => {
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
      assertBound(outcome.port, stderr);
      const origin = `http://127.0.0.1:${outcome.port}`;
      const redirect = "http://127.0.0.1:5173/";
      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const authorize = async () => {
        const auth = await fetch(
          `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
          { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
        );
        return new URL(auth.headers.get("location") ?? "", origin).searchParams.get("code") ?? "";
      };
      const first = await authorize();
      assert.equal(first.length > 0, true);
      for (let i = 0; i < 100; i += 1) {
        const code = await authorize();
        assert.equal(code.length > 0, true, `authorize ${i} had no code`);
      }
      const last = await authorize();
      const exchange = async (code: string) =>
        fetch(`${origin}/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirect,
            code_verifier: verifier,
          }),
          signal: AbortSignal.timeout(LOCAL_FETCH_MS),
        });
      const firstRes = await exchange(first);
      assert.equal(firstRes.status, 400, "the oldest code must have been dropped");
      const lastRes = await exchange(last);
      assert.equal(lastRes.status, 200);
    } finally {
      child.kill("SIGTERM");
      await closed;
    }
  });

  it("lets a registered redirect origin read the token response", { timeout: 15000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-cors-"));
    const outPath = join(stateDir, "token");
    const panel = "http://127.0.0.1:5173";
    const redirect = `${panel}/`;
    const child = spawn(process.execPath, [script, "--out", outPath], {
      env: {
        ...process.env,
        VERAX_STATE_DIR: stateDir,
        NODE_ENV: "development",
        VERAX_DEV_ISSUER_PORT: "0",
        VERAX_DEV_REDIRECT_URIS: redirect,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
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
      assertBound(outcome.port, stderr);
      const origin = `http://127.0.0.1:${outcome.port}`;

      // The panel is served from another port, so the browser refuses to hand
      // the token to it unless the response says that origin may read it.
      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const authorized = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      const location = authorized.headers.get("location") ?? "";
      const code = new URL(location).searchParams.get("code") ?? "";
      assert.notEqual(code, "", `no code in ${location}`);

      const preflight = await fetch(`${origin}/token`, {
        method: "OPTIONS",
        headers: {
          origin: panel,
          "access-control-request-method": "POST",
          "access-control-request-headers": "content-type",
        },
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(preflight.status < 300, true, `preflight status=${preflight.status}`);
      assert.equal(preflight.headers.get("access-control-allow-origin"), panel);

      const token = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: panel },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirect,
          code_verifier: verifier,
          client_id: "verax-panel",
        }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(token.status, 200, `token status=${token.status}`);
      assert.equal(
        token.headers.get("access-control-allow-origin"),
        panel,
        "without this header the browser drops the token and the panel stays on loading",
      );
    } finally {
      child.kill();
    }
  });

  it("does not invite an origin it never registered", { timeout: 15000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-dev-cors-no-"));
    const outPath = join(stateDir, "token");
    const child = spawn(process.execPath, [script, "--out", outPath], {
      env: {
        ...process.env,
        VERAX_STATE_DIR: stateDir,
        NODE_ENV: "development",
        VERAX_DEV_ISSUER_PORT: "0",
        VERAX_DEV_REDIRECT_URIS: "http://127.0.0.1:5173/",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
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
      assertBound(outcome.port, stderr);
      const origin = `http://127.0.0.1:${outcome.port}`;
      const preflight = await fetch(`${origin}/token`, {
        method: "OPTIONS",
        headers: {
          origin: "http://evil.test",
          "access-control-request-method": "POST",
        },
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(preflight.headers.get("access-control-allow-origin"), null);
    } finally {
      child.kill();
    }
  });
});
