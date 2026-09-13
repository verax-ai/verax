import { strict as assert } from "node:assert";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { beginPairing, writePairing, hashPairingCode, PAIRING_MAX_ATTEMPTS, PAIRING_TTL_MS } from "../packages/body/src/operator-pairing.ts";
import { hasRegisteredOperator } from "../packages/body/src/operator-credentials.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey, registerWithSoftwarePasskey } from "./software-passkey.ts";

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

async function startIssuer(
  stateDir: string,
  over: { rp?: boolean; port?: number } = {},
): Promise<{ origin: string; port: number; rpID: string; kill: () => Promise<void>; stderr: () => string }> {
  const port = over.port ?? (await freePort());
  const origin = `http://127.0.0.1:${port}`;
  const rpID = "localhost";
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    VERAX_STATE_DIR: stateDir,
    NODE_ENV: "development",
    VERAX_DEV_ISSUER_PORT: String(port),
    VERAX_AUDIENCE: "http://127.0.0.1/verax-passkey",
    VERAX_ISSUER: "http://127.0.0.1:8790",
    VERAX_DEV_SUB: "dev-brain",
    VERAX_DEV_OPERATOR_SUB: "operator-1",
  };
  if (over.rp !== false) {
    env.VERAX_RP_ID = rpID;
    env.VERAX_RP_ORIGINS = origin;
  } else {
    delete env.VERAX_RP_ID;
    delete env.VERAX_RP_ORIGINS;
  }
  const child = spawn(process.execPath, ["--experimental-strip-types", script, "--out", join(stateDir, "token")], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += String(chunk);
  });
  const closed = new Promise<number>((resolve) => child.once("close", (code) => resolve(code ?? 1)));
  const until = Date.now() + 8_000;
  let bound = "";
  while (Date.now() < until) {
    const match = LISTENING.exec(stderr);
    if (match) {
      bound = match[1] ?? "";
      break;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  if (bound === "") {
    child.kill("SIGTERM");
    await closed;
    throw new Error(`issuer did not start: ${stderr}`);
  }
  const boundPort = Number(bound);
  if (boundPort !== port) {
    child.kill("SIGTERM");
    await closed;
    throw new Error(`issuer bound ${boundPort}, wanted ${port}: ${stderr}`);
  }
  return {
    origin,
    port: boundPort,
    rpID,
    stderr: () => stderr,
    async kill() {
      child.kill("SIGTERM");
      await closed;
    },
  };
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const redirect = "http://127.0.0.1:5173/";
  return { verifier, challenge, redirect };
}

type EnrollBody = { challenge?: string; error?: string; enrolled?: boolean; sub?: string };

async function enroll(origin: string, rpID: string, code: string): Promise<{
  passkey: ReturnType<typeof mintSoftwarePasskey>;
  status: number;
  body: EnrollBody;
}> {
  const passkey = mintSoftwarePasskey();
  const opt = await fetch(`${origin}/enroll/options`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code }),
    signal: AbortSignal.timeout(LOCAL_FETCH_MS),
  });
  const options = (await opt.json()) as EnrollBody;
  if (opt.status !== 200) {
    return { passkey, status: opt.status, body: options };
  }
  assert.ok(options.challenge, `enroll options missing challenge: ${opt.status} ${options.error}`);
  const response = registerWithSoftwarePasskey(passkey, {
    challenge: options.challenge,
    rpID,
    origin,
  });
  const done = await fetch(`${origin}/enroll/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code, response }),
    signal: AbortSignal.timeout(LOCAL_FETCH_MS),
  });
  const body = (await done.json()) as EnrollBody;
  return { passkey, status: done.status, body };
}

async function signIn(origin: string, rpID: string, passkey: ReturnType<typeof mintSoftwarePasskey>) {
  const { verifier, challenge, redirect } = pkce();
  const opt = await fetch(`${origin}/authorize/options`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
    signal: AbortSignal.timeout(LOCAL_FETCH_MS),
  });
  const options = (await opt.json()) as { challenge?: string; error?: string };
  assert.equal(opt.status, 200, `signin options: ${opt.status} ${options.error}`);
  assert.ok(options.challenge);
  const assertion = assertWithSoftwarePasskey(passkey, {
    challenge: options.challenge,
    rpID,
    origin,
  });
  const done = await fetch(`${origin}/authorize/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      response: assertion,
      response_type: "code",
      client_id: "verax-panel",
      redirect_uri: redirect,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "st",
    }),
    signal: AbortSignal.timeout(LOCAL_FETCH_MS),
  });
  const body = (await done.json()) as { location?: string; error?: string; sub?: string };
  return { status: done.status, body, verifier, redirect };
}

async function exchange(origin: string, location: string, verifier: string, redirect: string) {
  const code = new URL(location).searchParams.get("code");
  assert.ok(code, "no code on location");
  const tokenRes = await fetch(`${origin}/token`, {
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
  assert.equal(tokenRes.status, 200);
  const tokenBody = (await tokenRes.json()) as { access_token?: string };
  assert.ok(tokenBody.access_token);
  return decodePayload(tokenBody.access_token);
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

describe("operator passkey sign-in", { concurrency: 1 }, () => {
  it("refuses a wrong pairing code, burns on the sixth try, and will not reuse a spent code", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-pairing-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      const wrong = await fetch(`${issuer.origin}/enroll/options`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: "00000000" }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(wrong.status, 400);
      assert.equal(((await wrong.json()) as { error?: string }).error, "mismatch");

      for (let i = 1; i < PAIRING_MAX_ATTEMPTS; i += 1) {
        await fetch(`${issuer.origin}/enroll/options`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code: "11111111" }),
        });
      }
      const sixth = await fetch(`${issuer.origin}/enroll/options`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(sixth.status, 400);
      assert.equal(((await sixth.json()) as { error?: string }).error, "burned");
      assert.equal(hasRegisteredOperator(stateDir), false);
    } finally {
      await issuer.kill();
    }
  });

  it("refuses an expired pairing code even when the digits match", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-expired-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir, Date.now() - PAIRING_TTL_MS - 1);
      writePairing(stateDir, {
        hash: hashPairingCode(code),
        expiresAtMs: Date.now() - 1,
        attempts: 0,
      });
      const late = await fetch(`${issuer.origin}/enroll/options`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(late.status, 400);
      assert.equal(((await late.json()) as { error?: string }).error, "expired");
    } finally {
      await issuer.kill();
    }
  });

  it("consumes the pairing code so a second enroll is refused", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-consume-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      const first = await enroll(issuer.origin, issuer.rpID, code);
      assert.equal(first.status, 200);
      assert.equal(first.body.enrolled, true);
      assert.equal(first.body.sub, "operator-1");
      assert.equal(hasRegisteredOperator(stateDir), true);
      const second = await enroll(issuer.origin, issuer.rpID, code);
      assert.equal(second.status, 400);
      assert.equal(second.body.error, "burned");
    } finally {
      await issuer.kill();
    }
  });

  it("a registered operator with a valid passkey gets approve, and the sub is not the agent's", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-ok-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      const page = await fetch(`${issuer.origin}/enroll`, { signal: AbortSignal.timeout(LOCAL_FETCH_MS) });
      assert.equal(page.status, 200);
      const vendor = await fetch(`${issuer.origin}/vendor/@simplewebauthn/browser/esm/index.js`, {
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(vendor.status, 200);
      const { passkey, status } = await enroll(issuer.origin, issuer.rpID, code);
      assert.equal(status, 200);
      const signed = await signIn(issuer.origin, issuer.rpID, passkey);
      assert.equal(signed.status, 200);
      assert.ok(signed.body.location);
      const claims = await exchange(issuer.origin, signed.body.location, signed.verifier, signed.redirect);
      assert.equal(claims.sub, "operator-1");
      assert.notEqual(claims.sub, "dev-brain");
      assert.equal(
        typeof claims.scope === "string" && claims.scope.split(/\s+/).includes("verax:approve"),
        true,
        `passkey session missing approve: ${claims.scope}`,
      );
    } finally {
      await issuer.kill();
    }
  });

  it("refuses a cloned authenticator when the counter does not advance", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-clone-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      const { passkey, status } = await enroll(issuer.origin, issuer.rpID, code);
      assert.equal(status, 200);
      const first = await signIn(issuer.origin, issuer.rpID, passkey);
      assert.equal(first.status, 200);
      const { challenge, redirect } = pkce();
      const opt = await fetch(`${issuer.origin}/authorize/options`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      const options = (await opt.json()) as { challenge?: string };
      assert.ok(options.challenge);
      const assertion = assertWithSoftwarePasskey(passkey, {
        challenge: options.challenge,
        rpID: issuer.rpID,
        origin: issuer.origin,
        counter: passkey.counter,
      });
      const replay = await fetch(`${issuer.origin}/authorize/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          response: assertion,
          response_type: "code",
          client_id: "verax-panel",
          redirect_uri: redirect,
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(replay.status >= 400, true);
      assert.equal(typeof ((await replay.json()) as { location?: string }).location, "undefined");
    } finally {
      await issuer.kill();
    }
  });

  it("a registered operator without a valid passkey gets no code, including for audit", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-denied-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      await enroll(issuer.origin, issuer.rpID, code);
      const { challenge, redirect } = pkce();
      const auth = await fetch(
        `${issuer.origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(auth.status, 200);
      assert.equal((auth.headers.get("location") ?? "").includes("code="), false);
      const html = await auth.text();
      assert.match(html, /passkey/i);
      const bogus = await fetch(`${issuer.origin}/authorize/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          response: { id: "nope", rawId: "nope", type: "public-key", response: {}, clientExtensionResults: {} },
          response_type: "code",
          client_id: "verax-panel",
          redirect_uri: redirect,
          code_challenge: challenge,
          code_challenge_method: "S256",
        }),
        signal: AbortSignal.timeout(LOCAL_FETCH_MS),
      });
      assert.equal(bogus.status >= 400, true);
      assert.equal(typeof ((await bogus.json()) as { location?: string }).location, "undefined");
    } finally {
      await issuer.kill();
    }
  });

  it("a signature from another key under the enrolled credential id gets no code", async () => {
    // The test above sends an id the issuer has never seen, so it is refused
    // before any signature is checked. With verification skipped it stayed
    // green; only the counter test noticed, and only by accident. Here the id
    // is real and the counter advances: the signature is the one thing wrong.
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-impostor-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      const { passkey, status } = await enroll(issuer.origin, issuer.rpID, code);
      assert.equal(status, 200);
      const impostor = { ...mintSoftwarePasskey(), id: passkey.id };
      const signed = await signIn(issuer.origin, issuer.rpID, impostor);
      assert.equal(signed.status >= 400, true, `impostor signed in: ${signed.status}`);
      assert.equal(signed.body.location, undefined);
    } finally {
      await issuer.kill();
    }
  });

  it("an unreadable credential file keeps authorize closed instead of reopening the old flow", async () => {
    // The file only exists because an operator enrolled. Reading a truncated
    // or mistyped file as "no operator" handed a read code to anyone who
    // asked, which is the passkey-less flow this gate exists to close.
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-unreadable-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { challenge, redirect } = pkce();
      const authorizeUrl = `${issuer.origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`;
      for (const broken of ['{"credentials": [', JSON.stringify({ credentials: [{ id: "a", publicKey: "b", counter: "0", sub: "operator-1" }] })]) {
        writeFileSync(join(stateDir, "operator-credentials.json"), broken, "utf8");
        const auth = await fetch(authorizeUrl, { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) });
        assert.equal((auth.headers.get("location") ?? "").includes("code="), false, `code minted for ${broken}`);
        assert.notEqual(auth.status, 302, `old flow reopened for ${broken}`);
        await auth.body?.cancel();
      }
    } finally {
      await issuer.kill();
    }
  });

  it("with no registered operator the old flow still opens and the session has no approve", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-legacy-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { verifier, challenge, redirect } = pkce();
      const auth = await fetch(
        `${issuer.origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(auth.status, 302);
      const location = auth.headers.get("location") ?? "";
      assert.match(location, /code=/);
      const claims = await exchange(issuer.origin, location, verifier, redirect);
      assert.equal(claims.sub, "operator-1");
      assert.equal(
        typeof claims.scope === "string" && claims.scope.split(/\s+/).includes("verax:approve"),
        false,
        `legacy session carries approve: ${claims.scope}`,
      );
      assert.match(issuer.stderr(), /passkey enroll and sign-in are closed|listening/);
    } finally {
      await issuer.kill();
    }
  });

  it("without RP config, enroll is closed and desktop-style authorize still mints a read-only session", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-norp-"));
    const issuer = await startIssuer(stateDir, { rp: false });
    try {
      assert.match(issuer.stderr(), /passkey enroll and sign-in are closed: VERAX_RP_ID is unset/);
      const enrollRes = await fetch(`${issuer.origin}/enroll`, { signal: AbortSignal.timeout(LOCAL_FETCH_MS) });
      assert.equal(enrollRes.status, 503);
      const { verifier, challenge, redirect } = pkce();
      const auth = await fetch(
        `${issuer.origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(LOCAL_FETCH_MS) },
      );
      assert.equal(auth.status, 302);
      const claims = await exchange(issuer.origin, auth.headers.get("location") ?? "", verifier, redirect);
      assert.equal(
        typeof claims.scope === "string" && claims.scope.split(/\s+/).includes("verax:approve"),
        false,
      );
    } finally {
      await issuer.kill();
    }
  });

  it("spend defers, a passkey session approves over HTTP, and the ledger names the operator", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-passkey-e2e-"));
    const issuer = await startIssuer(stateDir);
    try {
      const { code } = beginPairing(stateDir);
      const { passkey } = await enroll(issuer.origin, issuer.rpID, code);
      const signed = await signIn(issuer.origin, issuer.rpID, passkey);
      const operatorClaims = await exchange(issuer.origin, signed.body.location ?? "", signed.verifier, signed.redirect);
      const agentToken = (
        await import("node:fs")
      ).readFileSync(join(stateDir, "token"), "utf8").trim();
      const agentClaims = decodePayload(agentToken);
      assert.equal(agentClaims.sub, "dev-brain");
      assert.notEqual(operatorClaims.sub, agentClaims.sub);

      const signedIn = await signIn(issuer.origin, issuer.rpID, passkey);
      const operatorToken = (
        await (
          await fetch(`${issuer.origin}/token`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              code: new URL(signedIn.body.location ?? "").searchParams.get("code") ?? "",
              redirect_uri: signedIn.redirect,
              code_verifier: signedIn.verifier,
              client_id: "verax-panel",
            }),
          })
        ).json()
      ) as { access_token?: string };
      assert.ok(operatorToken.access_token);

      const body = await listen({
        issuer: "http://127.0.0.1:8790",
        jwksUrl: `${issuer.origin}/.well-known/jwks.json`,
        audience: "http://127.0.0.1/verax-passkey",
        stateDir: join(stateDir, "body"),
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile: approvePolicyFile(stateDir),
        tlsTerminated: false,
      });
      const port = (body.address() as { port: number }).port;
      const base = `http://127.0.0.1:${port}`;
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
          headers: { authorization: `Bearer ${operatorToken.access_token}` },
        });
        assert.equal(listed.status, 200);
        const ledger = (await listed.json()) as {
          approvals?: { ref: string; requestHash: string; status?: string }[];
          decisions?: { claims: { decision: string } }[];
        };
        const waiting = (ledger.approvals ?? []).find((a) => a.status === "pending" || a.status === undefined);
        assert.ok(waiting, "nothing is waiting");
        const ok = await fetch(`${base}/api/approve`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${operatorToken.access_token}`,
          },
          body: JSON.stringify({ ref: waiting.ref, requestHash: waiting.requestHash }),
        });
        assert.equal(ok.status, 200);
        const first = (await ok.json()) as { allowRef?: string; approver?: string };
        assert.equal(first.approver, "operator-1");
        const after = await fetch(`${base}/api/ledger?from=0&to=${Number.MAX_SAFE_INTEGER}`, {
          headers: { authorization: `Bearer ${operatorToken.access_token}` },
        });
        const seen = (await after.json()) as {
          decisions?: { claims: { decision: string } }[];
          inputs?: Record<string, { principal?: { brain?: string }; approver?: { id?: string; via?: string } }>;
        };
        assert.ok((seen.decisions ?? []).some((d) => d.claims.decision === "allow"));
        const approver = first.allowRef ? seen.inputs?.[first.allowRef]?.approver : undefined;
        assert.equal(approver?.id, "operator-1");
        assert.equal(approver?.via, "http");
        assert.equal(first.allowRef ? seen.inputs?.[first.allowRef]?.principal?.brain : undefined, "dev-brain");
      } finally {
        await new Promise<void>((resolve, reject) => {
          body.close((err) => (err ? reject(err) : resolve()));
        });
      }
    } finally {
      await issuer.kill();
    }
  });
});
