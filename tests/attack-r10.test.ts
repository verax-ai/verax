// R10: independent of the earlier rounds. Each `it` asserts the safe
// behaviour. On the current tree the implementation does the unsafe thing,
// so the assertion fails. A fix should turn that assertion green without
// weakening it.

import { strict as assert } from "node:assert";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { createProxy, FileLedger, loadPolicy, verifyLedger } from "@verax-ai/proxy";

import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "../packages/proxy/tests/helpers.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const issuerScript = join(root, "scripts", "dev-issuer.mjs");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;

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

/**
 * A signed deny of memory.get. When `effectClass` is set, a signed effect of
 * that class is appended on the same ref before the ledger is closed.
 */
async function deniedMemoryLedger(ref: string, effectClass?: string): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-r10-deny-"));
  const ledger = new FileLedger(dir);
  try {
    const proxy = createProxy({
      policy: loadPolicy({ version: 1, default: "deny", rules: [] }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce([ref]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      { name: "memory.get", arguments: { id: "a", _ref: ref } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    if (effectClass !== undefined) {
      await ledger.appendEffect({
        ref,
        effectHash: "ab".repeat(32),
        effectClass,
        timestampMs: 99,
        actor: "brain-1",
      });
    }
  } finally {
    ledger.close();
  }
  return dir;
}

describe("attack R10", () => {
  it("R10-1 verify does not bind a :threw effect to a decision that did not throw that class", async () => {
    const otherClass = await deniedMemoryLedger("deny-ref", "spend:threw");
    const sameStem = await deniedMemoryLedger("deny-stem", "memory.get:threw");
    const pins = {
      publicKeyPem: RECORD_SIGNER.publicKeyPem,
      effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
    };
    try {
      const other = await verifyLedger(otherClass, pins);
      assert.equal(other.ok, false, JSON.stringify(other.problems));
      assert.equal(other.effectsBound, 0, JSON.stringify(other));
      assert.ok(
        other.problems.some((problem) => /deny-ref/.test(problem)),
        JSON.stringify(other.problems),
      );

      const stem = await verifyLedger(sameStem, pins);
      assert.equal(stem.ok, false, JSON.stringify(stem.problems));
      assert.equal(stem.effectsBound, 0, JSON.stringify(stem));
      assert.ok(
        stem.problems.some((problem) => /deny-stem/.test(problem)),
        JSON.stringify(stem.problems),
      );
    } finally {
      rmSync(otherClass, { recursive: true, force: true });
      rmSync(sameStem, { recursive: true, force: true });
    }
  });

  it("R10-2 a token minted with no passkey does not carry verax:audit", { timeout: 20_000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-r10-issuer-"));
    const outPath = join(stateDir, "token");
    const child = spawn(process.execPath, ["--experimental-strip-types", issuerScript, "--out", outPath], {
      env: {
        ...process.env,
        VERAX_STATE_DIR: stateDir,
        NODE_ENV: "development",
        VERAX_DEV_ISSUER_PORT: "0",
        VERAX_DEV_ISSUER_TRACE: "1",
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
      const port = Number(outcome.port);
      assert.equal(Number.isInteger(port) && port > 0, true, `issuer did not bind: ${stderr}`);
      const origin = `http://127.0.0.1:${port}`;
      const jwks = createRemoteJWKSet(new URL(`${origin}/.well-known/jwks.json`));
      const verifyOpts = { issuer: "http://127.0.0.1:8790", audience: "http://127.0.0.1:8787" };
      const hasAudit = (scope: unknown): boolean =>
        typeof scope === "string" && scope.split(/\s+/).includes("verax:audit");

      const agentToken = readFileSync(outPath, "utf8").trim();
      const agent = await jwtVerify(agentToken, jwks, verifyOpts);
      assert.equal(hasAudit(agent.payload.scope), false, `agent file scope=${String(agent.payload.scope)}`);

      const redirect = "http://127.0.0.1:5173/";
      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const auth = await fetch(
        `${origin}/authorize?response_type=code&client_id=verax-panel&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { redirect: "manual", signal: AbortSignal.timeout(10_000) },
      );
      assert.equal(auth.status, 302, `authorize status=${auth.status}`);
      const code = new URL(auth.headers.get("location") ?? "", origin).searchParams.get("code");
      assert.equal(typeof code === "string" && code.length > 0, true);
      const tokenRes = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: redirect,
          code_verifier: verifier,
        }),
        signal: AbortSignal.timeout(10_000),
      });
      assert.equal(tokenRes.status, 200);
      const body = (await tokenRes.json()) as { access_token?: string };
      const session = await jwtVerify(body.access_token ?? "", jwks, verifyOpts);
      assert.equal(hasAudit(session.payload.scope), false, `session scope=${String(session.payload.scope)}`);
      assert.equal(
        typeof session.payload.scope === "string" && session.payload.scope.split(/\s+/).includes("verax:approve"),
        false,
      );
    } finally {
      child.kill("SIGTERM");
      await closed;
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R10-3 verify does not follow a manifest piece outside the directory", async () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-r10-escape-"));
    const real = join(parent, "real");
    const wrap = join(parent, "wrap");
    try {
      mkdirSync(real);
      const built = await deniedMemoryLedger("inside-ref");
      try {
        cpSync(join(built, "decisions.jsonl"), join(real, "decisions.jsonl"));
      } finally {
        rmSync(built, { recursive: true, force: true });
      }
      mkdirSync(wrap);
      writeFileSync(join(wrap, "decisions.jsonl"), `${JSON.stringify({ claims: { ref: "lie", decision: "allow" } })}\n`);
      writeFileSync(
        join(wrap, "ledger-manifest.json"),
        `${JSON.stringify({
          version: 1,
          pieces: [
            {
              id: "p",
              decisions: "../real/decisions.jsonl",
              effects: "effects.jsonl",
              inputs: "inputs.jsonl",
              n: 1,
              effectN: 0,
              firstMs: null,
              lastMs: null,
              lastHash: null,
              closed: false,
            },
          ],
          countedAtMs: [],
        })}\n`,
      );
      const pins = {
        publicKeyPem: RECORD_SIGNER.publicKeyPem,
        effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
      };
      const direct = await verifyLedger(real, pins);
      assert.equal(direct.ok, true, JSON.stringify(direct.problems));
      const result = await verifyLedger(wrap, pins);
      assert.equal(result.ok, false, JSON.stringify(result));
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
});
