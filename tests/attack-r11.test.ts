// R11: each `it` asserts the safe behaviour. On 0ddf9c4 the implementation
// does the unsafe thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { createVerifier } from "../packages/body/src/auth.ts";
import { loadConfig } from "../packages/body/src/config.ts";
import { desktopChildExitedLine, superviseDesktopChildren } from "../packages/body/src/desktop.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { pinnedApproveTarget } from "../apps/panel/src/records/approve-target.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const issuerScript = join(root, "scripts", "dev-issuer.mjs");
const golden = join(root, "packages", "proxy", "tests", "fixtures", "ledger-golden");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function copyGolden(): string {
  const dir = ownerDir("verax-r11-ledger-");
  for (const name of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, name), join(dir, name));
  }
  return dir;
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

describe("attack R11", () => {
  it("R11-1 a non-object token body is 400 and the issuer stays up", { timeout: 60_000 }, async () => {
    const stateDir = ownerDir("verax-r11-issuer-");
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
    const outcome = await Promise.race([
      closed.then((code) => ({ kind: "closed" as const, code })),
      listeningPort(() => stderr).then((port) => ({ kind: "ready" as const, port })),
    ]);
    try {
      if (outcome.kind === "closed") assert.fail(`issuer exited ${outcome.code}: ${stderr}`);
      const port = Number(outcome.port);
      assert.equal(Number.isInteger(port) && port > 0, true, stderr);
      const origin = `http://127.0.0.1:${port}`;
      for (const body of ["null", "[]", '"x"']) {
        const res = await fetch(`${origin}/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
        });
        assert.equal(res.status, 400, body);
        const parsed = (await res.json()) as { error?: string };
        assert.equal(parsed.error, "bad-request", body);
      }
      const jwks = await fetch(`${origin}/.well-known/jwks.json`);
      assert.equal(jwks.status, 200);
      assert.equal(child.exitCode, null);
    } finally {
      child.kill("SIGTERM");
      await closed;
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R11-1 desktop stops every child when the issuer exits", async () => {
    const stopped: string[] = [];
    const fire: Partial<Record<"issuer" | "body" | "panel", () => void>> = {};
    const exited = superviseDesktopChildren(
      (["issuer", "body", "panel"] as const).map((name) => ({
        name,
        onExit: (listener: () => void) => {
          fire[name] = listener;
        },
      })),
      () => {
        stopped.push("stop");
      },
    );
    assert.equal(desktopChildExitedLine("issuer"), "desktop-child-exited:issuer\n");
    fire.issuer?.();
    assert.equal(await exited, "issuer");
    assert.deepEqual(stopped, ["stop"]);
    fire.body?.();
    fire.panel?.();
    assert.deepEqual(stopped, ["stop"]);
  });

  it("R11-1 a signing key outside the pinned set does not verify", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), alg: "ES256", use: "sig", kid: "verax-dev" };
    const pin = { keys: [jwk] };
    const issuer = "http://127.0.0.1:8790";
    const audience = "http://127.0.0.1:8787";
    const stateDir = ownerDir("verax-r11-pin-");
    try {
      const loaded = loadConfig({
        VERAX_ISSUER: issuer,
        VERAX_JWKS_URL: "http://127.0.0.1:1/jwks.json",
        VERAX_JWKS_PIN: JSON.stringify(pin),
        VERAX_AUDIENCE: audience,
        VERAX_STATE_DIR: stateDir,
        VERAX_POLICY_FILE: "policy.json",
        VERAX_BIND: "127.0.0.1:8787",
      });
      assert.equal(loaded.ok, true);
      if (!loaded.ok) return;
      assert.equal(loaded.value.jwksFile, null);
      const verify = createVerifier(
        loaded.value.jwksUrl,
        issuer,
        audience,
        loaded.value.jwksFile,
        loaded.value.jwksPin,
      );
      const good = await new SignJWT({ scope: "verax:approve" })
        .setProtectedHeader({ alg: "ES256", kid: "verax-dev" })
        .setSubject("operator-1")
        .setIssuer(issuer)
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime("10m")
        .sign(privateKey);
      const verified = await verify(good);
      assert.equal(verified.principal.brain, "operator-1");

      const other = await generateKeyPair("ES256", { extractable: true });
      const evil = await new SignJWT({ scope: "verax:approve" })
        .setProtectedHeader({ alg: "ES256", kid: "attacker" })
        .setSubject("attacker")
        .setIssuer(issuer)
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime("10m")
        .sign(other.privateKey);
      await assert.rejects(() => verify(evil));
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R11-2 an open confirmation does not follow a different row", () => {
    const captured = { ref: "A", requestHash: "aa".repeat(32) };
    assert.equal(pinnedApproveTarget(captured, { ref: "B", requestHash: "bb".repeat(32) }), null);
    assert.equal(pinnedApproveTarget(captured, { ref: "A", requestHash: "bb".repeat(32) }), null);
    assert.deepEqual(pinnedApproveTarget(captured, captured), captured);
  });

  it("R11-3 an Ed448 pinned key is a problem and the body refuses one at start", async () => {
    const ed = generateKeyPairSync("ed448");
    const pem = ed.publicKey.export({ type: "spki", format: "pem" }).toString();
    const dir = copyGolden();
    const stateDir = ownerDir("verax-r11-ed448-");
    try {
      const verdict = await verifyLedger(dir, {
        publicKeyPem: pem,
        effectPublicKeyPem: pem,
        checkpointPublicKeyPem: pem,
      });
      assert.equal(verdict.ok, false, JSON.stringify(verdict.problems));
      assert.ok(
        verdict.problems.some((problem) => problem === "public key is not ed25519"),
        JSON.stringify(verdict.problems),
      );

      const keyDir = join(stateDir, "keys");
      mkdirSync(keyDir, { recursive: true, mode: 0o700 });
      const ok = generateKeyPairSync("ed25519");
      writeFileSync(join(keyDir, "record.public.pem"), pem);
      writeFileSync(join(keyDir, "record.private.pem"), ed.privateKey.export({ type: "pkcs8", format: "pem" }));
      writeFileSync(join(keyDir, "effect.public.pem"), ok.publicKey.export({ type: "spki", format: "pem" }));
      writeFileSync(join(keyDir, "effect.private.pem"), ok.privateKey.export({ type: "pkcs8", format: "pem" }));
      assert.throws(() => loadOrCreateSigners(stateDir), /not ed25519/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R11-4 {} in checkpoints.jsonl is a problem", async () => {
    const dir = copyGolden();
    try {
      writeFileSync(join(dir, "checkpoints.jsonl"), "{}\n");
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => problem === "checkpoint line 1 is not a checkpoint"),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R11-5 a corrupt manifest is not verified and the CLI answers with JSON", async () => {
    const dir = copyGolden();
    try {
      writeFileSync(join(dir, "ledger-manifest.json"), "{");
      let result: Awaited<ReturnType<typeof verifyLedger>>;
      try {
        result = await verifyLedger(dir);
      } catch (err) {
        assert.fail(`verifyLedger threw: ${err instanceof Error ? err.message : err}`);
      }
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /manifest/i.test(problem)),
        JSON.stringify(result.problems),
      );

      const jsonLines: string[] = [];
      const jsonCode = await runVerify([dir, "--json"], (line) => jsonLines.push(line));
      assert.equal(jsonCode, 1);
      const parsed = JSON.parse(jsonLines.join("\n")) as { ok?: boolean; problems?: unknown };
      assert.equal(parsed.ok, false);
      assert.ok(Array.isArray(parsed.problems));

      const textLines: string[] = [];
      const textCode = await runVerify([dir], (line) => textLines.push(line));
      const text = textLines.join("\n");
      assert.equal(textCode, 1, text);
      assert.match(text, /NOT VERIFIED/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
