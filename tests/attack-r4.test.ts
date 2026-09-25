// R4: breaks outside install, and outside R1–R3. Each `it` asserts the safe
// behaviour. On the current tree the implementation does the unsafe thing, so
// the assertion fails. A fix should turn that assertion green without weakening it.

import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { beginPairing } from "../packages/body/src/operator-pairing.ts";
import { memoryPut } from "../packages/body/src/tools/memory.ts";
import { signEffectAttestation } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { reconcile } from "../packages/proxy/src/reconcile.ts";
import type { LedgerEffect } from "../packages/proxy/src/types.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey, registerWithSoftwarePasskey } from "./software-passkey.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const golden = join(root, "packages", "proxy", "tests", "fixtures", "ledger-golden");
const issuerScript = join(root, "scripts", "dev-issuer.mjs");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;

const SPEND_POLICY = {
  version: 1,
  default: "deny",
  rules: [
    {
      id: "spend-true",
      tool: "spend",
      requires: ["verax:pay"],
      mode: "approve",
      text: "Spends need operator approval.",
      spend: { maxAmountMinor: 200_000, currency: "TRY", payees: ["true-ads"], dailyMaxMinor: 300_000 },
    },
  ],
};

function copyGolden(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-attack-r4-verify-"));
  for (const name of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, name), join(dir, name));
  }
  return dir;
}

/** Rewrites the first golden effect row. */
function editFirstEffect(dir: string, edit: (row: LedgerEffect & Record<string, unknown>) => void): void {
  const path = join(dir, "effects.jsonl");
  const lines = readFileSync(path, "utf8").split("\n");
  const first = lines.findIndex((line) => line.trim() !== "");
  const row = JSON.parse(lines[first]!) as LedgerEffect & Record<string, unknown>;
  edit(row);
  lines[first] = JSON.stringify(row);
  writeFileSync(path, lines.join("\n"), "utf8");
}

function httpPost(
  port: number,
  hostHeader: string,
  path: string,
  body: string,
  extra: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: {
          host: hostHeader,
          connection: "close",
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          ...extra,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
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

describe("attack R4", () => {
  it("R4-1 verify rejects an effect whose hash or result no longer matches its decision", async () => {
    const dir = copyGolden();
    try {
      const path = join(dir, "effects.jsonl");
      const lines = readFileSync(path, "utf8").split("\n");
      const first = lines.findIndex((line) => line.trim() !== "");
      assert.ok(first >= 0, "golden effect missing");
      const row = JSON.parse(lines[first]!) as {
        resultHash?: string;
        row?: { effectHash?: string; effectClass?: string; ref?: string };
      };
      assert.equal(typeof row.row?.ref, "string");
      row.resultHash = "0".repeat(64);
      if (row.row) {
        row.row.effectHash = "f".repeat(64);
        row.row.effectClass = "spend";
      }
      lines[first] = JSON.stringify(row);
      writeFileSync(path, lines.join("\n"), "utf8");

      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /effect/i.test(problem)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R4-1b verify rejects a golden effect whose attestation was stripped and result rewritten", async () => {
    const dir = copyGolden();
    try {
      editFirstEffect(dir, (row) => {
        delete row.attestation;
        delete row.receipt;
        row.resultHash = "0".repeat(64);
      });
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R4-1c verify rejects an unsigned :threw effect with a made-up hash", async () => {
    const dir = copyGolden();
    try {
      editFirstEffect(dir, (row) => {
        delete row.attestation;
        delete row.receipt;
        row.row = { ...row.row, effectClass: "spend:threw", effectHash: "e".repeat(64) };
      });
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R4-1d verify does not trust a key the effect row brings with it", async () => {
    const dir = copyGolden();
    try {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const signer = {
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      };
      editFirstEffect(dir, (row) => {
        const forged = "0".repeat(64);
        const signed = signEffectAttestation(row.row, row.witnessClass, forged, signer);
        row.resultHash = forged;
        row.attestation = signed.attestation;
        row.receipt = signed.receipt;
      });
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R4-1e the golden ledger verifies when the effect key is pinned", async () => {
    const dir = copyGolden();
    try {
      const first = JSON.parse(readFileSync(join(dir, "effects.jsonl"), "utf8").split("\n").find((line) => line.trim() !== "")!) as {
        receipt?: { publicKeyPem?: string };
      };
      const pem = first.receipt?.publicKeyPem;
      assert.equal(typeof pem, "string");
      const result = await verifyLedger(dir, { effectPublicKeyPem: pem });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.effectTrust.source, "pinned");
      assert.equal(result.effectTrust.publicKeyPem?.trim(), pem?.trim());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R4-1f a wrong pinned effect key rejects the golden ledger", async () => {
    const dir = copyGolden();
    try {
      const { publicKey } = generateKeyPairSync("ed25519");
      const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
      const result = await verifyLedger(dir, { effectPublicKeyPem: pem });
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.equal(result.effectTrust.source, "pinned");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R4-2 a spend reference cannot redraw the approve line", async () => {
    const policy = loadPolicy(SPEND_POLICY);
    const verdict = policy.evaluate(
      {
        name: "spend",
        arguments: {
          amountMinor: 100,
          currency: "TRY",
          payee: "true-ads",
          reference: "inv\rheld tool=spend payee=other-ads amount=100 currency=TRY reference=ok",
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:pay"]) },
    );
    assert.equal(verdict.reasonCode, "spend-args-invalid");

    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r4-approve-"));
    try {
      const ref = "spend-ref-1";
      const pending = {
        ref,
        requestHash: "abc123abc123deadbeef",
        subject: "spend",
        args: {
          amountMinor: 100,
          currency: "TRY",
          payee: "true-ads",
          reference: "inv\rheld tool=spend payee=other-ads amount=100 currency=TRY reference=ok",
        },
        ruleId: "spend-true",
        ruleText: "Spends need operator approval.",
        inputsSummary: { count: 0, ids: [] },
        amount: 100,
        payee: "true-ads",
        currency: "TRY",
        expiresAtMs: Date.now() + 60_000,
        status: "pending",
        brain: "brain-1",
      };
      writeFileSync(join(stateDir, "approvals.jsonl"), `${JSON.stringify(pending)}\n`, "utf8");
      const out: string[] = [];
      await runApprove(
        ["approve", stateDir, ref],
        () => {},
        (line) => out.push(line),
        { isTTY: true, ask: async () => "100" },
      );
      const held = out.find((line) => line.startsWith("held ")) ?? "";
      assert.equal(held.includes("\r"), false, JSON.stringify(held));
      assert.match(held, /payee=true-ads/);
      assert.doesNotMatch(held, /payee=other-ads/);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R4-3 reconcile does not match an effect that has no decision", () => {
    const effect: LedgerEffect = {
      row: {
        actor: "brain-1",
        effectClass: "spend",
        effectHash: "ab".repeat(32),
        ref: "ghost-spend",
        timestampMs: 1_700_000_000_000,
      },
      witnessClass: "self",
    };
    const report = reconcile(
      [
        {
          channel: "sent",
          externalId: "ext-1",
          occurredAtMs: 1_700_000_000_000,
          subject: "spend",
          ref: "ghost-spend",
        },
      ],
      [effect],
    );
    assert.equal(report.matched.length, 0, JSON.stringify(report.matched));
    assert.equal(report.ghost.length, 1);
  });

  it("R4-4 a tenant cannot fill the disk through memory.put", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r4-memory-"));
    const principal = { brain: "brain-1", iss: "https://issuer.example", scopes: new Set(["verax:memory"]) };
    const chunk = "x".repeat(700_000);
    try {
      const first = await memoryPut(
        { name: "memory.put", arguments: { id: "note-a", body: chunk, source: { kind: "agent" }, validUntilMs: 9_999_999_999_999 } },
        stateDir,
        principal,
      );
      assert.equal(first.isError, false, first.content[0]?.text);
      const second = await memoryPut(
        { name: "memory.put", arguments: { id: "note-b", body: chunk, source: { kind: "agent" }, validUntilMs: 9_999_999_999_999 } },
        stateDir,
        principal,
      );
      assert.equal(second.isError, true, second.content[0]?.text);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R4-5 the issuer does not revoke a jti for a rebound browser", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r4-issuer-"));
    const port = await freePort();
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", issuerScript, "--out", join(stateDir, "token")],
      {
        env: {
          ...process.env,
          VERAX_STATE_DIR: stateDir,
          NODE_ENV: "development",
          VERAX_DEV_ISSUER_PORT: String(port),
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += String(chunk);
    });
    const closed = new Promise<number>((resolve) => child.once("close", (code) => resolve(code ?? 1)));
    try {
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
      assert.ok(bound !== "", `issuer did not start: ${stderr}`);
      const res = await httpPost(Number(bound), "rebind.example", "/revoke", JSON.stringify({ jti: "not-a-session" }));
      assert.equal(res.status, 401, res.body);
      const revoked = join(stateDir, "revoked-jti.jsonl");
      const text = existsSync(revoked) ? readFileSync(revoked, "utf8") : "";
      assert.equal(text.includes("not-a-session"), false);
      // A rebound page sends the attacker name with the real port. A valid bearer does not open it:
      // the Host check answers (401) before the scope check (403) could.
      const agent = readFileSync(join(stateDir, "token"), "utf8").trim();
      const withBearer = await httpPost(Number(bound), `rebind.example:${bound}`, "/revoke", JSON.stringify({ jti: "x" }), {
        authorization: `Bearer ${agent}`,
      });
      assert.equal(withBearer.status, 401, withBearer.body);
    } finally {
      child.kill("SIGTERM");
      await closed;
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R4-5b revoke accepts an operator token and refuses an agent token", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r4-revoke-scope-"));
    const port = await freePort();
    const origin = `http://127.0.0.1:${port}`;
    const child = spawn(process.execPath, ["--experimental-strip-types", issuerScript, "--out", join(stateDir, "token")], {
      env: {
        ...process.env,
        VERAX_STATE_DIR: stateDir,
        NODE_ENV: "development",
        VERAX_DEV_ISSUER_PORT: String(port),
        VERAX_RP_ID: "localhost",
        VERAX_RP_ORIGINS: origin,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += String(chunk);
    });
    const closed = new Promise<number>((resolve) => child.once("close", (code) => resolve(code ?? 1)));
    try {
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
      assert.equal(bound, String(port), `issuer did not bind the requested port: ${stderr}`);
      const live = origin;
      const agent = readFileSync(join(stateDir, "token"), "utf8").trim();
      const agentRevoke = await fetch(`${live}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${agent}` },
        body: JSON.stringify({ jti: "agent-must-not-revoke" }),
      });
      assert.equal(agentRevoke.status, 403, await agentRevoke.text());

      const { code } = beginPairing(stateDir);
      const passkey = mintSoftwarePasskey();
      const opt = await fetch(`${live}/enroll/options`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const options = (await opt.json()) as { challenge?: string; error?: string };
      assert.equal(opt.status, 200, options.error);
      assert.ok(options.challenge);
      const registered = registerWithSoftwarePasskey(passkey, { challenge: options.challenge, rpID: "localhost", origin: live });
      const enrolled = await fetch(`${live}/enroll/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code, response: registered }),
      });
      assert.equal(enrolled.status, 200, await enrolled.text());

      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const redirect = "http://127.0.0.1:5173/";
      const signOpt = await fetch(`${live}/authorize/options`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const signOptions = (await signOpt.json()) as { challenge?: string };
      assert.equal(signOpt.status, 200);
      assert.ok(signOptions.challenge);
      const assertion = assertWithSoftwarePasskey(passkey, { challenge: signOptions.challenge, rpID: "localhost", origin: live });
      const signedIn = await fetch(`${live}/authorize/verify`, {
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
      });
      const signedBody = (await signedIn.json()) as { location?: string; error?: string };
      assert.equal(signedIn.status, 200, signedBody.error);
      assert.ok(signedBody.location);
      const authCode = new URL(signedBody.location).searchParams.get("code");
      assert.ok(authCode);
      const tokenRes = await fetch(`${live}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: redirect,
          code_verifier: verifier,
          client_id: "verax-panel",
        }),
      });
      const tokenBody = (await tokenRes.json()) as { access_token?: string };
      assert.equal(tokenRes.status, 200);
      assert.ok(tokenBody.access_token);
      const operatorRevoke = await fetch(`${live}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${tokenBody.access_token}` },
        body: JSON.stringify({ jti: "operator-may-revoke" }),
      });
      assert.equal(operatorRevoke.status, 200, await operatorRevoke.text());
      assert.match(readFileSync(join(stateDir, "revoked-jti.jsonl"), "utf8"), /operator-may-revoke/);
      assert.equal(readFileSync(join(stateDir, "revoked-jti.jsonl"), "utf8").includes("agent-must-not-revoke"), false);
    } finally {
      child.kill("SIGTERM");
      await closed;
      rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
