// F18: the four cases attack-r10.test.ts does not pin. Each `it` asserts the
// safe behaviour on the fixed tree. Both keys are pinned on every verifyLedger.

import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

const pins = {
  publicKeyPem: RECORD_SIGNER.publicKeyPem,
  effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
};

const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

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

function allowMemory() {
  return loadPolicy({
    version: 1,
    default: "deny",
    rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
  });
}

function effectClassesOnDisk(dir: string): string[] {
  const text = readFileSync(join(dir, "effects.jsonl"), "utf8");
  const classes: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const row = JSON.parse(line) as { row?: { effectClass?: string } };
    if (typeof row.row?.effectClass === "string") classes.push(row.row.effectClass);
  }
  return classes;
}

function writePieceManifest(dir: string, decisions: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "decisions.jsonl"), `${JSON.stringify({ claims: { ref: "lie", decision: "allow" } })}\n`);
  writeFileSync(
    join(dir, "ledger-manifest.json"),
    `${JSON.stringify({
      version: 1,
      pieces: [
        {
          id: "p",
          decisions,
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
}

describe("F18 R10 fixes", () => {
  it("a thrown allow of memory.get verifies and the effect row is memory.get:threw", async () => {
    const ref = "threw-ref";
    const dir = mkdtempSync(join(tmpdir(), "verax-f18-threw-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: allowMemory(),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce([ref]),
        inner: async () => {
          throw new Error("tool threw");
        },
      });
      await assert.rejects(() =>
        proxy.call({ name: "memory.get", arguments: { id: "a", _ref: ref } }, reader),
      );
    } finally {
      ledger.close();
    }
    try {
      const result = await verifyLedger(dir, pins);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.effectsBound, 1, JSON.stringify(result));
      assert.ok(effectClassesOnDisk(dir).includes("memory.get:threw"), effectClassesOnDisk(dir).join(","));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("spend:threw on an allow of memory.get does not bind", async () => {
    const ref = "allow-foreign";
    const dir = mkdtempSync(join(tmpdir(), "verax-f18-foreign-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: allowMemory(),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce([ref]),
        inner: async () => {
          // The allow is already on disk. This row is a different tool on that
          // ref. Closing drops the lock so the proxy's own effect is not written.
          await ledger.appendEffect({
            ref,
            effectHash: "ab".repeat(32),
            effectClass: "spend:threw",
            timestampMs: 99,
            actor: "brain-1",
          });
          ledger.close();
          throw new Error("foreign effect only");
        },
      });
      await assert.rejects(() =>
        proxy.call({ name: "memory.get", arguments: { id: "a", _ref: ref } }, reader),
      );
    } finally {
      ledger.close();
    }
    try {
      assert.deepEqual(effectClassesOnDisk(dir), ["spend:threw"]);
      const result = await verifyLedger(dir, pins);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.equal(result.effectsBound, 0, JSON.stringify(result));
      assert.ok(
        result.problems.some((problem) => problem.includes(ref)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it(
    "VERAX_DEV_SCOPE cannot put verax:audit or verax:approve on the --out token",
    { timeout: 20_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-f18-issuer-"));
      const outPath = join(stateDir, "token");
      const child = spawn(process.execPath, ["--experimental-strip-types", issuerScript, "--out", outPath], {
        env: {
          ...process.env,
          VERAX_STATE_DIR: stateDir,
          NODE_ENV: "development",
          VERAX_DEV_ISSUER_PORT: "0",
          VERAX_DEV_ISSUER_TRACE: "1",
          VERAX_DEV_SCOPE: "verax:read verax:memory verax:audit verax:approve",
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
        const agentToken = readFileSync(outPath, "utf8").trim();
        const agent = await jwtVerify(agentToken, jwks, {
          issuer: "http://127.0.0.1:8790",
          audience: "http://127.0.0.1:8787",
        });
        const parts =
          typeof agent.payload.scope === "string" ? agent.payload.scope.split(/\s+/).filter((part) => part !== "") : [];
        assert.equal(parts.includes("verax:audit"), false, `agent file scope=${String(agent.payload.scope)}`);
        assert.equal(parts.includes("verax:approve"), false, `agent file scope=${String(agent.payload.scope)}`);
        assert.equal(parts.includes("verax:read"), true, `agent file scope=${String(agent.payload.scope)}`);
        assert.equal(parts.includes("verax:memory"), true, `agent file scope=${String(agent.payload.scope)}`);
      } finally {
        child.kill("SIGTERM");
        await closed;
        rmSync(stateDir, { recursive: true, force: true });
      }
    },
  );

  it("manifest piece paths that leave the directory are refused", async () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-f18-escape-"));
    const real = join(parent, "real");
    const uncBack = "\\\\127.0.0.1\\c$\\x\\decisions.jsonl";
    const uncForward = "//127.0.0.1/c$/x/decisions.jsonl";
    try {
      // FileLedger refuses a directory other users can read (0700 on POSIX).
      mkdirSync(real, { mode: 0o700 });
      const ledger = new FileLedger(real);
      try {
        const proxy = createProxy({
          policy: loadPolicy({ version: 1, default: "deny", rules: [] }),
          recordSigner: RECORD_SIGNER,
          effectSigner: EFFECT_SIGNER,
          ledger,
          now: tickingNow(),
          nonce: queuedNonce(["inside-ref"]),
          inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
        });
        await proxy.call(
          { name: "memory.get", arguments: { id: "a", _ref: "inside-ref" } },
          reader,
        );
      } finally {
        ledger.close();
      }
      const direct = await verifyLedger(real, pins);
      assert.equal(direct.ok, true, JSON.stringify(direct.problems));

      const absolute = join(real, "decisions.jsonl");
      const cases: { name: string; decisions: string }[] = [
        { name: "absolute", decisions: absolute },
        { name: "unc-back", decisions: uncBack },
        { name: "unc-forward", decisions: uncForward },
      ];
      for (const piece of cases) {
        const wrap = join(parent, piece.name);
        writePieceManifest(wrap, piece.decisions);
        const result = await verifyLedger(wrap, pins);
        assert.equal(result.ok, false, `${piece.name} ${JSON.stringify(result)}`);
        assert.ok(
          result.problems.some((problem) => problem.includes(piece.decisions)),
          `${piece.name} ${JSON.stringify(result.problems)}`,
        );
      }
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
});
