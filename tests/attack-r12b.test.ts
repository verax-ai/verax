// R12b: each `it` asserts the safe behaviour. On 9ca2bb5 the implementation
// does the unsafe thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { bearerStillLive, listen } from "../packages/body/src/server.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "../packages/proxy/tests/helpers.ts";
import { readIssuerBody } from "../scripts/issuer-body.mjs";
import { readVendorFile } from "../scripts/vendor-allow.mjs";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const issuerScript = join(root, "scripts", "dev-issuer.mjs");
const LISTENING = /dev-issuer listening on http:\/\/127\.0\.0\.1:(\d+)\//;

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

async function oneAllowedGet(dir: string, ref: string): Promise<void> {
  const ledger = new FileLedger(dir);
  try {
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
      }),
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
  } finally {
    ledger.close();
  }
}

function jwtPayload(token: string): { jti?: string } {
  const part = token.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as { jti?: string };
}

async function boundPort(child: ChildProcess, getStderr: () => string): Promise<string> {
  const closed = new Promise<number>((resolve) => {
    child.once("close", (code) => resolve(code ?? 1));
  });
  const ready = (async () => {
    const until = Date.now() + 8_000;
    while (Date.now() < until) {
      const match = LISTENING.exec(getStderr());
      if (match?.[1]) return match[1];
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return "";
  })();
  const outcome = await Promise.race([
    closed.then((code) => ({ kind: "closed" as const, code })),
    ready.then((port) => ({ kind: "ready" as const, port })),
  ]);
  if (outcome.kind === "closed") {
    assert.fail(`issuer exited ${outcome.code}: ${getStderr()}`);
  }
  assert.equal(outcome.port !== "", true, `issuer did not listen: ${getStderr()}`);
  return outcome.port;
}

describe("attack R12b", () => {
  it("R12b-2 refuses a drive letter and a UNC vendor path before any filesystem call", () => {
    const src = readFileSync(issuerScript, "utf8");
    assert.match(src, /readVendorFile\(rel, vendorFiles, readFileSync\)/);
    assert.equal(src.includes("resolve(vendorRoot, rel)"), false);
    let reads = 0;
    // Named apart from node:fs readFileSync, which the lines above use on the real file.
    const fakeRead = (): Buffer => {
      reads += 1;
      throw new Error("filesystem");
    };
    const files = new Map<string, string>([["esm/index.js", join(root, "package.json")]]);
    assert.equal(readVendorFile("D:/x", files, fakeRead), null);
    assert.equal(readVendorFile("//host/share/f", files, fakeRead), null);
    assert.equal(reads, 0);
    let served = "";
    const body = readVendorFile("esm/index.js", files, (path: string) => {
      served = path;
      return Buffer.from("module");
    });
    assert.equal(served, files.get("esm/index.js"));
    assert.equal(body?.toString(), "module");
  });

  it("R12b-1 checks the bearer again after the body and bounds the request", async () => {
    const stateDir = ownerDir("verax-r12b-stale-");
    const dead = ownerDir("verax-r12b-jti-");
    let server: Awaited<ReturnType<typeof listen>> | undefined;
    let issuer: Awaited<ReturnType<typeof startDevIssuer>> | undefined;
    try {
      appendFileSync(join(dead, "revoked-jti.jsonl"), `${JSON.stringify({ jti: "dead" })}\n`, "utf8");
      const later = Math.floor(Date.now() / 1000) + 600;
      assert.equal(bearerStillLive({ jti: "dead", exp: later }, dead), false);
      assert.equal(bearerStillLive({ jti: "live", exp: Math.floor(Date.now() / 1000) - 30 }, dead), false);
      assert.equal(bearerStillLive({ jti: "live", exp: later }, dead), true);

      const audience = "http://127.0.0.1/verax-test";
      issuer = await startDevIssuer(0, audience);
      server = await listen({
        issuer: issuer.issuer,
        jwksUrl: issuer.jwksUrl,
        audience,
        stateDir,
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile,
        tlsTerminated: false,
      });
      assert.equal(server.requestTimeout, 30_000);
      assert.equal(server.headersTimeout, 20_000);
      const port = (server.address() as { port: number }).port;
      const token = await issuer.sign({ expSkewSec: -30, scope: "verax:read", jti: "r12b-stale-exp" });
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
      assert.equal(res.status, 401);
      const body = (await res.json()) as { error?: string };
      assert.equal(body.error, "unauthorized");
    } finally {
      if (server) {
        await new Promise<void>((resolve, reject) => {
          server?.close((err) => (err ? reject(err) : resolve()));
        });
      }
      await issuer?.close();
      rmSync(stateDir, { recursive: true, force: true });
      rmSync(dead, { recursive: true, force: true });
    }
  });

  it("R12b-3 binds at most one primary effect row per ref", async () => {
    const ref = "r12b-copy";
    const dir = ownerDir("verax-r12b-effect-");
    try {
      await oneAllowedGet(dir, ref);
      const effectsPath = join(dir, "effects.jsonl");
      const lines = readFileSync(effectsPath, "utf8")
        .split("\n")
        .filter((line) => line.trim() !== "");
      assert.equal(lines.length, 1);
      const primary = lines[0]!;
      assert.equal(primary.includes("duplicate-effect"), false);
      writeFileSync(effectsPath, `${primary}\n${primary}\n${primary}\n`, "utf8");
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.equal(result.effectsBound, 1);
      assert.equal(
        result.problems.filter((problem) => problem === `ref ${ref} has more than one effect row`).length,
        2,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("revoke refuses a bearer whose jti is already revoked before granting a role", async () => {
    const stateDir = ownerDir("verax-r12b-revoke-");
    const outPath = join(stateDir, "token");
    const child = spawn(process.execPath, ["--experimental-strip-types", issuerScript, "--out", outPath], {
      env: {
        ...process.env,
        VERAX_STATE_DIR: stateDir,
        NODE_ENV: "development",
        VERAX_DEV_ISSUER_PORT: "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += String(chunk);
    });
    const closed = new Promise<number>((resolve) => {
      child.once("close", (code) => resolve(code ?? 1));
    });
    try {
      const port = await boundPort(child, () => stderr);
      const agent = readFileSync(outPath, "utf8").trim();
      const jti = jwtPayload(agent).jti ?? "";
      assert.equal(jti !== "", true);
      writeFileSync(join(stateDir, "revoked-jti.jsonl"), `${JSON.stringify({ jti })}\n`, "utf8");
      const victim = "r12b-must-not-revoke";
      const res = await fetch(`http://127.0.0.1:${port}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${agent}` },
        body: JSON.stringify({ jti: victim }),
      });
      assert.equal(res.status, 401);
      const body = (await res.json()) as { error?: string };
      assert.equal(body.error, "unauthorized");
      const text = readFileSync(join(stateDir, "revoked-jti.jsonl"), "utf8");
      assert.equal(text.includes(victim), false);
    } finally {
      child.kill("SIGTERM");
      await closed;
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("readBody caps the issuer body at 64 KiB and stops reading", async () => {
    const src = readFileSync(issuerScript, "utf8");
    assert.match(src, /readIssuerBody as readBody/);
    let pulls = 0;
    const over = {
      destroyed: false,
      destroy() {
        this.destroyed = true;
      },
      async *[Symbol.asyncIterator]() {
        pulls += 1;
        yield Buffer.alloc(64 * 1024);
        pulls += 1;
        yield Buffer.from("x");
        pulls += 1;
        yield Buffer.from("more");
      },
    };
    await assert.rejects(
      () => readIssuerBody(over),
      (err: unknown) => Boolean(err && typeof err === "object" && (err as { code?: string }).code === "PAYLOAD_TOO_LARGE"),
    );
    assert.equal(over.destroyed, true);
    assert.equal(pulls, 2);
    const exact = {
      destroy() {},
      async *[Symbol.asyncIterator]() {
        yield Buffer.alloc(64 * 1024);
      },
    };
    const text = await readIssuerBody(exact);
    assert.equal(text.length, 64 * 1024);
  });

  it("a symbolic link ledger file is a named problem and is not read", async (t) => {
    const ref = "r12b-link";
    const dir = ownerDir("verax-r12b-link-");
    try {
      await oneAllowedGet(dir, ref);
      const effectsPath = join(dir, "effects.jsonl");
      const moved = join(dir, "effects.real.jsonl");
      renameSync(effectsPath, moved);
      try {
        symlinkSync(moved, effectsPath, "file");
      } catch {
        t.skip("symlinks cannot be created");
        return;
      }
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.equal(result.effectsBound, 0);
      assert.ok(
        result.problems.some((problem) => problem.startsWith("symbolic link:") && problem.includes("effects.jsonl")),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
