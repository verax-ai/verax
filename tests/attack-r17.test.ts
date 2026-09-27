// R17: each `it` asserts the behaviour after the fix. On 0800665 the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { runCli } from "../packages/body/src/cli.ts";
import { runInitLocal } from "../packages/body/src/init-local.ts";
import { mkdirLeaf } from "../packages/body/src/install.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { requestWitnessCheckpoint } from "../packages/body/src/witness.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";
import { refusedAsElevated, skipIfElevated } from "./elevated-refusal.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function cleanEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return env;
}

const sink = { write: () => true };

const GET_POLICY = {
  version: 1,
  default: "deny",
  rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
};

function spendDoc(capped: boolean) {
  return {
    version: 1,
    default: "deny",
    approvalTtlMs: 86_400_000,
    rules: [
      {
        id: "spend",
        tool: "spend",
        requires: ["verax:pay"],
        mode: "approve",
        text: "A payment is held for an operator.",
        spend: {
          maxAmountMinor: capped ? 50 : 5000,
          currency: "USD",
          payees: ["sample-merchant"],
          ...(capped ? { dailyMaxMinor: 50 } : {}),
        },
      },
    ],
  };
}

describe("attack R17", () => {
  it("R17-1 an elevated command judges the Node binary and its ancestors", async () => {
    const dir = ownerDir("verax-r17-node-");
    const probed: string[] = [];
    const err: string[] = [];
    const code = await runCli(["verify", dir], {
      elevated: () => true,
      codeProbe: () => false,
      execArgv: [],
      env: cleanEnv(),
      execPathProbe: (file) => {
        probed.push(file);
        return true;
      },
      stdout: sink,
      stderr: { write: (s) => err.push(String(s)) },
    });
    const nodeReal = realpathSync(process.execPath);
    const nodeDir = dirname(nodeReal);
    const fold = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);
    const sep = process.platform === "win32" ? "\\" : "/";
    assert.ok(
      probed.some((p) => {
        const left = fold(p);
        const dirFold = fold(nodeDir);
        return left === dirFold || left === fold(nodeReal) || dirFold.startsWith(left.endsWith(sep) ? left : `${left}${sep}`);
      }),
      probed.join("\n"),
    );
    assert.equal(code, 78, err.join(""));
    const text = err.join("");
    assert.match(text, /Node at /);
    assert.match(text, /opt\/verax-node|nodejs\.org/);
  });

  it("R17-2 an elevated command refuses NODE_OPTIONS and a preload flag", async () => {
    const dir = ownerDir("verax-r17-preload-");
    const err: string[] = [];
    const code = await runCli(["verify", dir], {
      elevated: () => true,
      codeProbe: () => false,
      execArgv: [],
      platform: "win32",
      env: { ...cleanEnv(), NODE_OPTIONS: "--require C:\\Users\\u\\x.js" },
      stdout: sink,
      stderr: { write: (s) => err.push(String(s)) },
    });
    assert.equal(code, 78, err.join(""));
    assert.match(err.join(""), /NODE_OPTIONS or a preload flag is set/);
    const again: string[] = [];
    const flagged = await runCli(["verify", dir], {
      elevated: () => true,
      codeProbe: () => false,
      execArgv: ["--require", "x.js"],
      env: cleanEnv(),
      stdout: sink,
      stderr: { write: (s) => again.push(String(s)) },
    });
    assert.equal(flagged, 78, again.join(""));
    assert.match(again.join(""), /preload flag/);
  });

  it("R17-3 argument names are quoted the same way as values", async () => {
    const dir = ownerDir("verax-r17-name-");
    const hostile = "a\nb\r\u001b[2K\u2028~\u001b[2A\u001b[2K\rbody: \"weekly report\"\u001b[1B\u001b[2K\rto: \"ops@corp.example\"\u001b[1B\u001b[2K\rnote";
    const row = {
      ref: "m-1",
      requestHash: "ab".repeat(32),
      subject: "message.send",
      args: { to: "a@allowed.example", body: "real", [hostile]: "x" },
      ruleId: null,
      ruleText: null,
      inputsSummary: { count: 0, ids: [] as string[] },
      expiresAtMs: Date.now() + 60_000,
      status: "pending",
      brain: "brain-1",
    };
    writeFileSync(join(dir, "approvals.jsonl"), `${JSON.stringify(row)}\n`, "utf8");
    const out: string[] = [];
    const err: string[] = [];
    const code = await runApprove(
      ["approve", dir, "m-1"],
      (line) => err.push(line),
      (line) => out.push(line),
      { isTTY: true, ask: async () => "no" },
      { elevated: () => false },
    );
    assert.equal(code, 1, err.join(""));
    const shown = out.join("");
    assert.equal(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(shown.replaceAll("\n", "")), false, JSON.stringify(shown));
    const toLines = shown.split("\n").filter((line) => /^"?to"?:/.test(line));
    assert.equal(toLines.length, 1, JSON.stringify(shown));
    assert.equal(toLines[0], '"to": "a@allowed.example"');
    assert.equal(shown.split("\n").filter((line) => line === '"body": "real"').length, 1);
  });

  it("R17-4 an elevated approve refuses a state directory the invoking user can change", async () => {
    const dir = ownerDir("verax-r17-owned-");
    const ref = "held-1";
    const row = {
      ref,
      requestHash: "cd".repeat(32),
      subject: "message.send",
      args: { to: "a@example.com", body: "x" },
      ruleId: null,
      ruleText: null,
      inputsSummary: { count: 0, ids: [] as string[] },
      expiresAtMs: Date.now() + 60_000,
      status: "pending",
      brain: "brain-1",
    };
    writeFileSync(join(dir, "approvals.jsonl"), `${JSON.stringify(row)}\n`, "utf8");
    const env = cleanEnv();
    const err: string[] = [];
    const code = await runApprove(
      ["approve", "--from-script", dir, ref],
      (line) => err.push(line),
      () => undefined,
      { isTTY: true, ask: async () => "no" },
      { elevated: () => true, codeProbe: () => false, execArgv: [], stateProbe: () => true, env },
    );
    const text = err.join("");
    assert.equal(code, 78, text);
    assert.match(text, /can be changed by/);
    assert.match(text, /elevated approve only opens the installed state directory/);
    assert.equal(existsSync(join(dir, "keys")), false);
    const openErr: string[] = [];
    const open = await runApprove(
      ["approve", "--from-script", dir, ref],
      (line) => openErr.push(line),
      () => undefined,
      undefined,
      { elevated: () => false, stateProbe: () => true, env },
    );
    assert.equal(openErr.join("").includes("elevated approve only opens the installed state directory"), false);
    assert.match(openErr.join(""), /approve-unknown-ref/);
    assert.equal(open, 78);
  });

  it("R17-5 the install section names an always-elevated account", () => {
    const readme = readFileSync(join(root, "README.md"), "utf8");
    const at = readme.indexOf("\n## Install\n");
    assert.ok(at > 0);
    const next = readme.indexOf("\n## ", at + 12);
    const section = readme.slice(at, next);
    assert.match(section, /EnableLUA|built-in Administrator/);
    assert.match(section, /%ProgramFiles%\\verax-cli/);
  });

  it("R17-6 init --force keeps an existing issuer and a failed run leaves it", async () => {
    const leafParent = ownerDir("verax-r17-leaf-");
    const leaf = join(leafParent, "sub");
    mkdirSync(leaf, { recursive: true, mode: 0o700 });
    writeFileSync(join(leaf, "keep.txt"), "stay", "utf8");
    // Default stays strict: the installer relies on EEXIST for a directory planted after its check.
    assert.throws(
      () => mkdirLeaf(leaf, 0o700),
      (err: unknown) => (err as NodeJS.ErrnoException).code === "EEXIST",
    );
    mkdirLeaf(leaf, 0o700, { existingOk: true });
    assert.equal(readFileSync(join(leaf, "keep.txt"), "utf8"), "stay");
    const link = join(leafParent, "link");
    let linked = false;
    try {
      symlinkSync(leaf, link, "dir");
      linked = true;
    } catch {
      linked = false;
    }
    if (linked) {
      assert.throws(
        () => mkdirLeaf(link, 0o700, { existingOk: true }),
        (err: unknown) => (err as NodeJS.ErrnoException).code === "EEXIST",
      );
      assert.equal(lstatSync(link).isSymbolicLink(), true);
    }

    const dir = ownerDir("verax-r17-init-");
    const firstErr: string[] = [];
    const first = await runInitLocal(["--local", dir], {
      stdout: sink,
      stderr: { write: (s: string) => firstErr.push(s) },
    });
    assert.equal(first, 0, firstErr.join(""));
    const keyPath = join(dir, "local-issuer", "key.pem");
    const tokenPath = join(dir, "local-issuer", "agent.token");
    const oldKey = readFileSync(keyPath, "utf8");
    writeFileSync(join(dir, "local-issuer", "keep.txt"), "stay\n", "utf8");
    const secondErr: string[] = [];
    const second = await runInitLocal(["--local", dir, "--force"], {
      stdout: sink,
      stderr: { write: (s: string) => secondErr.push(s) },
    });
    assert.equal(second, 0, secondErr.join(""));
    assert.equal(existsSync(keyPath), true);
    assert.notEqual(readFileSync(keyPath, "utf8"), oldKey);
    assert.equal(existsSync(tokenPath), true);
    assert.equal(readFileSync(join(dir, "local-issuer", "keep.txt"), "utf8"), "stay\n");

    const kept = ownerDir("verax-r17-rollback-");
    const primed: string[] = [];
    const primedCode = await runInitLocal(["--local", kept], {
      stdout: sink,
      stderr: { write: (s: string) => primed.push(s) },
    });
    assert.equal(primedCode, 0, primed.join(""));
    const keptKey = readFileSync(join(kept, "local-issuer", "key.pem"), "utf8");
    writeFileSync(join(kept, "local-issuer", "keep.txt"), "stay\n", "utf8");
    const failedErr: string[] = [];
    const failed = await runInitLocal(
      ["--local", kept, "--force"],
      { stdout: sink, stderr: { write: (s: string) => failedErr.push(s) } },
      { beforeWrite: () => { throw new Error("stop-after-mkdir"); } },
    );
    assert.notEqual(failed, 0);
    assert.match(failedErr.join(""), /stop-after-mkdir/);
    assert.equal(readFileSync(join(kept, "local-issuer", "key.pem"), "utf8"), keptKey);
    assert.equal(readFileSync(join(kept, "local-issuer", "keep.txt"), "utf8"), "stay\n");
    assert.equal(existsSync(join(kept, "local-issuer")), true);
  });

  it("R17-7 an empty key file is an error", async () => {
    const dir = ownerDir("verax-r17-emptykey-");
    const empty = join(dir, "empty.pem");
    const blank = join(dir, "blank.pem");
    writeFileSync(empty, "", "utf8");
    writeFileSync(blank, " \t\r\n", "utf8");
    const flags = ["--key", "--effect-key", "--witness-key", "--checkpoint-key"] as const;
    for (const flag of flags) {
      const file = flag === "--key" || flag === "--witness-key" ? empty : blank;
      const lines: string[] = [];
      const code = await runVerify([dir, flag, file], (s) => lines.push(s));
      assert.notEqual(code, 0, flag);
      assert.match(lines.join("\n"), new RegExp(`verify-key-empty: ${flag}`));
    }
  });

  it("R17-8 a pinned key that verified no row is source none", async () => {
    const dir = ownerDir("verax-r17-pin-");
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: loadPolicy(GET_POLICY),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => 1_700_000_000_000,
        nonce: () => "m-1",
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        { name: "memory.get", arguments: { id: "a", _ref: "m-1" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
    } finally {
      ledger.close();
    }
    const { publicKey } = generateKeyPairSync("ed25519");
    const witnessPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const result = await verifyLedger(dir, {
      effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
      witnessPublicKeyPem: witnessPem,
    });
    assert.equal(result.witnessTrust.source, "none");
    assert.match(result.witnessTrust.note, /no same-org effects/);
    assert.equal(result.witnessTrust.note.includes("verified against a key the reader supplied"), false);
  });

  it("R17-9 a snapshot whose hash is not the file name is approve-policy-missing", async () => {
    const dir = ownerDir("verax-r17-policy-");
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(spendDoc(false)),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "s-a",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "spend",
        arguments: {
          amountMinor: 100,
          currency: "USD",
          payee: "sample-merchant",
          reference: "s-a",
          _ref: "s-a",
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:pay"]) },
    );
    const hash = (await ledger.decisions()).find((row) => row.claims.decision === "defer")?.claims.policyHash ?? "";
    ledger.close();
    assert.notEqual(hash, "");
    assert.notEqual(loadPolicy(spendDoc(true)).hash, hash);
    mkdirSync(join(dir, "policies"), { recursive: true, mode: 0o700 });
    writeFileSync(join(dir, "policies", `${hash}.json`), `${JSON.stringify(spendDoc(true))}\n`, "utf8");
    const err: string[] = [];
    const code = await runApprove(
      ["approve", "--from-script", dir, "s-a"],
      (line) => err.push(line),
      () => undefined,
      undefined,
      { elevated: () => false, env: cleanEnv() },
    );
    assert.equal(code, 1, err.join(""));
    assert.match(err.join(""), /approve-policy-missing/);
  });

  it("R17-10 a zero-byte checkpoint file is checkpoint-unreadable", { timeout: 40_000 }, async (t) => {
    if (skipIfElevated(t)) return;
    const dir = ownerDir("verax-r17-cp-");
    const child: ChildProcess = spawn(process.execPath, ["--experimental-strip-types", cli, "witness", dir], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += String(chunk);
    });
    try {
      const listen = join(dir, "witness.listen.json");
      const deadline = Date.now() + 30_000;
      while (!existsSync(listen)) {
        if (child.exitCode !== null) {
          if (refusedAsElevated(child.exitCode, stderr)) return;
          throw new Error(`witness-exited:${child.exitCode} ${stderr.slice(0, 300)}`);
        }
        if (Date.now() > deadline) throw new Error(`listen-timeout ${stderr.slice(0, 300)}`);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const signed = await requestWitnessCheckpoint(dir, { epoch: 0, startMs: 1, endMs: 2 });
      assert.ok(signed);
      const file = join(dir, "checkpoints.jsonl");
      assert.equal(existsSync(file), true);
      writeFileSync(file, "", "utf8");
      const again = await requestWitnessCheckpoint(dir, { epoch: 1, startMs: 2, endMs: 3 });
      assert.equal(again, null);
      const status = readFileSync(join(dir, "witness-status.jsonl"), "utf8");
      assert.match(status, /checkpoint-unreadable/);
    } finally {
      child.kill("SIGKILL");
      await new Promise((resolve) => child.once("close", () => resolve(undefined)));
    }
  });

  it("R17-11 a leading flag main does not read is an unknown option", async () => {
    const dir = ownerDir("verax-r17-flag-");
    const file = join(dir, "v.env");
    writeFileSync(file, "VERAX_BIND=127.0.0.1:9\n", "utf8");
    const err: string[] = [];
    const code = await runCli(["--env-file", file], {
      elevated: () => false,
      stdout: sink,
      stderr: { write: (s) => err.push(String(s)) },
    });
    assert.equal(code, 64, err.join(""));
    assert.match(err.join(""), /unknown option: --env-file/);
    const portErr: string[] = [];
    const port = await runCli(["--port", "9000"], {
      elevated: () => false,
      stdout: sink,
      stderr: { write: (s) => portErr.push(String(s)) },
    });
    assert.equal(port, 64, portErr.join(""));
    assert.match(portErr.join(""), /unknown option: --port/);
  });
});
