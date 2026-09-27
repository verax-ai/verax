// R16: each `it` asserts the behaviour after the fix. On c8b34be the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { runCli } from "../packages/body/src/cli.ts";
import { runDesktop } from "../packages/body/src/desktop.ts";
import { clearVeraxEnv, loadEnvFile, runInitLocal } from "../packages/body/src/init-local.ts";
import { windowsUserCanWrite } from "../packages/body/src/install.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { requestWitnessCheckpoint } from "../packages/body/src/witness.ts";
import { loadApprovalsFromDir } from "../packages/proxy/src/approvals.ts";
import { signEffectAttestation, FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";
import { elevatedRunner, refusedAsElevated, skipIfElevated } from "./elevated-refusal.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function ed25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

const sink = { write: () => true };

const GET_POLICY = {
  version: 1,
  default: "deny",
  rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
};

const MEMORY_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "memory-put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
  ],
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
          maxAmountMinor: 5000,
          currency: "USD",
          payees: ["sample-merchant"],
          ...(capped ? { dailyMaxMinor: 1000 } : {}),
        },
      },
    ],
  };
}

function envFromFile(stateDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toUpperCase().startsWith("VERAX_")) delete env[key];
  }
  for (const line of readFileSync(join(stateDir, "verax.env"), "utf8").split(/\r?\n/)) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (match?.[1] && match[2] !== undefined) env[match[1]] = match[2];
  }
  env.VERAX_BIND = "127.0.0.1:0";
  return env;
}

function strippedEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toUpperCase().startsWith("VERAX_")) delete env[key];
  }
  return env;
}

function stopChild(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("exit", () => resolve());
    child.kill("SIGTERM");
  });
}

describe("attack R16", () => {
  it("R16-1 verax with no command stays up and still answers /healthz", { timeout: 45_000 }, async (t) => {
    if (skipIfElevated(t)) return;
    const dir = ownerDir("verax-r16-serve-");
    const initCode = await runInitLocal(
      ["--local", dir, "--port", "8799"],
      { stdout: sink, stderr: sink },
      { quiet: true, noOwnerGrant: true },
    );
    assert.equal(initCode, 0);
    const child = spawn(process.execPath, ["--experimental-strip-types", cli], {
      env: envFromFile(dir),
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
    });
    let err = "";
    child.stderr?.on("data", (chunk: Buffer | string) => {
      err += String(chunk);
    });
    try {
      const port = await new Promise<number>((resolve, reject) => {
        let settled = false;
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          reject(new Error(`no listen: ${err.slice(0, 400)}`));
        }, 20_000);
        child.once("exit", (code) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(new Error(`exit ${code}: ${err.slice(0, 400)}`));
        });
        child.stderr?.on("data", () => {
          if (settled) return;
          const match = /listening [^\s:]+:(\d+)/.exec(err);
          if (!match?.[1]) return;
          settled = true;
          clearTimeout(timer);
          resolve(Number(match[1]));
        });
      });
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      assert.equal(child.exitCode, null, err.slice(0, 400));
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(res.status > 0, true);
      assert.equal(child.exitCode, null);
    } finally {
      await stopChild(child);
    }
  });

  it("R16-2 an unknown command exits 64 and a leading flag that main does not read exits 64", { timeout: 40_000 }, async () => {
    const err: string[] = [];
    const code = await runCli(["instal"], {
      elevated: () => false,
      stdout: sink,
      stderr: { write: (s) => err.push(String(s)) },
    });
    const text = err.join("");
    assert.equal(code, 64, text);
    assert.match(text, /unknown command: instal\n/);
    assert.match(text, /Usage: verax <command>/);

    const dir = ownerDir("verax-r16-flag-");
    const env = strippedEnv();
    const run = (args: string[]) =>
      new Promise<{ code: number; stderr: string }>((resolve, reject) => {
        const child = spawn(process.execPath, ["--experimental-strip-types", cli, ...args], {
          env,
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });
        let stderr = "";
        child.stderr?.on("data", (chunk: Buffer | string) => {
          stderr += String(chunk);
        });
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          reject(new Error(`still running: ${args.join(" ")} ${stderr.slice(0, 300)}`));
        }, 15_000);
        child.once("close", (exit) => {
          clearTimeout(timer);
          resolve({ code: exit ?? 1, stderr });
        });
      });
    // Elevated runner: every child of this checkout is refused before the command, so there is
    // nothing to learn about flag routing there (and Node 22 may read a later --env-file itself).
    if (elevatedRunner) return;
    // A bare --env-file right after the script is taken by Node itself (it exits 9 before the CLI
    // runs), so it is not a CLI path to test; --log-file reaches the CLI.
    const logFile = await run(["--log-file", join(dir, "body.log")]);
    assert.equal(logFile.code, 64, logFile.stderr);
    assert.match(logFile.stderr, /unknown option: --log-file/);
  });

  it("R16-3 a mixed-case VERAX_ name is removed from the object passed in", () => {
    const dir = ownerDir("verax-r16-case-");
    const file = join(dir, "v.env");
    writeFileSync(file, "VERAX_JWKS_FILE=C:/jwks.json\n", "utf8");
    const env: NodeJS.ProcessEnv = { Verax_Policy_File: "left", KEEP: "yes" };
    clearVeraxEnv(env);
    assert.equal("Verax_Policy_File" in env, false);
    assert.equal(env.KEEP, "yes");
    const again: NodeJS.ProcessEnv = { Verax_Policy_File: "left", KEEP: "yes" };
    const loaded = loadEnvFile(file, again);
    assert.equal(loaded.ok, true);
    assert.equal("Verax_Policy_File" in again, false);
    assert.equal(again.KEEP, "yes");
    assert.equal(again.VERAX_JWKS_FILE, "C:/jwks.json");
  });

  it("R16-4 elevated demo --with-conarium is refused", async () => {
    const err: string[] = [];
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    const code = await runCli(["demo", "--with-conarium"], {
      elevated: () => true,
      codeProbe: () => false,
      execArgv: [],
      env,
      stdout: sink,
      stderr: { write: (s) => err.push(String(s)) },
    });
    assert.equal(code, 78, err.join(""));
    assert.match(
      err.join(""),
      /refusing: demo --with-conarium fetches and runs code with npx; run it from a terminal that is not elevated/,
    );
  });

  it("R16-5 a spend with no loadable policy is refused when not elevated", async () => {
    const dir = ownerDir("verax-r16-nopolicy-");
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
    ledger.close();
    const missErr: string[] = [];
    const miss = await runApprove(
      ["approve", "--from-script", dir, "s-a"],
      (line) => missErr.push(line),
      () => undefined,
      undefined,
      { elevated: () => false, env: strippedEnv() },
    );
    assert.equal(miss, 1, missErr.join(""));
    assert.match(missErr.join(""), /approve-policy-missing/);
    const still = loadApprovalsFromDir(dir).find((row) => row.ref === "s-a" || row.ref.endsWith(":s-a"));
    assert.ok(still);
    assert.equal(still.status === "pending" || still.status === undefined, true);
  });

  it("R16-6 an env policy is used only when its hash is the defer hash", async () => {
    // "s-a" is asked for before today's UTC midnight and "s-b" today: at the request a pending row counts
    // on the day it was created, so both defer; at approval "s-a" counts today and the cap refuses "s-b".
    const capped = { ...spendDoc(true), approvalTtlMs: 172_800_000 };
    const today = new Date();
    const beforeMidnight = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()) - 3_600_000;
    let clock = beforeMidnight;
    const dir = ownerDir("verax-r16-hash-");
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    let n = 0;
    const proxy = createProxy({
      policy: loadPolicy(capped),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => clock,
      nonce: () => `n-${n++}`,
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    for (const ref of ["s-a", "s-b"]) {
      if (ref === "s-b") clock = Date.now();
      await proxy.call(
        {
          name: "spend",
          arguments: {
            amountMinor: 1000,
            currency: "USD",
            payee: "sample-merchant",
            reference: ref,
            _ref: ref,
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:pay"]) },
      );
    }
    const hash = (await ledger.decisions()).find((row) => row.claims.decision === "defer")?.claims.policyHash ?? "";
    ledger.close();
    assert.equal(hash, loadPolicy(capped).hash);
    mkdirSync(join(dir, "policies"), { recursive: true, mode: 0o700 });
    writeFileSync(join(dir, "policies", `${hash}.json`), `${JSON.stringify(capped)}\n`, "utf8");
    const envPath = join(ownerDir("verax-r16-other-"), "policy.json");
    writeFileSync(envPath, `${JSON.stringify(spendDoc(false))}\n`, "utf8");
    assert.notEqual(loadPolicy(spendDoc(false)).hash, hash);
    const env = { ...strippedEnv(), VERAX_POLICY_FILE: envPath };
    const firstErr: string[] = [];
    const firstOut: string[] = [];
    const first = await runApprove(
      ["approve", "--from-script", dir, "s-a"],
      (line) => firstErr.push(line),
      (line) => firstOut.push(line),
      undefined,
      { elevated: () => false, env },
    );
    assert.equal(first, 0, firstErr.join(""));
    assert.match(firstOut.join(""), /^approved:/);
    const secondErr: string[] = [];
    const second = await runApprove(
      ["approve", "--from-script", dir, "s-b"],
      (line) => secondErr.push(line),
      () => undefined,
      undefined,
      { elevated: () => false, env },
    );
    assert.equal(second, 1, secondErr.join(""));
    assert.match(secondErr.join(""), /approve-budget-exceeded/);
  });

  it("R16-7 each held field is its own JSON-quoted line", async () => {
    const dir = ownerDir("verax-r16-prompt-");
    const ref = "spend-ref-1";
    const pending = {
      ref,
      requestHash: "abc123abc123deadbeef",
      subject: "spend",
      args: {
        amountMinor: 100,
        currency: "TRY",
        payee: "sample-merchant",
        reference: " payee=x",
      },
      ruleId: "spend",
      ruleText: "Spends need operator approval.",
      inputsSummary: { count: 0, ids: [] },
      amount: 100,
      payee: "sample-merchant",
      currency: "TRY",
      expiresAtMs: Date.now() + 60_000,
      status: "pending",
      brain: "brain-1",
    };
    writeFileSync(join(dir, "approvals.jsonl"), `${JSON.stringify(pending)}\n`, "utf8");
    const out: string[] = [];
    await runApprove(
      ["approve", dir, ref],
      () => undefined,
      (line) => out.push(line),
      { isTTY: true, ask: async () => "100" },
      { elevated: () => false },
    );
    const shown = out.join("");
    assert.match(shown, /"payee": "sample-merchant"/);
    assert.match(shown, /"reference": " payee=x"/);
    assert.equal(shown.split("\n").filter((line) => line.startsWith('"payee":')).length, 1);
  });

  it("R16-8 a non-spend prompt shows arguments and wants yes, and a non-integer spend amount is refused", async () => {
    const dir = ownerDir("verax-r16-yes-");
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(MEMORY_POLICY),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "put-1",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "memory.put",
        arguments: { id: "n1", body: "x", source: { kind: "t" }, validUntilMs: 9_999, _ref: "put-1" },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    ledger.close();
    const emptyErr: string[] = [];
    const emptyOut: string[] = [];
    const empty = await runApprove(
      ["approve", dir, "put-1"],
      (line) => emptyErr.push(line),
      (line) => emptyOut.push(line),
      { isTTY: true, ask: async () => "" },
      { elevated: () => false },
    );
    assert.equal(empty, 1, emptyErr.join(""));
    assert.match(emptyErr.join(""), /approve-confirm-mismatch/);
    assert.match(emptyOut.join(""), /"tool": "memory.put"/);
    assert.match(emptyOut.join(""), /"id": "n1"/);
    assert.match(emptyOut.join(""), /Type yes:/);
    const pending = loadApprovalsFromDir(dir).find((row) => row.ref === "put-1" || row.ref.endsWith(":put-1"));
    assert.equal(pending?.status, "pending");

    const yesErr: string[] = [];
    const yesOut: string[] = [];
    const yes = await runApprove(
      ["approve", dir, "put-1"],
      (line) => yesErr.push(line),
      (line) => yesOut.push(line),
      { isTTY: true, ask: async () => "yes" },
      { elevated: () => false },
    );
    assert.equal(yes, 0, yesErr.join(""));
    assert.match(yesOut.join(""), /^approved:/m);

    const spendDir = ownerDir("verax-r16-fraction-");
    const spendSigners = loadOrCreateSigners(spendDir);
    const spendLedger = new FileLedger(spendDir);
    const spendProxy = createProxy({
      policy: loadPolicy(spendDoc(false)),
      recordSigner: spendSigners.recordSigner,
      effectSigner: spendSigners.effectSigner,
      ledger: spendLedger,
      now: () => Date.now(),
      nonce: () => "frac",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await spendProxy.call(
      {
        name: "spend",
        arguments: {
          amountMinor: 100,
          currency: "USD",
          payee: "sample-merchant",
          reference: "frac",
          _ref: "frac",
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:pay"]) },
    );
    spendLedger.close();
    const approvalsPath = join(spendDir, "approvals.jsonl");
    const lines = readFileSync(approvalsPath, "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as { amount?: unknown; ref?: string });
    const row = lines.find((item) => item.ref === "frac" || item.ref?.endsWith(":frac"));
    assert.ok(row);
    row.amount = 1.5;
    writeFileSync(approvalsPath, `${lines.map((item) => JSON.stringify(item)).join("\n")}\n`, "utf8");
    let asked = false;
    const fracErr: string[] = [];
    const frac = await runApprove(
      ["approve", spendDir, "frac"],
      (line) => fracErr.push(line),
      () => undefined,
      {
        isTTY: true,
        ask: async () => {
          asked = true;
          return "1.5";
        },
      },
      { elevated: () => false, env: strippedEnv() },
    );
    assert.equal(frac, 1, fracErr.join(""));
    assert.match(fracErr.join(""), /approve-amount-unreadable/);
    assert.equal(asked, false);
    const again = new FileLedger(spendDir);
    const recs = await again.decisions();
    again.close();
    assert.equal(
      recs.some((rec) => rec.claims.decision === "allow"),
      false,
    );
  });

  it("R16-9 a checkpoint answer from another key is not stored", async () => {
    const dir = ownerDir("verax-r16-cpkey-");
    const listenKey = ed25519();
    const other = ed25519();
    const server = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        const body = {
          claims: { epoch: 0, startMs: 1, endMs: 2, receiptCount: 0, chainHeadHash: null, totals: {}, prevCheckpointHash: null },
          publicKeyPem: other.publicKeyPem,
          encoding: "cose",
          coseHex: "abcd",
        };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    writeFileSync(
      join(dir, "witness.listen.json"),
      `${JSON.stringify({
        pid: process.pid,
        port: address.port,
        token: "tok",
        publicKeyPem: listenKey.publicKeyPem,
        startedAt: Date.now(),
      })}\n`,
      "utf8",
    );
    try {
      const signed = await requestWitnessCheckpoint(dir, { epoch: 0, startMs: 1, endMs: 2 });
      assert.equal(signed, null);
      assert.equal(existsSync(join(dir, "checkpoints.jsonl")), false);
      const status = readFileSync(join(dir, "witness-status.jsonl"), "utf8").trim().split("\n").pop();
      const parsed = JSON.parse(status ?? "{}") as { reason?: string };
      assert.equal(parsed.reason, "witness-key-mismatch");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("R16-10 an unreadable checkpoint file stops checkpointing", { timeout: 40_000 }, async (t) => {
    if (skipIfElevated(t)) return;
    const dir = ownerDir("verax-r16-cpbad-");
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "witness", dir], {
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
      writeFileSync(join(dir, "checkpoints.jsonl"), "{\n", "utf8");
      const signed = await requestWitnessCheckpoint(dir, { epoch: 0, startMs: 1, endMs: 2 });
      assert.equal(signed, null);
      const text = readFileSync(join(dir, "checkpoints.jsonl"), "utf8");
      assert.equal(text.includes("coseHex"), false, text.slice(0, 200));
      const status = readFileSync(join(dir, "witness-status.jsonl"), "utf8").trim().split("\n").pop();
      const parsed = JSON.parse(status ?? "{}") as { reason?: string };
      assert.equal(parsed.reason, "checkpoint-unreadable");
    } finally {
      await stopChild(child);
    }
  });

  it("R16-11 a pinned effect key with a same-org row needs a pinned witness key, and the reverse", async () => {
    const dir = ownerDir("verax-r16-pin-");
    const witness = ed25519();
    const ledger = new FileLedger(dir);
    let witnessed = 0;
    let issued = 0;
    ledger.remoteWitness = async (row, resultHash) => {
      witnessed += 1;
      if (witnessed > 1) return null;
      const signed = signEffectAttestation(row, "same-org", resultHash, witness);
      return { witnessClass: "same-org", ...signed };
    };
    try {
      const proxy = createProxy({
        policy: loadPolicy(GET_POLICY),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => 1_700_000_000_000,
        nonce: () => `m-${issued++}`,
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        { name: "memory.get", arguments: { id: "a", _ref: "m-0" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      await proxy.call(
        { name: "memory.get", arguments: { id: "b", _ref: "m-1" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
    } finally {
      ledger.close();
    }
    const effectOnly = await verifyLedger(dir, { effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem });
    assert.equal(effectOnly.ok, false, JSON.stringify(effectOnly.problems));
    assert.ok(
      effectOnly.problems.includes("same-org rows need --witness-key when --effect-key is pinned"),
      JSON.stringify(effectOnly.problems),
    );
    const witnessOnly = await verifyLedger(dir, { witnessPublicKeyPem: witness.publicKeyPem });
    assert.equal(witnessOnly.ok, false, JSON.stringify(witnessOnly.problems));
    assert.ok(
      witnessOnly.problems.includes("self rows need --effect-key when --witness-key is pinned"),
      JSON.stringify(witnessOnly.problems),
    );
    const both = await verifyLedger(dir, {
      effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
      witnessPublicKeyPem: witness.publicKeyPem,
    });
    assert.equal(both.ok, true, JSON.stringify(both.problems));
  });

  it("R16-12 an existing Windows state directory with another owner SID is refused", async () => {
    const dir = ownerDir("verax-r16-desk-");
    let restricted = 0;
    const mismatchErr: string[] = [];
    const mismatch = await runDesktop(
      { stateDir: dir, panelPort: 1, issuerPort: 2, bodyPort: 3 },
      (line) => mismatchErr.push(line),
      {
        platform: "win32",
        windowsDirectoryOwner: () => ({ ownerSid: "S-1-5-21-9", invokingSid: "S-1-5-21-1" }),
        restrictOwner: () => {
          restricted += 1;
        },
      },
    );
    assert.equal(mismatch, 1, mismatchErr.join(""));
    assert.match(mismatchErr.join(""), new RegExp(`desktop-dir-refused:${dir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.equal(restricted, 0);

    const matchErr: string[] = [];
    const match = await runDesktop(
      { stateDir: dir, panelPort: 1, issuerPort: 2, bodyPort: 3 },
      (line) => matchErr.push(line),
      {
        platform: "win32",
        windowsDirectoryOwner: () => ({ ownerSid: "S-1-5-21-1", invokingSid: "s-1-5-21-1" }),
        restrictOwner: () => {
          throw new Error("restrict-ran");
        },
      },
    );
    assert.equal(match, 1, matchErr.join(""));
    assert.match(matchErr.join(""), /restrict-ran/);
    assert.equal(matchErr.join("").includes("desktop-dir-refused:"), false);

    // An elevated administrator's directories are owned by Administrators; that is accepted.
    const adminErr: string[] = [];
    const admin = await runDesktop(
      { stateDir: dir, panelPort: 1, issuerPort: 2, bodyPort: 3 },
      (line) => adminErr.push(line),
      {
        platform: "win32",
        windowsDirectoryOwner: () => ({ ownerSid: "S-1-5-32-544", invokingSid: "S-1-5-21-1" }),
        restrictOwner: () => {
          throw new Error("restrict-ran");
        },
      },
    );
    assert.equal(admin, 1, adminErr.join(""));
    assert.match(adminErr.join(""), /restrict-ran/);
    assert.equal(adminErr.join("").includes("desktop-dir-refused:"), false);
  });

  it("R16-13 a user ACE with KA is judged writable", () => {
    const sid = "S-1-5-21-111";
    const text = `O:SYG:SYD:(A;;KA;;;${sid})`;
    assert.equal(windowsUserCanWrite(text, { path: "C:\\Verax\\state", userSid: sid }), true);
  });
});
