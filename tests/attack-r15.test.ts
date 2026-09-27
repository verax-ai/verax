// R15: each `it` asserts the behaviour after the fix. On 0ba20f9 the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { runCli } from "../packages/body/src/cli.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { requestWitnessSign } from "../packages/body/src/witness.ts";
import {
  approvePending,
  approvalsLogFor,
  drainApprovalCommands,
  enqueueApprovalCommand,
  loadApprovalsFromDir,
} from "../packages/proxy/src/approvals.ts";
import { signEffectAttestation, FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";
import { persistPolicySnapshot } from "../packages/body/src/policy-store.ts";

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
          maxAmountMinor: 5000,
          currency: "USD",
          payees: ["sample-merchant"],
          ...(capped ? { dailyMaxMinor: 1000 } : {}),
        },
      },
    ],
  };
}

const sink = { write: () => true };

describe("attack R15", () => {
  it("R15-1 elevated commands refuse writable code and unelevated commands do not", async () => {
    const listed: string[][] = [
      ["doctor"],
      ["verify"],
      ["unlock"],
      ["halt"],
      ["witness"],
      ["reconcile"],
      ["serve", "--log-file"],
    ];
    for (const argv of listed) {
      const err: string[] = [];
      const code = await runCli(argv, {
        elevated: () => true,
        codeProbe: () => true,
        stderr: { write: (s) => err.push(String(s)) },
        stdout: sink,
      });
      assert.equal(code, 78, `${argv[0]} ${err.join("")}`);
      assert.match(err.join(""), /the verax code at .+ can be changed by/, argv[0]);
    }
    for (const argv of listed) {
      const err: string[] = [];
      const out: string[] = [];
      const code = await runCli(argv, {
        elevated: () => false,
        codeProbe: () => true,
        stderr: { write: (s) => err.push(String(s)) },
        stdout: { write: (s) => out.push(String(s)) },
      });
      assert.doesNotMatch(`${code}\n${err.join("")}\n${out.join("")}`, /can be changed by/, argv[0]);
    }
    const dir = ownerDir("verax-r15-halt-");
    const err: string[] = [];
    const code = await runCli(["halt", dir], {
      elevated: () => false,
      stderr: { write: (s) => err.push(String(s)) },
      stdout: sink,
    });
    assert.equal(code, 0, err.join(""));
    assert.equal(existsSync(join(dir, "halted")), true);
    const blocked: string[] = [];
    const refused = await runCli(["halt", dir], {
      elevated: () => true,
      codeProbe: () => true,
      stderr: { write: (s) => blocked.push(String(s)) },
      stdout: sink,
    });
    assert.equal(refused, 78, blocked.join(""));
    assert.match(blocked.join(""), /can be changed by/);
  });

  it("R15-2 keeps an unreadable approval queue and refuses a linked path", async () => {
    const dir = ownerDir("verax-r15-queue-");
    mkdirSync(join(dir, "approval-commands.processing-1"));
    let applied = 0;
    await drainApprovalCommands(dir, async () => {
      applied += 1;
    });
    assert.equal(applied, 0);
    const names = readdirSync(dir);
    assert.equal(
      names.some((name) => name.startsWith("approval-commands.unreadable-")),
      true,
      names.join(","),
    );
    assert.equal(
      names.some((name) => name.startsWith("approval-commands.processing-")),
      false,
      names.join(","),
    );

    const target = join(dir, "elsewhere.txt");
    writeFileSync(target, "kept\n", { encoding: "utf8" });
    try {
      symlinkSync(target, join(dir, "approval-commands.jsonl"));
    } catch {
      return;
    }
    assert.throws(() =>
      enqueueApprovalCommand(dir, { ref: "r", approverId: "op", atMs: 1, via: "cli" }),
    );
    assert.equal(readFileSync(target, "utf8"), "kept\n");
  });

  it("R15-4 a mixed self and same-org ledger verifies, and a third key fails when pinned", async () => {
    const dir = ownerDir("verax-r15-verify-");
    const witness = ed25519();
    const third = ed25519();
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
        { name: "memory.get", arguments: { id: "a", _ref: "m-1" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      await proxy.call(
        { name: "memory.get", arguments: { id: "b", _ref: "m-2" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
    } finally {
      ledger.close();
    }
    const mixed = await verifyLedger(dir);
    assert.equal(mixed.ok, true, JSON.stringify(mixed.problems));
    assert.equal(mixed.witnessTrust.source, "in-ledger");
    assert.equal(mixed.witnessTrust.publicKeyPem?.includes("BEGIN PUBLIC KEY"), true);
    assert.match(mixed.witnessTrust.note, /not that the key was ever trusted/);

    const again = new FileLedger(dir);
    again.remoteWitness = async (row, resultHash) => {
      const signed = signEffectAttestation(row, "same-org", resultHash, third);
      return { witnessClass: "same-org", ...signed };
    };
    try {
      const proxy = createProxy({
        policy: loadPolicy(GET_POLICY),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger: again,
        now: () => 1_700_000_000_100,
        nonce: () => "m-3",
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        { name: "memory.get", arguments: { id: "c", _ref: "m-3" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
    } finally {
      again.close();
    }
    const pinned = await verifyLedger(dir, { witnessPublicKeyPem: witness.publicKeyPem });
    assert.equal(pinned.ok, false, JSON.stringify(pinned.problems));
    assert.equal(pinned.witnessTrust.source, "pinned");
    assert.ok(
      pinned.problems.some((problem) => problem.includes("effect attestation does not cover the row")),
      JSON.stringify(pinned.problems),
    );
  });

  it("R15-5 a witness answer signed by another key is a self-fallback", async () => {
    const dir = ownerDir("verax-r15-witness-");
    const listenKey = ed25519();
    const other = ed25519();
    const row = {
      ref: "w-1",
      effectHash: "ab".repeat(32),
      effectClass: "memory.get",
      timestampMs: 10,
    };
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { resultHash?: unknown };
        const resultHash = typeof body.resultHash === "string" ? body.resultHash : undefined;
        const signed = signEffectAttestation(row, "same-org", resultHash, other);
        const text = JSON.stringify({ witnessClass: "same-org", ...signed });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(text);
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
      { encoding: "utf8" },
    );
    try {
      const answer = await requestWitnessSign(dir, row, "cd".repeat(32));
      assert.equal(answer, null);
      const status = readFileSync(join(dir, "witness-status.jsonl"), "utf8").trim().split("\n").pop();
      const parsed = JSON.parse(status ?? "{}") as { result?: string; reason?: string };
      assert.equal(parsed.result, "self-fallback");
      assert.equal(parsed.reason, "witness-key-mismatch");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("R15-6 elevated approve ignores VERAX_POLICY_FILE and refuses a missing snapshot for a spend", async () => {
    // "s-a" is asked for before today's UTC midnight and "s-b" today, so both defer under the cap;
    // at approval "s-a" counts today and the cap in the snapshot refuses "s-b".
    const capped = { ...spendDoc(true), approvalTtlMs: 172_800_000 };
    const hold = async (prefix: string, policyDoc: Record<string, unknown>): Promise<{ dir: string; hash: string }> => {
      const dir = ownerDir(prefix);
      const signers = loadOrCreateSigners(dir);
      const ledger = new FileLedger(dir);
      const today = new Date();
      let clock = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()) - 3_600_000;
      let i = 0;
      const proxy = createProxy({
        policy: loadPolicy(policyDoc),
        recordSigner: signers.recordSigner,
        effectSigner: signers.effectSigner,
        ledger,
        now: () => clock,
        nonce: () => `n-${i++}`,
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
      return { dir, hash };
    };
    const elevatedHooks = { elevated: () => true, codeProbe: () => false, execArgv: [] as string[], stateProbe: () => false };

    // The environment names an uncapped policy; the snapshot the body wrote is the capped one that held the calls.
    const uncappedPath = join(ownerDir("verax-r15-env-policy-"), "policy.json");
    writeFileSync(uncappedPath, `${JSON.stringify({ ...spendDoc(false), approvalTtlMs: 172_800_000 })}\n`, { encoding: "utf8" });
    const elevatedHold = await hold("verax-r15-elev-", capped);
    assert.equal(elevatedHold.hash, loadPolicy(capped).hash);
    persistPolicySnapshot(elevatedHold.dir, elevatedHold.hash, capped);
    const env: NodeJS.ProcessEnv = { ...process.env, VERAX_POLICY_FILE: uncappedPath };
    delete env.NODE_OPTIONS;
    const firstErr: string[] = [];
    const firstOut: string[] = [];
    const first = await runApprove(
      ["approve", "--from-script", elevatedHold.dir, "s-a"],
      (line) => firstErr.push(line),
      (line) => firstOut.push(line),
      undefined,
      { ...elevatedHooks, env },
    );
    assert.equal(first, 0, firstErr.join(""));
    assert.match(firstOut.join(""), /^approved:/m);
    const secondErr: string[] = [];
    const second = await runApprove(
      ["approve", "--from-script", elevatedHold.dir, "s-b"],
      (line) => secondErr.push(line),
      () => undefined,
      undefined,
      { ...elevatedHooks, env },
    );
    assert.equal(second, 1, secondErr.join(""));
    assert.match(secondErr.join(""), /approve-budget-exceeded/);

    // No snapshot at all: an elevated approve of a spend is refused and the row stays pending.
    const missing = await hold("verax-r15-missing-", capped);
    const missErr: string[] = [];
    const missEnv: NodeJS.ProcessEnv = { ...process.env };
    delete missEnv.NODE_OPTIONS;
    const miss = await runApprove(
      ["approve", "--from-script", missing.dir, "s-a"],
      (line) => missErr.push(line),
      () => undefined,
      undefined,
      { ...elevatedHooks, env: missEnv },
    );
    assert.equal(miss, 1, missErr.join(""));
    assert.match(missErr.join(""), /approve-policy-missing/);
    const still = loadApprovalsFromDir(missing.dir).find((row) => row.ref.endsWith(":s-a") || row.ref === "s-a");
    assert.ok(still);
    assert.equal(still.status === "pending" || still.status === undefined, true);
  });

  it("R15-7 a halted state directory refuses approval and leaves the row pending", async () => {
    const dir = ownerDir("verax-r15-halted-");
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(spendDoc(false)),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "held",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "spend",
        arguments: {
          amountMinor: 100,
          currency: "USD",
          payee: "sample-merchant",
          reference: "h",
          _ref: "held",
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:pay"]) },
    );
    const defer = (await ledger.decisions()).find((row) => row.claims.decision === "defer");
    assert.ok(defer);
    ledger.close();
    writeFileSync(join(dir, "halted"), "", { encoding: "utf8" });
    const again = new FileLedger(dir);
    try {
      const result = await approvePending({
        ledger: again,
        recordSigner: signers.recordSigner,
        now: () => Date.now(),
        nonce: () => "allow-1",
        ref: defer.claims.ref!,
        approverId: "op",
        via: "cli",
        policyHash: defer.claims.policyHash,
        approvals: approvalsLogFor(again),
      });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.reason, "halted");
      enqueueApprovalCommand(dir, { ref: defer.claims.ref!, approverId: "op", atMs: 1, via: "cli" });
      await drainApprovalCommands(dir, async (cmd) => {
        await approvePending({
          ledger: again,
          recordSigner: signers.recordSigner,
          now: () => Date.now(),
          nonce: () => "allow-2",
          ref: cmd.ref,
          approverId: cmd.approverId,
          via: "cli",
          policyHash: defer.claims.policyHash,
          approvals: approvalsLogFor(again),
        });
      });
      const pending = loadApprovalsFromDir(dir).find((row) => row.ref === defer.claims.ref);
      assert.equal(pending?.status, "pending");
      const allows = (await again.decisions()).filter((row) => row.claims.decision === "allow");
      assert.equal(allows.length, 0);
    } finally {
      again.close();
    }
  });

  it("R15-10 elevated approve refuses ProgramData that fails the ancestor check", async () => {
    const err: string[] = [];
    const code = await runApprove(
      ["approve", "held-ref"],
      (line) => err.push(line),
      () => undefined,
      { isTTY: true, ask: async () => "" },
      {
        platform: "win32",
        elevated: () => true,
        codeProbe: () => false,
        env: { ProgramData: "C:\\Users\\me\\fake", USERNAME: "me", USERDOMAIN: "DESKTOP" },
      },
    );
    assert.equal(code, 78, err.join(""));
    assert.match(err.join(""), /refusing/);
    // The injected root is not opened as a state directory.
    assert.equal(err.join("").includes("approve-unknown-ref"), false);
  });
});
