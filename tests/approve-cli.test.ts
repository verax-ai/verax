import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createProxy, FileLedger, loadApprovalsFromDir, loadPolicy } from "@verax-ai/proxy";
import { runApprove } from "../packages/body/src/approve-cli.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

const POLICY = {
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

describe("verax approve CLI", () => {
  it("writes a chained allow for a pending defer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-approve-cli-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(POLICY),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "d-cli",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "memory.put",
        arguments: { id: "n1", body: "x", source: { kind: "t" }, validUntilMs: 9_999 },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    ledger.close();
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "approve", "--from-script", dir, "d-cli"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (buf: Buffer) => {
      stdout += String(buf);
    });
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 0, stderr);
    assert.match(stdout, /^approved:/);
    const again = new FileLedger(dir);
    const recs = await again.decisions();
    assert.equal(recs.length, 2);
    assert.equal(recs[0]!.claims.decision, "defer");
    assert.equal(recs[1]!.claims.decision, "allow");
    assert.equal(recs[1]!.claims.reasonCode, "approved-by-operator");
    again.close();
    // The signed inputs name the door: this approval came from `verax approve`.
    const allowRef = recs[1]!.claims.ref;
    const row = readFileSync(join(dir, "inputs.jsonl"), "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as { ref: string; inputs: { approver?: { via?: string } } })
      .find((r) => r.ref === allowRef);
    assert.equal(row?.inputs.approver?.via, "cli-script");
  });

  it("accepts a raw _ref when exactly one pending row ends with it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-approve-raw-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(POLICY),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "d1",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "memory.put",
        arguments: { id: "n1", body: "x", source: { kind: "t" }, validUntilMs: 9_999, _ref: "d1" },
      },
      { brain: "alice", scopes: new Set(["verax:memory"]), iss: "https://issuer-a.example" },
    );
    ledger.close();
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "approve", "--from-script", dir, "d1"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (buf: Buffer) => {
      stdout += String(buf);
    });
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 0, stderr);
    assert.match(stdout, /^approved:/);
  });

  it("refuses a raw _ref when two tenants share it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-approve-amb-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(POLICY),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "d1",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const args = { id: "n1", body: "x", source: { kind: "t" }, validUntilMs: 9_999, _ref: "d1" };
    await proxy.call(
      { name: "memory.put", arguments: args },
      { brain: "alice", scopes: new Set(["verax:memory"]), iss: "https://issuer-a.example" },
    );
    await proxy.call(
      { name: "memory.put", arguments: args },
      { brain: "bob", scopes: new Set(["verax:memory"]), iss: "https://issuer-b.example" },
    );
    ledger.close();
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "approve", "--from-script", dir, "d1"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (buf: Buffer) => {
      stdout += String(buf);
    });
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 78, stdout);
    assert.match(stderr, /^ambiguous-ref\n/);
    assert.match(stderr, /:d1\n/);
    const lines = stderr.trim().split("\n");
    assert.equal(lines[0], "ambiguous-ref");
    assert.equal(lines.length, 3);
    assert.equal(stdout, "");
  });

  it("approves a held spend of 100 from an injected terminal and refuses a wrong amount", async () => {
    const spendPolicy = {
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
            dailyMaxMinor: 10_000,
          },
        },
      ],
    };
    const hold = async (prefix: string) => {
      const dir = mkdtempSync(join(tmpdir(), prefix));
      const signers = loadOrCreateSigners(dir);
      const ledger = new FileLedger(dir);
      const proxy = createProxy({
        policy: loadPolicy(spendPolicy),
        recordSigner: signers.recordSigner,
        effectSigner: signers.effectSigner,
        ledger,
        now: () => Date.now(),
        nonce: () => "d-spend",
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        {
          name: "spend",
          arguments: {
            amountMinor: 100,
            currency: "USD",
            payee: "sample-merchant",
            reference: "demo-1",
            _ref: "d-spend",
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:pay"]) },
      );
      ledger.close();
      return dir;
    };

    const yesDir = await hold("verax-approve-tty-");
    const yesErr: string[] = [];
    const yesOut: string[] = [];
    const yesCode = await runApprove(
      ["approve", yesDir, "d-spend"],
      (s) => yesErr.push(s),
      (s) => yesOut.push(s),
      { isTTY: true, ask: async () => "100" },
    );
    assert.equal(yesCode, 0, yesErr.join(""));
    assert.match(yesOut.join(""), /^held tool=spend /);
    const yesLedger = new FileLedger(yesDir);
    const yesRecs = await yesLedger.decisions();
    yesLedger.close();
    const allow = yesRecs.find((rec) => rec.claims.decision === "allow");
    assert.ok(allow);
    const via = readFileSync(join(yesDir, "inputs.jsonl"), "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as { ref: string; inputs: { approver?: { via?: string } } })
      .find((row) => row.ref === allow!.claims.ref);
    assert.equal(via?.inputs.approver?.via, "cli");

    const noDir = await hold("verax-approve-tty-miss-");
    const noErr: string[] = [];
    const noCode = await runApprove(
      ["approve", noDir, "d-spend"],
      (s) => noErr.push(s),
      () => undefined,
      { isTTY: true, ask: async () => "5" },
    );
    assert.equal(noCode, 1);
    assert.match(noErr.join(""), /approve-amount-mismatch/);
    const still = loadApprovalsFromDir(noDir).filter((row) => row.subject === "spend");
    assert.equal(still.length, 1, JSON.stringify(still));
    assert.equal(still[0]!.status, "pending");
    const noLedger = new FileLedger(noDir);
    const noRecs = await noLedger.decisions();
    noLedger.close();
    assert.equal(
      noRecs.some((rec) => rec.claims.decision === "allow"),
      false,
    );
  });

  it("checks the amount before queueing while the ledger stays locked", async () => {
    const spendPolicy = {
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
            dailyMaxMinor: 10_000,
          },
        },
      ],
    };
    const dir = mkdtempSync(join(tmpdir(), "verax-approve-locked-"));
    const signers = loadOrCreateSigners(dir);
    const lock = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(spendPolicy),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger: lock,
      now: () => Date.now(),
      nonce: () => "d-locked",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "spend",
        arguments: {
          amountMinor: 100,
          currency: "USD",
          payee: "sample-merchant",
          reference: "demo-1",
          _ref: "d-locked",
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:pay"]) },
    );
    const queue = join(dir, "approval-commands.jsonl");
    const missErr: string[] = [];
    const missCode = await runApprove(
      ["approve", dir, "d-locked"],
      (s) => missErr.push(s),
      () => undefined,
      { isTTY: true, ask: async () => "999" },
    );
    assert.equal(missCode, 1);
    assert.match(missErr.join(""), /approve-amount-mismatch/);
    assert.equal(existsSync(queue), false);

    const hitOut: string[] = [];
    const hitErr: string[] = [];
    const hitCode = await runApprove(
      ["approve", dir, "d-locked"],
      (s) => hitErr.push(s),
      (s) => hitOut.push(s),
      { isTTY: true, ask: async () => "100" },
    );
    assert.equal(hitCode, 0, hitErr.join(""));
    assert.match(hitOut.join(""), /approve-queued/);
    const queued = readFileSync(queue, "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as { ref: string; via?: string });
    assert.equal(queued.length, 1);
    assert.equal(queued[0]!.ref, "d-locked");
    assert.equal(queued[0]!.via, "cli");
    lock.close();
  });
});
