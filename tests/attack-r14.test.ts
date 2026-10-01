// R14: each `it` asserts the behaviour after the fix. On 830496d the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  approvePending,
  createApprovalBudgetGuard,
  createProxy,
  FileLedger,
  loadPolicy,
  MemoryLedger,
  verifyLedger,
} from "@verax-ai/proxy";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import {
  elevatedCodeRefusal,
  planInstall,
  planUninstall,
  refuseWritableCode,
  runInstall,
  runUninstall,
  systemToolName,
  veraxCodeDirectories,
  type PlanOp,
} from "../packages/body/src/install.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function textOf(result: { content: { text: string }[] }): string {
  return result.content.map((part) => part.text).join("");
}

const linuxEnv = {
  SUDO_USER: "runner",
  SUDO_UID: "1000",
  SUDO_GID: "1000",
  VERAX_INVOKING_HOME: "/home/runner",
};

const darwinEnv = {
  SUDO_USER: "runner",
  SUDO_UID: "501",
  SUDO_GID: "20",
  VERAX_INVOKING_HOME: "/Users/runner",
};

const winEnv = {
  ProgramFiles: "C:\\Program Files",
  ProgramData: "C:\\ProgramData",
  USERPROFILE: "C:\\Users\\operator",
  USERNAME: "operator",
  USERDOMAIN: "DESKTOP",
};

const baseOpts = {
  port: 8801,
  days: 30,
  force: false,
  stateExists: false,
};

function underHome(value: string, home: string): boolean {
  const norm = value.replaceAll("\\", "/").replace(/\/+$/, "");
  const root = home.replaceAll("\\", "/").replace(/\/+$/, "");
  return norm === root || norm.startsWith(`${root}/`);
}

function opTouches(op: PlanOp, home: string): boolean {
  if (op.op === "write" || op.op === "mkdir" || op.op === "remove" || op.op === "place-token") {
    return underHome(op.path, home);
  }
  if (op.op === "user-token") return false;
  if (op.op === "argv") {
    return op.argv.some((arg) => underHome(arg, home));
  }
  if (op.op === "init") return underHome(op.stateDir, home);
  return false;
}

describe("attack R14", () => {
  it("R14-8 elevated install does not chown, chmod, or write a path under the invoking home", () => {
    const linux = planInstall("linux", linuxEnv, {
      ...baseOpts,
      execPath: "/usr/bin/node",
      bodyVersion: "0.3.0",
      npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
      ancestorStat: () => ({ uid: 0, mode: 0o755 }),
    });
    assert.equal(linux.ok, true, linux.ok ? "" : linux.message);
    if (!linux.ok) return;
    assert.equal(linux.ops.some((op) => opTouches(op, "/home/runner") && (op.op === "argv" || op.op === "write" || op.op === "mkdir")), false);
    const homeArgv = linux.ops.filter((op) => op.op === "argv" && op.argv.some((arg) => underHome(arg, "/home/runner")));
    assert.equal(homeArgv.length, 0);
    const token = linux.ops.find((op) => op.op === "user-token");
    assert.ok(token && token.op === "user-token");
    assert.equal(token.uid, 1000);
    assert.equal(token.gid, 1000);
    assert.equal(token.tokenPath, "/home/runner/.verax/agent.token");
    assert.equal(linux.ops.some((op) => op.op === "argv" && systemToolName(op.argv[0] ?? "") === "chown" && op.argv.some((arg) => underHome(arg, "/home/runner"))), false);
    assert.equal(linux.ops.some((op) => op.op === "argv" && systemToolName(op.argv[0] ?? "") === "chmod" && op.argv.some((arg) => underHome(arg, "/home/runner"))), false);

    const darwin = planInstall("darwin", darwinEnv, {
      ...baseOpts,
      execPath: "/usr/bin/node",
      bodyVersion: "0.3.0",
      npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
      invokingIds: { uid: 501, gid: 20 },
      ancestorStat: () => ({ uid: 0, mode: 0o755 }),
    });
    assert.equal(darwin.ok, true, darwin.ok ? "" : darwin.message);
    if (!darwin.ok) return;
    assert.equal(darwin.ops.some((op) => op.op === "argv" && op.argv.some((arg) => underHome(arg, "/Users/runner"))), false);
    assert.equal(darwin.ops.some((op) => op.op === "write" && underHome(op.path, "/Users/runner")), false);
    const macToken = darwin.ops.find((op) => op.op === "user-token");
    assert.ok(macToken && macToken.op === "user-token");
    assert.equal(macToken.uid, 501);
    assert.equal(macToken.gid, 20);

    const sid = "S-1-5-21-1001";
    const win = planInstall("win32", winEnv, {
      ...baseOpts,
      execPath: "C:\\Program Files\\nodejs\\node.exe",
      bodyVersion: "0.3.0",
      npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
      userSid: sid,
    });
    assert.equal(win.ok, true, win.ok ? "" : win.message);
    if (!win.ok) return;
    assert.equal(win.tokenPath, `C:\\ProgramData\\Verax\\agent-token\\${sid}\\agent.token`);
    assert.equal(win.ops.some((op) => opTouches(op, "C:\\Users\\operator")), false);
    const dir = `C:\\ProgramData\\Verax\\agent-token\\${sid}`;
    const dirGrant = win.ops.find((op) => op.op === "argv" && op.argv[1] === dir && op.argv.includes("/grant:r"));
    assert.ok(dirGrant && dirGrant.op === "argv");
    assert.ok(dirGrant.argv.includes(`*${sid}:(OI)(CI)RX`));
    assert.ok(dirGrant.argv.includes("*S-1-5-32-544:(OI)(CI)F"));
    assert.ok(dirGrant.argv.includes("*S-1-5-18:(OI)(CI)F"));
    const fileGrant = win.ops.find((op) => op.op === "argv" && op.argv[1] === win.tokenPath);
    assert.ok(fileGrant && fileGrant.op === "argv");
    assert.ok(fileGrant.argv.includes(`*${sid}:(R)`));
    assert.ok(win.ops.some((op) => op.op === "argv" && op.argv.includes("/setowner") && op.argv.includes(dir)));
    assert.ok(win.ops.some((op) => op.op === "place-token" && op.path === win.tokenPath));
    const removed = planUninstall("win32", winEnv, { keepState: false, userSid: sid });
    assert.equal(removed.ok, true, removed.ok ? "" : removed.message);
    if (removed.ok) {
      assert.ok(removed.ops.some((op) => op.op === "remove" && op.path === dir));
    }
  });

  it("R14-9 elevated install, uninstall, and approve refuse user-writable code and proceed when the probe says it is administrator-owned", async () => {
    let err: string[] = [];
    const io = { stdout: { write: () => undefined }, stderr: { write: (line: string) => err.push(line) } };
    // No code directory found is refused, not waved through.
    assert.match(elevatedCodeRefusal("linux", [], { account: "runner", probe: () => false }) ?? "", /could not be found/);
    const writable = await runInstall(["install", "--nope"], {
      platform: "linux",
      env: linuxEnv,
      elevated: () => true,
      codeProbe: () => true,
      exec: () => ({ status: 0, stdout: "", stderr: "" }),
      io,
    });
    assert.equal(writable, 78);
    assert.match(err.join(""), /the verax code at .+ can be changed by runner/);
    assert.match(err.join(""), /\/opt\/verax-node/);

    err = [];
    const owned = await runInstall(["install", "--nope"], {
      platform: "linux",
      env: linuxEnv,
      elevated: () => true,
      codeProbe: () => false,
      exec: () => ({ status: 0, stdout: "", stderr: "" }),
      io,
    });
    assert.equal(owned, 78);
    assert.match(err.join(""), /flag-unknown:--nope/);
    assert.equal(err.join("").includes("can be changed by"), false);

    err = [];
    const uninstallNo = await runUninstall(["uninstall"], {
      platform: "win32",
      env: winEnv,
      elevated: () => true,
      codeProbe: () => true,
      exec: () => ({ status: 0, stdout: "", stderr: "" }),
      io,
    });
    assert.equal(uninstallNo, 78);
    assert.match(err.join(""), /can be changed by DESKTOP\\operator/);
    assert.match(err.join(""), /verax-cli/);

    err = [];
    const uninstallYes = await runUninstall(["uninstall", "--nope"], {
      platform: "win32",
      env: winEnv,
      elevated: () => true,
      codeProbe: () => false,
      exec: () => ({ status: 0, stdout: "", stderr: "" }),
      io,
    });
    assert.equal(uninstallYes, 78);
    assert.match(err.join(""), /flag-unknown:--nope/);
    assert.equal(err.join("").includes("can be changed by"), false);

    err = [];
    const approveNo = await runApprove(["approve"], (line) => err.push(line), () => undefined, undefined, {
      elevated: () => true,
      codeProbe: () => true,
      platform: "win32",
      env: winEnv,
    });
    assert.equal(approveNo, 78);
    assert.match(err.join(""), /can be changed by DESKTOP\\operator/);

    err = [];
    const approveYes = await runApprove(["approve"], (line) => err.push(line), () => undefined, undefined, {
      elevated: () => true,
      codeProbe: () => false,
      platform: "linux",
      env: linuxEnv,
    });
    assert.equal(approveYes, 78);
    assert.match(err.join(""), /verax approve <stateDir> <ref>/);
    assert.equal(err.join("").includes("can be changed by"), false);
  });

  it("R14-9 the code check names real package roots and reads Windows ACLs in one process", () => {
    // Each @verax-ai dependency resolves through its entry point (an exports map need not
    // expose package.json); a path that is not on disk is never on the list.
    const dirs = veraxCodeDirectories();
    const roots = dirs.map((dir) => dir.replaceAll("\\", "/"));
    for (const pkg of ["body", "inventory", "proxy"]) {
      assert.ok(roots.some((dir) => dir.endsWith(`/packages/${pkg}`)), JSON.stringify(roots));
    }
    for (const dir of dirs) assert.ok(existsSync(dir), dir);
    let sddlCalls = 0;
    const refusal = refuseWritableCode("win32", {}, (argv) => {
      const line = argv.join(" ");
      if (/whoami/i.test(argv[0] ?? "")) return { status: 0, stdout: "desk\\op S-1-5-21-1001\n", stderr: "" };
      if (line.includes("GetAccessControl")) sddlCalls += 1;
      return { status: 0, stdout: "{}", stderr: "" };
    });
    assert.equal(sddlCalls, 1, "one PowerShell process for every code path");
    assert.match(refusal ?? "", /can be changed by/);
  });

  it("R14-3 an approved retry is checked against the inputs that were approved", async () => {
    const dir = ownerDir("verax-r14-3-");
    let nowMs = 1_000;
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: loadPolicy({
          version: 1,
          default: "deny",
          approvalTtlMs: 86_400_000,
          rules: [
            {
              id: "send",
              tool: "message.send",
              requires: ["verax:memory"],
              mode: "approve",
              text: "Sending needs operator approval.",
            },
          ],
        }),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => nowMs,
        nonce: (() => {
          let n = 0;
          return () => `n-${++n}`;
        })(),
        resolveInput: async (id) => {
          if (id === "A") return { versionHash: "a".repeat(64), validFromMs: 0, validUntilMs: 1_500 };
          return { versionHash: "b".repeat(64), validFromMs: 0, validUntilMs: 9_000_000 };
        },
        inner: async () => ({ content: [{ type: "text", text: "sent" }], isError: false }),
      });
      const principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
      const first = await proxy.call(
        {
          name: "message.send",
          arguments: { to: "a@b.c", body: "one", _ref: "r-1", _inputs: [{ id: "A", versionHash: "a".repeat(64) }] },
        },
        principal,
      );
      assert.match(textOf(first), /^deferred:approval-required:/);
      const defer = (await ledger.decisions()).find((row) => row.claims.decision === "defer");
      assert.ok(defer?.claims.ref);
      const approved = await approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: () => nowMs,
        nonce: () => "allow-1",
        ref: defer.claims.ref,
        approverId: "op",
        via: "cli",
        policyHash: defer.claims.policyHash,
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
      });
      assert.equal(approved.ok, true, JSON.stringify(approved));
      nowMs = 2_000;
      const changed = await proxy.call(
        {
          name: "message.send",
          arguments: { to: "a@b.c", body: "one", _ref: "r-1", _inputs: [{ id: "B", versionHash: "b".repeat(64) }] },
        },
        principal,
      );
      assert.match(textOf(changed), /^denied:inputs-changed:/);
      const omitted = await proxy.call(
        { name: "message.send", arguments: { to: "a@b.c", body: "one", _ref: "r-1" } },
        principal,
      );
      assert.match(textOf(omitted), /^denied:input-invalid:/);
      const reasons = (await ledger.decisions()).map((row) => row.claims.reasonCode);
      assert.ok(reasons.includes("inputs-changed"));
      assert.ok(reasons.includes("input-invalid"));
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R14-4 a call waiting in the admission queue is denied halted when the flag appears", async () => {
    const dir = ownerDir("verax-r14-4-");
    const ledger = new FileLedger(dir);
    let release = (): void => {};
    let started = false;
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
        now: () => Date.now(),
        nonce: (() => {
          let n = 0;
          return () => `h-${++n}`;
        })(),
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      // Admission holds the queue while it writes the decision; the tool runs after
      // the queue is released. Hold the first decision write so the second call waits
      // inside admission, where the halt flag has to be read again.
      const append = ledger.appendDecisionChained.bind(ledger);
      let held = false;
      ledger.appendDecisionChained = async (...args: Parameters<typeof append>) => {
        if (!held) {
          held = true;
          started = true;
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        }
        return append(...args);
      };
      const principal = { brain: "brain-1", scopes: new Set(["verax:read"]) };
      const slow = proxy.call({ name: "memory.get", arguments: { id: "slow" } }, principal);
      for (let i = 0; i < 50 && !started; i += 1) await new Promise((resolve) => setTimeout(resolve, 5));
      assert.equal(started, true);
      let queued: { content: { text: string }[] } | undefined;
      const waiting = proxy.call({ name: "memory.get", arguments: { id: "next" } }, principal).then((result) => {
        queued = result;
      });
      await new Promise((resolve) => setTimeout(resolve, 20));
      writeFileSync(join(dir, "halted"), "");
      release();
      await slow;
      await waiting;
      assert.match(textOf(queued!), /^denied:halted:/);
      const halted = (await ledger.decisions()).filter((row) => row.claims.reasonCode === "halted");
      assert.ok(halted.length >= 1);
      assert.equal(halted[0]!.claims.decision, "deny");
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R14-1 a missing spend rule is rule-missing and a rule with no daily cap stays open", async () => {
    const capped = loadPolicy({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "cap",
          tool: "spend",
          requires: ["verax:pay"],
          mode: "approve",
          text: "Spends need operator approval.",
          spend: { maxAmountMinor: 500, currency: "USD", payees: ["vendor"], dailyMaxMinor: 500 },
        },
      ],
    });
    const ledger = new MemoryLedger();
    let n = 0;
    const proxy = createProxy({
      policy: capped,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => 1_000,
      nonce: () => `b-${++n}`,
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    const payer = { brain: "brain-1", scopes: new Set(["verax:pay"]) };
    const held = await proxy.call(
      { name: "spend", arguments: { amountMinor: 100, currency: "USD", payee: "vendor", reference: "r", _ref: "s-1" } },
      payer,
    );
    assert.match(textOf(held), /deferred:approval-required:s-1/);
    const defer = (await ledger.decisions()).find((row) => row.claims.decision === "defer");
    assert.ok(defer?.claims.ref);
    const missing = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now: () => 1_000,
      nonce: () => "allow-missing",
      ref: defer.claims.ref,
      approverId: "op",
      via: "cli",
      policyHash: defer.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
      budgetGuard: createApprovalBudgetGuard({
        policy: { ...capped, rule: () => null },
        approvals: proxy.approvals,
        now: () => 1_000,
        ledger,
      }),
    });
    assert.equal(missing.ok, false);
    if (!missing.ok) assert.equal(missing.reason, "rule-missing");

    const openPolicy = loadPolicy({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "open",
          tool: "spend",
          requires: ["verax:pay"],
          mode: "approve",
          text: "Spends need operator approval.",
          spend: { maxAmountMinor: 500, currency: "USD", payees: ["vendor"] },
        },
      ],
    });
    const ledger2 = new MemoryLedger();
    const proxy2 = createProxy({
      policy: openPolicy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: ledger2,
      now: () => 1_000,
      nonce: () => `o-${++n}`,
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    await proxy2.call(
      { name: "spend", arguments: { amountMinor: 100, currency: "USD", payee: "vendor", reference: "r", _ref: "s-open" } },
      payer,
    );
    const defer2 = (await ledger2.decisions()).find((row) => row.claims.decision === "defer");
    assert.ok(defer2?.claims.ref);
    const opened = await approvePending({
      ledger: ledger2,
      recordSigner: RECORD_SIGNER,
      now: () => 1_000,
      nonce: () => "allow-open",
      ref: defer2.claims.ref,
      approverId: "op",
      via: "cli",
      policyHash: defer2.claims.policyHash,
      approvals: proxy2.approvals,
      inputsLog: proxy2.inputsLog,
      budgetGuard: createApprovalBudgetGuard({
        policy: openPolicy,
        approvals: proxy2.approvals,
        now: () => 1_000,
        ledger: ledger2,
      }),
    });
    assert.equal(opened.ok, true, JSON.stringify(opened));
  });

  it("R14-2 a pending spend the ledger already allowed counts toward the daily cap", async () => {
    const policy = loadPolicy({
      version: 1,
      default: "deny",
      approvalTtlMs: 172_800_000,
      rules: [
        {
          id: "cap",
          tool: "spend",
          requires: ["verax:pay"],
          mode: "approve",
          text: "Spends need operator approval.",
          spend: { maxAmountMinor: 200, currency: "USD", payees: ["vendor"], dailyMaxMinor: 150 },
        },
      ],
    });
    const ledger = new MemoryLedger();
    // "one" is asked for on day 0 and approved on day 1; "two" is asked for on day 1.
    // At the request, a pending row counts on the day it was created, so "two" defers.
    const DAY1 = 86_400_000 + 5_000;
    let clock = 5_000;
    let n = 0;
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => clock,
      nonce: () => `p-${++n}`,
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    const payer = { brain: "brain-1", scopes: new Set(["verax:pay"]) };
    const spend = (ref: string) => ({
      name: "spend",
      arguments: { amountMinor: 100, currency: "USD", payee: "vendor", reference: ref, _ref: ref },
    });
    await proxy.call(spend("one"), payer);
    clock = DAY1;
    await proxy.call(spend("two"), payer);
    const approvals = proxy.approvals;
    const real = approvals.updateStatus.bind(approvals);
    let thrown = false;
    approvals.updateStatus = async (ref, status, extra) => {
      if (!thrown && status === "approved") {
        thrown = true;
        throw new Error("stopped before the snapshot");
      }
      return real(ref, status, extra);
    };
    const guard = createApprovalBudgetGuard({ policy, approvals, now: () => DAY1, ledger });
    const firstPolicyHash = (await ledger.decisions())[0]!.claims.policyHash;
    await assert.rejects(
      () =>
        approvePending({
          ledger,
          recordSigner: RECORD_SIGNER,
          now: () => DAY1,
          nonce: () => "allow-one",
          ref: "one",
          approverId: "op",
          via: "cli",
          policyHash: firstPolicyHash,
          approvals,
          inputsLog: proxy.inputsLog,
          budgetGuard: guard,
        }),
      /stopped before the snapshot/,
    );
    const row = (await approvals.listAll()).find((item) => item.ref === "one");
    assert.equal(row?.status, "pending");
    approvals.updateStatus = real;
    const second = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now: () => DAY1,
      nonce: () => "allow-two",
      ref: "two",
      approverId: "op",
      via: "cli",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals,
      inputsLog: proxy.inputsLog,
      budgetGuard: createApprovalBudgetGuard({ policy, approvals, now: () => DAY1, ledger }),
    });
    assert.equal(second.ok, false, JSON.stringify(second));
    if (!second.ok) assert.equal(second.reason, "budget-exceeded");
  });

  it("R14-5 a manifest piece that is not on disk is a missing piece", async () => {
    const dir = ownerDir("verax-r14-5-");
    try {
      mkdirSync(join(dir, "pieces", "p1"), { recursive: true });
      if (process.platform !== "win32") chmodSync(join(dir, "pieces"), 0o700);
      writeFileSync(join(dir, "pieces", "p1", "effects.jsonl"), "", { mode: 0o600 });
      writeFileSync(
        join(dir, "ledger-manifest.json"),
        `${JSON.stringify({
          version: 1,
          countedAtMs: [],
          pieces: [
            {
              id: "p1",
              decisions: "pieces/p1/decisions.jsonl",
              effects: "pieces/p1/effects.jsonl",
              inputs: "pieces/p1/inputs.jsonl",
              n: 0,
              effectN: 0,
              firstMs: null,
              lastMs: null,
              lastHash: null,
              closed: false,
            },
          ],
        })}\n`,
      );
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false);
      assert.ok(
        result.problems.some((problem) => problem === "missing piece: pieces/p1/decisions.jsonl"),
        JSON.stringify(result.problems),
      );
      assert.equal(result.problems.some((problem) => problem === "missing piece: pieces/p1/effects.jsonl"), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R14-7 a repeated signed duplicate-effect row is counted once", async () => {
    const dir = ownerDir("verax-r14-7-");
    const ref = "dup-ref";
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
        now: () => 10,
        nonce: () => ref,
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        { name: "memory.get", arguments: { id: "a", _ref: ref } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      await assert.rejects(
        () =>
          ledger.appendEffect({
            ref,
            effectHash: "ab".repeat(32),
            effectClass: "memory.get",
            timestampMs: 99,
            actor: "brain-1",
          }),
        /duplicate-effect:dup-ref/,
      );
    } finally {
      ledger.close();
    }
    try {
      const path = join(dir, "effects.jsonl");
      const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.trim() !== "");
      const duplicate = lines.find((line) => line.includes('"duplicate-effect"'));
      assert.ok(duplicate);
      writeFileSync(path, `${lines.join("\n")}\n${duplicate}\n`, { mode: 0o600 });
      const result = await verifyLedger(dir);
      assert.ok(
        result.problems.some((problem) => problem === `duplicate-effect row repeated: ref ${ref}`),
        JSON.stringify(result.problems),
      );
      const copies = readFileSync(path, "utf8").split("\n").filter((line) => line.includes('"duplicate-effect"'));
      assert.equal(copies.length, 2);
      assert.equal(result.effectsBound, 2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
