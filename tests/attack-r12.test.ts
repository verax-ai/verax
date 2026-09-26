// R12: each `it` asserts the safe behaviour. On d1e33ab the implementation
// does the unsafe thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
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
  tenantKey,
  verifyLedger,
} from "@verax-ai/proxy";

import { auditExplain } from "../packages/body/src/tools/audit.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";
import { spentTodayMinorOf } from "../packages/proxy/src/approvals.ts";
import { startedWithoutEnd } from "../packages/proxy/src/in-flight-log.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "../packages/proxy/tests/helpers.ts";

const pins = {
  publicKeyPem: RECORD_SIGNER.publicKeyPem,
  effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
};

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function textOf(result: { content: { text: string }[] }): string {
  return result.content.map((part) => part.text).join("");
}

describe("attack R12", () => {
  it("R12-1 approving two 100 caps across midnight does not spend 200 in one day", async () => {
    const createdA = Date.UTC(2026, 8, 25, 23, 59, 0);
    const createdB = Date.UTC(2026, 8, 26, 0, 0, 30);
    const approveA = Date.UTC(2026, 8, 26, 0, 2, 0);
    const approveB = Date.UTC(2026, 8, 26, 0, 3, 0);
    let nowMs = createdA;
    const ledger = new MemoryLedger();
    // The body and the CLI both pass this guard to approvePending; without it the cap is not checked at all.
    const policy = loadPolicy({
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
            spend: { maxAmountMinor: 100, currency: "USD", payees: ["vendor"], dailyMaxMinor: 100 },
          },
        ],
      });
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => nowMs,
      nonce: queuedNonce(["n1", "n2", "n3", "n4"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    const payer = { brain: "brain-1", scopes: new Set(["verax:pay"]) };
    const spend = (ref: string, reference: string) => ({
      name: "spend",
      arguments: { amountMinor: 100, currency: "USD", payee: "vendor", reference, _ref: ref },
    });
    nowMs = createdA;
    const first = await proxy.call(spend("spend-a", "ref-a"), payer);
    assert.match(textOf(first), /deferred:approval-required:spend-a/);
    nowMs = createdB;
    const second = await proxy.call(spend("spend-b", "ref-b"), payer);
    assert.match(textOf(second), /deferred:approval-required:spend-b/);
    const policyHash = (await ledger.decisions())[0]!.claims.policyHash;
    const approve = (ref: string, at: number) => {
      nowMs = at;
      return approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: () => nowMs,
        nonce: queuedNonce([`allow-${ref}`]),
        ref,
        approverId: "op",
        via: "cli",
        policyHash,
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
        budgetGuard: createApprovalBudgetGuard({ policy, approvals: proxy.approvals, now: () => nowMs }),
      });
    };
    const okA = await approve("spend-a", approveA);
    assert.equal(okA.ok, true, JSON.stringify(okA));
    const rowA = (await proxy.approvals.listAll()).find((row) => row.ref === "spend-a");
    assert.equal(rowA?.status, "approved");
    assert.equal(rowA?.approvedAtMs, approveA);
    const okB = await approve("spend-b", approveB);
    assert.equal(okB.ok, false, JSON.stringify(okB));
    if (!okB.ok) assert.equal(okB.reason, "budget-exceeded");
  });

  it("an approved spend with no approvedAtMs still counts toward today", () => {
    const yesterday = Date.UTC(2026, 8, 25, 12, 0, 0);
    const today = Date.UTC(2026, 8, 26, 12, 0, 0);
    const sum = spentTodayMinorOf(
      [
        {
          subject: "spend",
          status: "approved",
          createdAtMs: yesterday,
          expiresAtMs: yesterday + 86_400_000,
          args: { amountMinor: 40, currency: "USD" },
        },
      ],
      today,
      "USD",
      86_400_000,
      0,
    );
    assert.equal(sum, 40);
  });

  it("R12-2 a recipient list is egress-host-missing", async () => {
    const tab = String.fromCharCode(9);
    const lf = String.fromCharCode(10);
    const listed = [
      "a@evil.com,b@allowed.com",
      "a@evil.com;b@allowed.com",
      `a@evil.com${tab}b@allowed.com`,
      `b@allowed.com${lf}`,
    ];
    const ledger = new MemoryLedger();
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        egress: ["allowed.com"],
        rules: [
          {
            id: "message-send",
            tool: "message.send",
            requires: ["verax:act"],
            text: "Sending a message needs the act scope.",
            egress: true,
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(listed.map((_, i) => `list-${i}`)),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "sent" }], isError: false };
      },
    });
    const sender = { brain: "brain-1", scopes: new Set(["verax:act"]) };
    for (const to of listed) {
      const out = await proxy.call({ name: "message.send", arguments: { to, text: "hi" } }, sender);
      assert.match(textOf(out), /denied:egress-host-missing:/, JSON.stringify(to));
      const rec = (await ledger.decisions()).find((row) => textOf(out).endsWith(row.claims.ref ?? ""));
      assert.equal(rec?.claims.reasonCode, "egress-host-missing", JSON.stringify(to));
    }
    assert.equal(inner, 0);
  });

  it("a single plain address still passes egress", async () => {
    const ledger = new MemoryLedger();
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        egress: ["allowed.com"],
        rules: [
          {
            id: "message-send",
            tool: "message.send",
            requires: ["verax:act"],
            text: "Sending a message needs the act scope.",
            egress: true,
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["plain-1"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "sent" }], isError: false };
      },
    });
    const out = await proxy.call(
      { name: "message.send", arguments: { to: "alice@allowed.com", text: "hi" } },
      { brain: "brain-1", scopes: new Set(["verax:act"]) },
    );
    assert.equal(out.isError, false, textOf(out));
    assert.equal(inner, 1);
    assert.equal((await ledger.decisions())[0]?.claims.decision, "allow");
  });

  it("R12-3 an approved explain of another tenant's ref is not explained", async () => {
    const writerA = {
      brain: "alice",
      scopes: new Set(["verax:memory", "verax:read"]),
      iss: "https://issuer-a.example",
    };
    const readerB = {
      brain: "bob",
      scopes: new Set(["verax:read"]),
      iss: "https://issuer-b.example",
    };
    const stateDir = ownerDir("verax-r12-3-");
    const policyFile = join(stateDir, "policy.json");
    writeFileSync(
      policyFile,
      `${JSON.stringify({
        version: 1,
        default: "deny",
        approvalTtlMs: 86_400_000,
        rules: [
          {
            id: "memory-put",
            tool: "memory.put",
            requires: ["verax:memory"],
            text: "Writing memory needs the memory scope.",
          },
          {
            id: "audit-explain",
            tool: "audit.explain",
            requires: ["verax:read"],
            mode: "approve",
            text: "Reading an explanation needs the read scope.",
          },
        ],
      })}\n`,
    );
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const put = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "note-1",
            body: { secret: "alice-only" },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999_999_999_999,
            _ref: "invoice-1",
          },
        },
        writerA,
      );
      assert.equal(put.isError, false, textOf(put));
      const aliceRef = `${tenantKey(writerA)}:invoice-1`;
      const got = await services.proxy.call(
        { name: "audit.explain", arguments: { ref: aliceRef, _ref: "ask-b" } },
        readerB,
      );
      assert.equal(got.isError, true);
      assert.deepEqual(JSON.parse(textOf(got)), { error: "not-found" });
      assert.equal(textOf(got).includes("alice-only"), false);
      assert.equal(textOf(got).includes("\"record\""), false);
      const recs = await services.ledger.decisions();
      const explainDeny = recs.find(
        (row) => row.claims.subject === "audit.explain" && row.claims.reasonCode === "tenant-mismatch",
      );
      assert.ok(explainDeny);
      assert.equal(explainDeny.claims.decision, "deny");
      assert.equal(
        recs.some((row) => row.claims.subject === "audit.explain" && row.claims.decision === "defer"),
        false,
      );
      const direct = await auditExplain(
        { name: "audit.explain", arguments: { ref: aliceRef } },
        services.ledger,
        await services.explainOpts(),
        { principal: readerB, stateDir },
      );
      assert.equal(direct.isError, true);
      assert.deepEqual(JSON.parse(textOf(direct)), { error: "not-found" });
      assert.equal(textOf(direct).includes("alice-only"), false);
      assert.equal(textOf(direct).includes("\"record\""), false);
    } finally {
      services.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }

    let mismatch = false;
    let ran = 0;
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        approvalTtlMs: 86_400_000,
        rules: [
          {
            id: "audit-explain",
            tool: "audit.explain",
            requires: ["verax:read"],
            mode: "approve",
            text: "Reading an explanation needs the read scope.",
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["defer-1", "allow-1", "deny-1"]),
      checkTenantMismatch: async () => mismatch,
      inner: async () => {
        ran += 1;
        return {
          content: [{ type: "text", text: JSON.stringify({ record: { secret: "other-tenant" } }) }],
          isError: false,
        };
      },
    });
    const ask = {
      name: "audit.explain",
      arguments: { ref: "alice-ref", _ref: "ask-1" },
    };
    const reader = { brain: "bob", scopes: new Set(["verax:read"]) };
    const deferred = await proxy.call(ask, reader);
    assert.match(textOf(deferred), /deferred:approval-required:ask-1/);
    const defer = (await ledger.decisions()).find((row) => row.claims.decision === "defer");
    assert.ok(defer?.claims.ref);
    const approved = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now: tickingNow(),
      nonce: queuedNonce(["allow-ref"]),
      ref: defer.claims.ref,
      approverId: "op",
      via: "cli",
      policyHash: defer.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(approved.ok, true, JSON.stringify(approved));
    mismatch = true;
    const retried = await proxy.call(ask, reader);
    assert.equal(ran, 0);
    assert.equal(retried.isError, true);
    assert.deepEqual(JSON.parse(textOf(retried)), { error: "not-found" });
    assert.equal(textOf(retried).includes("other-tenant"), false);
    const denied = (await ledger.decisions()).find((row) => row.claims.reasonCode === "tenant-mismatch");
    assert.equal(denied?.claims.decision, "deny");
  });

  it("R12-4 a call whose effect cannot be written does not run again", async () => {
    const dir = ownerDir("verax-r12-4-");
    const call = { name: "message.send", arguments: { to: "a@b.co", body: "once", _ref: "r-once" } };
    const writer = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    const policy = loadPolicy({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "send-approve",
          tool: "message.send",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Sending needs operator approval.",
        },
      ],
    });
    let calls = 0;
    const ledger = new FileLedger(dir);
    ledger.appendEffect = async () => {
      throw new Error("effect-unwritable");
    };
    let n = 0;
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => Date.now(),
      nonce: () => `n-${++n}`,
      inner: async () => {
        calls += 1;
        return { content: [{ type: "text", text: "sent" }], isError: false };
      },
    });
    try {
      const deferred = await proxy.call(call, writer);
      assert.match(textOf(deferred), /deferred:approval-required:r-once/);
      const defer = (await ledger.decisions()).find((row) => row.claims.decision === "defer");
      assert.ok(defer?.claims.ref);
      const approved = await approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: () => Date.now(),
        nonce: () => `n-approve-${++n}`,
        ref: defer.claims.ref,
        approverId: "op",
        via: "cli",
        policyHash: defer.claims.policyHash,
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
      });
      assert.equal(approved.ok, true, JSON.stringify(approved));
      await assert.rejects(() => proxy.call(call, writer), /effect-unwritable/);
      assert.equal(calls, 1);
      assert.equal(startedWithoutEnd(dir, "r-once"), true);
      ledger.close();

      const ledger2 = new FileLedger(dir);
      const proxy2 = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger: ledger2,
        now: () => Date.now(),
        nonce: () => `n2-${++n}`,
        inner: async () => {
          calls += 1;
          return { content: [{ type: "text", text: "sent" }], isError: false };
        },
      });
      try {
        const again = await proxy2.call(call, writer);
        assert.match(textOf(again), /^denied:outcome-unknown:/, textOf(again));
        assert.equal(calls, 1);
      } finally {
        ledger2.close();
      }
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a real thrown call still ends its mark and verifies", async () => {
    const dir = ownerDir("verax-r12-4b-");
    const call = { name: "message.send", arguments: { to: "a@b.co", body: "boom", _ref: "r-threw" } };
    const writer = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    const policy = loadPolicy({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "send-approve",
          tool: "message.send",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Sending needs operator approval.",
        },
      ],
    });
    let calls = 0;
    let n = 0;
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => 1_700_000_000_000,
      nonce: () => `t-${++n}`,
      inner: async () => {
        calls += 1;
        throw new Error("alici reddetti");
      },
    });
    try {
      const deferred = await proxy.call(call, writer);
      assert.match(textOf(deferred), /deferred:approval-required:r-threw/);
      const defer = (await ledger.decisions()).find((row) => row.claims.decision === "defer");
      assert.ok(defer?.claims.ref);
      const approved = await approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: () => 1_700_000_000_010,
        nonce: () => `t-approve-${++n}`,
        ref: defer.claims.ref,
        approverId: "op",
        via: "cli",
        policyHash: defer.claims.policyHash,
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
      });
      assert.equal(approved.ok, true, JSON.stringify(approved));
      await assert.rejects(() => proxy.call(call, writer), /alici reddetti/);
      assert.equal(calls, 1);
      const flight = join(dir, "in-flight");
      const left = existsSync(flight) ? readdirSync(flight) : [];
      assert.deepEqual(left, []);
      ledger.close();
      const verified = await verifyLedger(dir, pins);
      assert.equal(verified.ok, true, JSON.stringify(verified.problems));
      assert.ok(verified.effectsBound >= 1);

      const ledger2 = new FileLedger(dir);
      const proxy2 = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger: ledger2,
        now: () => 1_700_000_000_020,
        nonce: () => `t2-${++n}`,
        inner: async () => {
          calls += 1;
          return { content: [{ type: "text", text: "sent" }], isError: false };
        },
      });
      try {
        await proxy2.call(call, writer);
        assert.equal(calls, 1);
      } finally {
        ledger2.close();
      }
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R12-5 deleting effects.jsonl is not a clean ledger", async () => {
    const dir = ownerDir("verax-r12-5-");
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        rules: [
          {
            id: "get",
            tool: "memory.get",
            requires: ["verax:read"],
            text: "Reading memory needs the read scope.",
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_000, 10),
      nonce: queuedNonce(["get-a", "get-b"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };
    try {
      for (const ref of ["get-a", "get-b"]) {
        const out = await proxy.call({ name: "memory.get", arguments: { id: ref, _ref: ref } }, reader);
        assert.equal(out.isError, false, textOf(out));
      }
      ledger.close();
      const before = await verifyLedger(dir, pins);
      assert.equal(before.ok, true, JSON.stringify(before.problems));
      assert.equal(before.effectsBound, 2);
      assert.equal(before.effectCompleteness, "effect completeness checked");

      const indexPath = join(dir, "index.jsonl");
      const indexText = readFileSync(indexPath, "utf8");
      unlinkSync(indexPath);
      const unchecked = await verifyLedger(dir, pins);
      assert.equal(unchecked.ok, true, JSON.stringify(unchecked.problems));
      assert.equal(unchecked.effectCompleteness, "effect completeness was not checked");
      writeFileSync(indexPath, indexText);

      unlinkSync(join(dir, "effects.jsonl"));
      const after = await verifyLedger(dir, pins);
      assert.equal(after.ok, false, JSON.stringify(after));
      assert.equal(after.effectsBound, 0);
      for (const ref of ["get-a", "get-b"]) {
        assert.ok(
          after.problems.some((problem) => problem.includes(ref) && problem.includes("no bound effect row")),
          JSON.stringify(after.problems),
        );
      }
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an allow whose effect never happened and which the index does not mark still verifies", async () => {
    const dir = ownerDir("verax-r12-5b-");
    const ledger = new FileLedger(dir);
    ledger.appendEffect = async () => {};
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        rules: [
          {
            id: "get",
            tool: "memory.get",
            requires: ["verax:read"],
            text: "Reading memory needs the read scope.",
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["never-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const out = await proxy.call(
        { name: "memory.get", arguments: { id: "x", _ref: "never-1" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      assert.equal(out.isError, false, textOf(out));
      ledger.close();
      const indexText = readFileSync(join(dir, "index.jsonl"), "utf8");
      const marked = indexText.split("\n").some((line) => {
        if (line === "") return false;
        const row = JSON.parse(line) as { hasEffect?: boolean; kind?: string };
        return row.hasEffect === true || row.kind === "effect";
      });
      assert.equal(marked, false, indexText);
      const result = await verifyLedger(dir, pins);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.index.present, true);
      assert.equal(result.effectCompleteness, "effect completeness checked");
      assert.equal(
        result.problems.some((problem) => problem.includes("no bound effect row")),
        false,
        JSON.stringify(result.problems),
      );
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R12-6 an empty _inputs list is inputs-required", async () => {
    const ledger = new MemoryLedger();
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        requireInputs: true,
        rules: [
          {
            id: "get",
            tool: "memory.get",
            requires: ["verax:read"],
            text: "Reading memory needs the read scope.",
          },
        ],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["empty-r12"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    const out = await proxy.call(
      { name: "memory.get", arguments: { id: "x", _inputs: [] } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    assert.equal(out.isError, true);
    assert.match(textOf(out), /denied:inputs-required:empty-r12/);
    assert.equal(inner, 0);
    const rec = (await ledger.decisions())[0];
    assert.equal(rec?.claims.decision, "deny");
    assert.equal(rec?.claims.reasonCode, "inputs-required");
    assert.equal(rec?.claims.effectHash, null);
  });
});
