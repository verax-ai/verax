// R6: black box against the product as a whole. Each finding `it` asserts the
// safe behaviour. On the current tree the implementation does the unsafe
// thing, so the assertion fails. The fuzz `it` asserts invariants that hold
// today; it passes because that pass found no break.

import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { approvePending } from "../packages/proxy/src/approvals.ts";
import { MemoryLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import type { Principal, ToolCall } from "../packages/proxy/src/types.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce } from "../packages/proxy/tests/helpers.ts";

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
} as const;

const INPUT_POLICY = {
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
} as const;

const FUZZ_POLICY = {
  version: 1,
  default: "deny",
  rules: [
    {
      id: "spend-true",
      tool: "spend",
      requires: ["verax:pay"],
      mode: "approve",
      text: "Spends need operator approval.",
      spend: { maxAmountMinor: 100, currency: "TRY", payees: ["true-ads"] },
    },
    {
      id: "memory-get",
      tool: "memory.get",
      requires: ["verax:read"],
      text: "Reading memory needs the read scope.",
    },
  ],
} as const;

const payer: Principal = { brain: "brain-1", scopes: new Set(["verax:pay"]) };

function spendCall(reference: string): ToolCall {
  return {
    name: "spend",
    arguments: { amountMinor: 100, currency: "TRY", payee: "true-ads", reference },
  };
}

describe("attack R6", () => {
  it("R6-1 a spend reference cannot carry a line separator or a C1 newline", () => {
    const policy = loadPolicy(SPEND_POLICY);
    for (const mark of ["\u2028", "\u2029", "\u0085"]) {
      const verdict = policy.evaluate(spendCall(`inv${mark}payee=other`), payer);
      assert.equal(verdict.decision, "deny", `mark U+${mark.codePointAt(0)!.toString(16)}`);
      assert.equal(verdict.reasonCode, "spend-args-invalid");
    }
  });

  it("R6-1 one code point of each terminal class is refused and escaped", async () => {
    const policy = loadPolicy(SPEND_POLICY);
    const table = [
      { cls: "Cc", mark: "\u0085" },
      { cls: "Cf", mark: "\uFEFF" },
      { cls: "Zl", mark: "\u2028" },
      { cls: "Zp", mark: "\u2029" },
    ];
    for (const { cls, mark } of table) {
      const reference = `inv${mark}payee=other`;
      const verdict = policy.evaluate(spendCall(reference), payer);
      assert.equal(verdict.decision, "deny", cls);
      assert.equal(verdict.reasonCode, "spend-args-invalid", cls);

      const stateDir = mkdtempSync(join(tmpdir(), "verax-r6-held-"));
      try {
        const ref = "spend-ref-1";
        const pending = {
          ref,
          requestHash: "abc123abc123deadbeef",
          subject: "spend",
          args: { amountMinor: 100, currency: "TRY", payee: "true-ads", reference },
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
        await runApprove(["approve", stateDir, ref], () => {}, (line) => out.push(line), {
          isTTY: true,
          ask: async () => "100",
        });
        const held = out.find((line) => line.startsWith("held ")) ?? "";
        const hex = mark.codePointAt(0)!.toString(16).padStart(4, "0");
        assert.equal(held.includes(mark), false, cls);
        assert.match(held, new RegExp(`\\\\u${hex}`), cls);
        assert.match(held, /payee=true-ads/, cls);
        assert.doesNotMatch(held, /payee=other/, cls);
      } finally {
        rmSync(stateDir, { recursive: true, force: true });
      }
    }
  });

  it("R6-2 an approved retry does not run after the cited input has expired", async () => {
    const ledger = new MemoryLedger();
    const versionHash = "ab".repeat(32);
    let nowMs = 1_000;
    let ran = 0;
    const proxy = createProxy({
      policy: loadPolicy(INPUT_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => nowMs,
      nonce: queuedNonce(["d1", "deny-1"]),
      resolveInput: async () => ({ versionHash, validFromMs: 0, validUntilMs: 5_000 }),
      inner: async () => {
        ran += 1;
        return { content: [{ type: "text", text: "wrote" }], isError: false };
      },
    });
    const principal: Principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    const call: ToolCall = {
      name: "memory.put",
      arguments: {
        id: "n1",
        body: "hello",
        source: { kind: "test" },
        validUntilMs: 9_999,
        _ref: "r1",
        _inputs: [{ id: "doc-1", versionHash }],
      },
    };
    const held = await proxy.call(call, principal);
    assert.match(held.content[0]?.text ?? "", /deferred:approval-required:r1/);
    assert.equal(ran, 0);
    const defer = (await ledger.decisions())[0]!;
    const approved = await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now: () => nowMs,
      nonce: queuedNonce(["a1"]),
      ref: "r1",
      approverId: "op-1",
      via: "cli",
      policyHash: defer.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    assert.equal(approved.ok, true);
    nowMs = 6_000;
    const retry = await proxy.call(call, principal);
    assert.equal(ran, 0);
    assert.match(retry.content[0]?.text ?? "", /input-invalid/);
    assert.equal((await ledger.effects()).length, 0);
  });

  it("R6 fuzz: policy and the JSON-RPC argument object keep the deny invariant", async () => {
    const policy = loadPolicy(FUZZ_POLICY);
    const rand = mulberry32(0x6e6);
    const names = ["spend", "memory.get", "nope", ""];
    let proxyDenies = 0;
    for (let i = 0; i < 80; i += 1) {
      const name = names[Math.floor(rand() * names.length)]!;
      const params = {
        name,
        arguments: rand() < 0.15 ? null : argumentBag(rand, name),
      };
      const call = toolCallFromRpc(params);
      const scopes = new Set<string>();
      if (rand() < 0.5) scopes.add("verax:pay");
      if (rand() < 0.5) scopes.add("verax:read");
      const principal: Principal = { brain: "fuzz", scopes };
      const verdict = policy.evaluate(call, principal);
      assert.ok(verdict.decision === "allow" || verdict.decision === "deny" || verdict.decision === "defer");
      if (call.name === "spend") assert.notEqual(verdict.decision, "allow");
      if (call.name === "memory.get" && !scopes.has("verax:read")) assert.notEqual(verdict.decision, "allow");
      if (verdict.decision !== "deny" || proxyDenies >= 12) continue;
      proxyDenies += 1;
      const ledger = new MemoryLedger();
      let ran = 0;
      const proxy = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => 1_000 + i,
        nonce: queuedNonce([`n${i}`]),
        inner: async () => {
          ran += 1;
          return { content: [{ type: "text", text: "ran" }], isError: false };
        },
      });
      await proxy.call(call, principal);
      assert.equal(ran, 0);
      assert.equal((await ledger.effects()).length, 0);
    }
    assert.ok(proxyDenies > 0);
  });
});

/** The handler's object: `arguments ?? {}`, then the same value evaluate sees. */
function toolCallFromRpc(params: { name?: unknown; arguments?: unknown }): ToolCall {
  const name = typeof params.name === "string" ? params.name : "";
  const raw = params.arguments ?? {};
  return { name, arguments: raw as Record<string, unknown> };
}

function argumentBag(rand: () => number, name: string): Record<string, unknown> {
  if (name === "spend") {
    const bag: Record<string, unknown> = {
      amountMinor: rand() < 0.7 ? 10 : "10",
      currency: rand() < 0.8 ? "TRY" : "try",
      payee: rand() < 0.8 ? "true-ads" : "other",
      reference: rand() < 0.8 ? "inv" : "x".repeat(200),
    };
    if (rand() < 0.3) bag.extra = 1;
    if (rand() < 0.2) bag.__proto__ = { payee: "other" };
    return bag;
  }
  const bag: Record<string, unknown> = {};
  const n = Math.floor(rand() * 4);
  for (let i = 0; i < n; i += 1) bag[`k${i}`] = rand() < 0.5 ? i : { nested: true };
  return bag;
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
