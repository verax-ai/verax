import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { parsePolicyDocument } from "../src/policy.ts";

// A key the parser does not know used to be dropped without a word, so a
// misspelt control (`requireInput`, `ttl`, `dailyMax` on a rule) left the
// policy weaker than the file reads and still loaded. It is refused instead.

function base(): Record<string, unknown> {
  return {
    version: 1,
    default: "deny",
    rules: [{ id: "r1", tool: "fs.read", requires: [], text: "read files" }],
  };
}

function spendRule(): Record<string, unknown> {
  return {
    id: "pay",
    tool: "spend",
    requires: [],
    text: "pay a listed payee",
    mode: "approve",
    spend: { maxAmountMinor: 1000, currency: "EUR", payees: ["acme"] },
  };
}

describe("policy unknown keys", () => {
  it("still loads a document that uses only known keys", () => {
    const doc = base();
    doc.egress = ["example.com"];
    (doc.rules as unknown[]).push({ id: "send", tool: "message.send", requires: [], text: "send messages", egress: true });
    doc.approvalTtlMs = 1000;
    doc.limits = { ratePerMinute: 5, dailyMax: 10, diskFreeBytes: 1 };
    doc.requireInputs = true;
    (doc.rules as unknown[]).push(spendRule());
    assert.doesNotThrow(() => parsePolicyDocument(doc));
  });

  it("refuses an unknown top-level key", () => {
    const doc = base();
    doc.requireInput = true;
    assert.throws(() => parsePolicyDocument(doc), /^Error: policy-unknown-key:requireInput$/);
  });

  it("refuses an unknown rule key and names the rule", () => {
    const doc = base();
    (doc.rules as Record<string, unknown>[])[0].dailyMax = 3;
    assert.throws(() => parsePolicyDocument(doc), /^Error: policy-rule-unknown-key:r1:dailyMax$/);
  });

  it("refuses an unknown spend key", () => {
    const doc = base();
    const rule = spendRule();
    (rule.spend as Record<string, unknown>).dailyMax = 5000;
    (doc.rules as unknown[]).push(rule);
    assert.throws(() => parsePolicyDocument(doc), /^Error: policy-rule-spend-unknown-key:pay:dailyMax$/);
  });

  it("refuses an unknown limits key", () => {
    const doc = base();
    doc.limits = { ratePerMinute: 5, perMinute: 1 };
    assert.throws(() => parsePolicyDocument(doc), /^Error: policy-limits-unknown-key:perMinute$/);
  });

  it("refuses an unknown key in a JSON string too", () => {
    const text = JSON.stringify({ ...base(), approvalTTL: 5 });
    assert.throws(() => parsePolicyDocument(text), /^Error: policy-unknown-key:approvalTTL$/);
  });
});
