import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { loadPolicy } from "@verax-ai/proxy";

/**
 * R26 (E-3). #169 refuses a key the parser does not know, so that a policy is
 * never weaker than its file reads. `spend` is a known rule key, but the
 * parser reads it only when the rule's tool is exactly `spend`. On any other
 * rule the block is neither validated nor kept: it is dropped, the hash is the
 * hash of the rule without it, and nothing is said. The misspelling #169 names
 * (`dailyMax` inside `spend`) still loads there, and a cap written on a
 * downstream payment tool is not a cap.
 */

const principal = { brain: "brain-1", scopes: new Set<string>() };

function load(doc: unknown): { ok: true; hash: string; policy: ReturnType<typeof loadPolicy> } | { ok: false; reason: string } {
  try {
    const policy = loadPolicy(JSON.stringify(doc));
    return { ok: true, hash: policy.hash, policy };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

describe("R26 a spend block on a rule whose tool is not spend", () => {
  it("the misspelt key #169 names is refused there too", () => {
    const got = load({
      version: 1,
      default: "deny",
      rules: [
        {
          id: "charge",
          tool: "stripe.charge",
          requires: [],
          mode: "approve",
          text: "Card charges need approval and stay under the daily cap.",
          spend: { maxAmountMinor: 10_000, currency: "USD", payees: ["acme"], dailyMax: 50_000 },
        },
      ],
    });
    assert.equal(
      got.ok,
      false,
      "a policy with dailyMax inside spend loaded; STATUS says policy-rule-spend-unknown-key:<id>:<key>",
    );
  });

  it("a spend block that is not even an object is refused", () => {
    const got = load({
      version: 1,
      default: "deny",
      rules: [{ id: "r1", tool: "fs.read", requires: [], text: "read files", spend: "ten dollars a day" }],
    });
    assert.equal(got.ok, false, "spend: \"ten dollars a day\" loaded without a word");
  });

  it("a cap the file reads is a cap the gate applies, or the file does not load", () => {
    const got = load({
      version: 1,
      default: "deny",
      rules: [
        {
          id: "charge",
          tool: "stripe.charge",
          requires: [],
          text: "Card charges up to 100.00 USD to acme.",
          spend: { maxAmountMinor: 10_000, currency: "USD", payees: ["acme"] },
        },
      ],
    });
    if (!got.ok) return; // refusing the file is the secure outcome
    const decision = got.policy.evaluate(
      { name: "stripe.charge", arguments: { amountMinor: 999_999_999, currency: "EUR", payee: "mallory" } },
      principal,
    );
    assert.notEqual(
      decision.decision,
      "allow",
      "999999999 EUR to mallory is allowed under a rule whose spend block reads 10000 USD to acme",
    );
  });

  it("two files that read differently do not share one policy hash", () => {
    const rule = { id: "r1", tool: "fs.read", requires: [], text: "read files" };
    const clean = load({ version: 1, default: "deny", rules: [rule] });
    const withBlock = load({
      version: 1,
      default: "deny",
      rules: [{ ...rule, spend: { maxAmountMinor: 1, currency: "USD", payees: ["acme"], descriptors: ["ACME"] } }],
    });
    assert.equal(clean.ok, true);
    if (!withBlock.ok || !clean.ok) return; // refusing the second file is the secure outcome
    assert.notEqual(withBlock.hash, clean.hash, "the signed policyHash is the same for both files");
  });
});
