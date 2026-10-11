import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { loadPolicy } from "@verax-ai/proxy";

/**
 * R26, outside the round's five targets, in a released area. A top-level
 * `egress` list is read only by a rule that carries `egress: true`. With no
 * such rule the list loads, enters the policy hash, and restricts nothing: an
 * operator who lists the hosts and leaves the mark off the rule has a file
 * that reads as an allow-list and a gate that sends anywhere. A mark on some
 * other rule does not change that for the unmarked one. Same class as #169
 * and R26-3: the policy is weaker than its file reads.
 */

const sender = { brain: "brain-1", scopes: new Set(["verax:act"]) };

const UNMARKED_SEND = {
  id: "message-send",
  tool: "message.send",
  requires: ["verax:act"],
  text: "Sending a message needs the act scope.",
};

function load(
  doc: unknown,
  options?: Parameters<typeof loadPolicy>[1],
): { ok: true; policy: ReturnType<typeof loadPolicy> } | { ok: false; reason: string } {
  try {
    return { ok: true, policy: loadPolicy(JSON.stringify(doc), options) };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

describe("R26 an egress list that no rule reads", () => {
  it("a host list beside an unmarked message.send rule does not load", () => {
    const got = load({ version: 1, default: "deny", egress: ["mail.example"], rules: [UNMARKED_SEND] });
    if (got.ok) {
      const decision = got.policy.evaluate(
        { name: "message.send", arguments: { to: "alice@evil.example", text: "hi" } },
        sender,
      );
      assert.notEqual(
        decision.decision,
        "allow",
        "the file lists mail.example and the gate allowed evil.example",
      );
    }
    assert.equal(got.ok, false, "a list no rule reads loaded without a word");
    if (!got.ok) assert.equal(got.reason, "policy-rule-egress-unmarked:message-send");
  });

  it("a host list with no rules at all does not load", () => {
    const got = load({ version: 1, default: "deny", egress: ["mail.example"], rules: [] });
    assert.equal(got.ok, false);
    if (!got.ok) assert.equal(got.reason, "policy-egress-unused");
  });

  it("an empty list reads as 'no host' and is refused the same way", () => {
    const got = load({ version: 1, default: "deny", egress: [], rules: [UNMARKED_SEND] });
    assert.equal(got.ok, false, "egress: [] loaded and message.send still reaches any host");
    if (!got.ok) assert.equal(got.reason, "policy-rule-egress-unmarked:message-send");
  });

  it("a host list beside rules for other tools only does not load", () => {
    const got = load({
      version: 1,
      default: "deny",
      egress: ["mail.example"],
      rules: [{ id: "get", tool: "memory.get", requires: ["verax:act"], text: "Reading memory needs the act scope." }],
    });
    assert.equal(got.ok, false);
    if (!got.ok) assert.equal(got.reason, "policy-egress-unused");
  });

  it("a mark on another rule does not cover an unmarked message.send", () => {
    const got = load({
      version: 1,
      default: "deny",
      egress: ["mail.example"],
      rules: [
        UNMARKED_SEND,
        { id: "get", tool: "memory.get", requires: ["verax:act"], text: "Reading memory needs the act scope.", egress: true },
      ],
    });
    if (got.ok) {
      const decision = got.policy.evaluate(
        { name: "message.send", arguments: { to: "alice@evil.example", text: "hi" } },
        sender,
      );
      assert.notEqual(
        decision.decision,
        "allow",
        "the file lists mail.example, one rule is marked, and message.send still reached evil.example",
      );
    }
    assert.equal(got.ok, false);
    if (!got.ok) assert.equal(got.reason, "policy-rule-egress-unmarked:message-send");
  });

  it("a list a marked rule reads still loads and still blocks", () => {
    const got = load({
      version: 1,
      default: "deny",
      egress: ["mail.example"],
      rules: [{ ...UNMARKED_SEND, egress: true }],
    });
    assert.equal(got.ok, true);
    if (!got.ok) return;
    const blocked = got.policy.evaluate(
      { name: "message.send", arguments: { to: "alice@evil.example", text: "hi" } },
      sender,
    );
    assert.equal(blocked.decision, "deny");
    assert.equal(blocked.reasonCode, "egress-blocked");
    const allowed = got.policy.evaluate(
      { name: "message.send", arguments: { to: "alice@mail.example", text: "hi" } },
      sender,
    );
    assert.equal(allowed.decision, "allow");
  });

  it("a snapshot already on disk with such a list still opens, under the hash it was written with", () => {
    const doc = { version: 1, default: "deny", egress: ["mail.example"], rules: [UNMARKED_SEND] };
    const got = load(doc, { unknownKeys: "ignore" });
    assert.equal(got.ok, true, "a state directory written by 0.4.8 would not open");
    if (!got.ok) return;
    const withoutList = load({ version: 1, default: "deny", rules: [UNMARKED_SEND] }, { unknownKeys: "ignore" });
    assert.equal(withoutList.ok, true);
    if (!withoutList.ok) return;
    assert.notEqual(got.policy.hash, withoutList.policy.hash, "the list left the hash of a stored snapshot");
  });
});

/**
 * The description the agent reads says `message.send` reaches a host only
 * when the policy lists it. A rule without the mark, in a document with no
 * list, made that false: nothing read the host. The mark is now required on
 * a rule for a tool whose host the gate reads.
 */
/**
 * Found in the pre-release review. "Some rule is marked" was enough to keep a
 * host list. The gate decides `spend` before it looks at any host, and a tool
 * with no host reader is refused whatever the list says, so a mark on either
 * reads the list no more than no mark does.
 */
describe("a mark on a rule that never reads a host", () => {
  const SPEND = {
    id: "pay",
    tool: "spend",
    requires: ["verax:act"],
    mode: "approve",
    text: "Paying a listed payee needs approval.",
    spend: { maxAmountMinor: 1000, currency: "EUR", payees: ["acme"] },
  };

  it("on the spend rule is refused: the gate does not apply it there", () => {
    const got = load({ version: 1, default: "deny", rules: [{ ...SPEND, egress: true }] });
    assert.equal(got.ok, false, "a spend rule marked egress loaded, and the mark is never read");
    if (!got.ok) assert.equal(got.reason, "policy-rule-egress-on-spend:pay");
  });

  it("on the spend rule does not keep a host list either", () => {
    const got = load({
      version: 1,
      default: "deny",
      egress: ["mail.example"],
      rules: [{ ...SPEND, egress: true }],
    });
    assert.equal(got.ok, false, "the list loaded beside a rule that never reads a host");
  });

  it("on a tool with no host reader does not keep a host list", () => {
    const got = load({
      version: 1,
      default: "deny",
      egress: ["mail.example"],
      rules: [{ id: "get", tool: "memory.get", requires: ["verax:act"], text: "Reading memory needs the act scope.", egress: true }],
    });
    assert.equal(got.ok, false, "the list loaded and no rule can read it");
    if (!got.ok) assert.equal(got.reason, "policy-egress-unused");
  });

  it("a snapshot already on disk with a marked spend rule still opens", () => {
    const got = load({ version: 1, default: "deny", rules: [{ ...SPEND, egress: true }] }, { unknownKeys: "ignore" });
    assert.equal(got.ok, true);
  });
});

describe("a message.send rule without the mark", () => {
  it("does not load, list or no list", () => {
    const got = load({ version: 1, default: "deny", rules: [UNMARKED_SEND] });
    if (got.ok) {
      const decision = got.policy.evaluate(
        { name: "message.send", arguments: { to: "alice@evil.example", text: "hi" } },
        sender,
      );
      assert.notEqual(decision.decision, "allow", "no host is listed and the gate allowed evil.example");
    }
    assert.equal(got.ok, false);
    if (!got.ok) assert.equal(got.reason, "policy-rule-egress-unmarked:message-send");
  });

  it("an approve rule is held to the same mark", () => {
    const got = load({
      version: 1,
      default: "deny",
      rules: [{ ...UNMARKED_SEND, mode: "approve" }],
    });
    assert.equal(got.ok, false, "an operator would be asked to approve a send to a host nothing checked");
    if (!got.ok) assert.equal(got.reason, "policy-rule-egress-unmarked:message-send");
  });

  it("a marked rule with no list loads and reaches no host", () => {
    const got = load({ version: 1, default: "deny", rules: [{ ...UNMARKED_SEND, egress: true }] });
    assert.equal(got.ok, true);
    if (!got.ok) return;
    const decision = got.policy.evaluate(
      { name: "message.send", arguments: { to: "alice@mail.example", text: "hi" } },
      sender,
    );
    assert.equal(decision.decision, "deny");
    assert.equal(decision.reasonCode, "egress-blocked");
  });

  it("a snapshot already on disk with an unmarked rule still opens", () => {
    const got = load({ version: 1, default: "deny", rules: [UNMARKED_SEND] }, { unknownKeys: "ignore" });
    assert.equal(got.ok, true, "a state directory written by 0.4.8 would not open");
  });
});
