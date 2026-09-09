import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { countRecords, summarySentence } from "../src/records/summary.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";
import type { ReconcileCardReport } from "../src/ReconcileCard.tsx";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;
const tr = JSON.parse(readFileSync(join(here, "..", "src", "copy", "tr.json"), "utf8")) as Record<string, string>;

function action(partial: { decision: "allow" | "deny" | "defer"; effectClass?: string; ref: string }): RailAction {
  return {
    record: {
      claims: {
        subject: "spend",
        decision: partial.decision,
        reasonCode: partial.decision,
        timestampMs: 1,
        decider: "verax-proxy",
        ref: partial.ref,
        policyHash: "aa",
        effectHash: null,
      },
    },
    effect: partial.effectClass
      ? {
          row: {
            ref: partial.ref,
            effectClass: partial.effectClass,
            effectHash: "bb",
            timestampMs: 1,
          },
        }
      : null,
    rule: null,
    finding: null,
  };
}

describe("record summary", () => {
  it("names an empty ledger instead of inventing counts in the sentence", () => {
    const counts = countRecords([], [], null);
    assert.deepEqual(counts, { decisions: 0, denied: 0, pending: 0, unmatched: null });
    assert.equal(summarySentence(en, counts), "No decision has been produced yet.");
    assert.equal(summarySentence(tr, counts), "Henüz karar üretilmedi.");
  });

  it("counts deny, last-write pending, and unmatched spend only when a statement is bound", () => {
    const actions = [
      action({ decision: "deny", ref: "d1" }),
      action({ decision: "allow", ref: "a1", effectClass: "spend" }),
      action({ decision: "allow", ref: "a2", effectClass: "spend" }),
      action({ decision: "allow", ref: "x1", effectClass: "audit.explain" }),
    ];
    const pending: PendingApproval[] = [
      {
        ref: "p1",
        requestHash: "h",
        subject: "spend",
        ruleText: "need approval",
        inputsSummary: { count: 0, ids: [] },
        expiresAtMs: 9,
        status: "pending",
        brain: "b",
      },
      {
        ref: "p1",
        requestHash: "h",
        subject: "spend",
        ruleText: "need approval",
        inputsSummary: { count: 0, ids: [] },
        expiresAtMs: 9,
        status: "approved",
        brain: "b",
        allowRef: "a1",
      },
      {
        ref: "p2",
        requestHash: "h2",
        subject: "spend",
        ruleText: "need approval",
        inputsSummary: { count: 0, ids: [] },
        expiresAtMs: 9,
        status: "pending",
        brain: "b",
      },
    ];
    const unbound = countRecords(actions, pending, null);
    assert.equal(unbound.decisions, 4);
    assert.equal(unbound.denied, 1);
    assert.equal(unbound.pending, 1);
    assert.equal(unbound.unmatched, null);
    assert.match(summarySentence(en, unbound), /statement not bound/);

    const report: ReconcileCardReport = {
      scope: { channel: "card", windowStartMs: 1, windowEndMs: 2, rowCount: 1 },
      ghost: [],
      matched: [{ effect: { ref: "a1" } }],
      authorizedUnpaid: [],
    };
    const bound = countRecords(actions, pending, report);
    assert.equal(bound.unmatched, 1);
    assert.match(summarySentence(en, bound), /1 not matched to a statement/);
  });
});
