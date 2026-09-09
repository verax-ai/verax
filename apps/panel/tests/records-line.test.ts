import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { recordLine } from "../src/records/line.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;

describe("record line", () => {
  it("says what was asked, what the rule said, and what happened — not a naked ref", () => {
    const action: RailAction = {
      record: {
        claims: {
          subject: "spend",
          decision: "allow",
          reasonCode: "approved-by-operator",
          timestampMs: 1,
          decider: "verax-operator",
          ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
          policyHash: "f7",
          effectHash: "ed",
        },
      },
      effect: {
        row: {
          ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
          effectClass: "spend",
          effectHash: "ed",
          timestampMs: 1,
        },
      },
      rule: { id: "spend-meta-ads", tool: "spend", text: "Payments to the Meta ads account need operator approval." },
      finding: null,
    };
    const approvals: PendingApproval[] = [
      {
        ref: "kart-test-2",
        requestHash: "rh",
        subject: "spend",
        ruleText: "Payments to the Meta ads account need operator approval.",
        inputsSummary: { count: 0, ids: [] },
        amount: 1000,
        currency: "TRY",
        payee: "meta-ads",
        expiresAtMs: 9,
        status: "approved",
        brain: "dev-brain",
        allowRef: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      },
    ];
    const line = recordLine(en, action, approvals, "en");
    // 1000 is the stored minor amount. The line must spend-read it: ten, not a thousand.
    assert.match(line.asked, /^spend .*10\.00.* → meta-ads$/);
    assert.equal(/(^|[^.\d])1000([^.\d]|$)/.test(line.asked), false, line.asked);
    assert.match(line.rule, /Meta ads/);
    assert.equal(line.outcome, "allow approved-by-operator");
    assert.equal(line.label.includes("398befdf"), false);
    assert.match(line.label, / → meta-ads/);
  });

  function defer(ref: string): RailAction {
    return {
      record: {
        claims: {
          subject: "spend",
          decision: "defer",
          reasonCode: "approval-required",
          timestampMs: 1,
          decider: "verax-proxy",
          ref,
          policyHash: "f7",
          effectHash: null,
        },
      },
      effect: null,
      rule: null,
      finding: null,
    };
  }

  function row(partial: {
    ref: string;
    status: PendingApproval["status"];
    allowRef?: string;
  }): PendingApproval {
    return {
      ref: partial.ref,
      requestHash: "rh",
      subject: "spend",
      ruleText: "need approval",
      inputsSummary: { count: 0, ids: [] },
      expiresAtMs: 9,
      status: partial.status,
      brain: "dev-brain",
      ...(partial.allowRef ? { allowRef: partial.allowRef } : {}),
    };
  }

  it("does not call a later-approved defer waiting", () => {
    const approvals = [
      row({ ref: "kart-test-2", status: "pending" }),
      row({
        ref: "kart-test-2",
        status: "approved",
        allowRef: "398befdf-78f6-4780-833b-aa7c7ee5ef5d",
      }),
    ];
    const line = recordLine(en, defer("kart-test-2"), approvals, "en");
    assert.notEqual(line.kind, "defer");
  });

  it("names an expired approval as expired, not waiting and not allowed", () => {
    const approvals = [row({ ref: "kart-test-1", status: "expired" })];
    const line = recordLine(en, defer("kart-test-1"), approvals, "en");
    assert.equal(line.kind, "expired");
    assert.notEqual(line.kind, "defer");
    assert.notEqual(line.kind, "allow");
  });

  it("keeps a defer waiting when the approval ledger has no row for it", () => {
    const line = recordLine(en, defer("kart-test-1"), [], "en");
    assert.equal(line.kind, "defer");
  });
});
