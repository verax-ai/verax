import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { ApprovalRow } from "../src/approvals.ts";
import { parseCardCsv, reconcile } from "../src/reconcile.ts";
import { tenantKey } from "../src/tenant.ts";
import type { LedgerEffect } from "../src/types.ts";

// With an issuer, tenant or org on the principal, the proxy writes a held spend's ref as
// `<tenantKey>:<raw>` (scopedClaimsRef). The payer copies that ref into the payment
// reference, so the statement carries `verax:<tenantKey>:<raw>`.
const noon = Date.UTC(2026, 8, 6, 12);

function heldSpend(deferRef: string, allowRef: string): { effect: LedgerEffect; approval: ApprovalRow } {
  return {
    effect: {
      row: { ref: allowRef, effectHash: "11".repeat(32), effectClass: "spend", timestampMs: noon },
      witnessClass: "self",
    },
    approval: {
      ref: deferRef,
      requestHash: "00".repeat(32),
      subject: "spend",
      args: { amountMinor: 125_050, currency: "TRY", payee: "true-ads", reference: `verax:${deferRef}` },
      ruleId: "spend-true",
      ruleText: "Spends need operator approval.",
      inputsSummary: { count: 0, ids: [] },
      amount: 125_050,
      payee: "true-ads",
      currency: "TRY",
      createdAtMs: noon,
      expiresAtMs: noon + 86_400_000,
      status: "approved",
      brain: "brain-1",
      allowRef,
    },
  };
}

function reconcileOne(deferRef: string) {
  const { effect, approval } = heldSpend(deferRef, "a1");
  const channel = parseCardCsv(`Tarih;Açıklama;Tutar\n06.09.2026;TRUE REKLAM verax:${deferRef};-1.250,50\n`, {
    currency: "TRY",
  });
  const report = reconcile(channel, [effect], {
    toleranceMs: 3 * 86_400_000,
    approvals: [approval],
    decisionRefs: new Set(["a1"]),
  });
  return { channel, report };
}

describe("card statement ref for a tenant-scoped held spend", () => {
  it("control: an unscoped ref reaches its allow and matches", () => {
    const { channel, report } = reconcileOne("d1");
    assert.equal(channel[0]?.ref, "d1");
    assert.equal(report.matched.length, 1);
    assert.equal(report.ghost.length, 0);
  });

  it("a scoped ref is read whole and reaches its allow", () => {
    const scoped = `${tenantKey({ iss: "https://issuer.example", brain: "brain-1" })}:d1`;
    const { channel, report } = reconcileOne(scoped);
    assert.equal(channel[0]?.ref, scoped, "the statement ref was cut short");
    assert.equal(report.matched.length, 1);
    assert.equal(report.ghost.length, 0);
  });

  it("only a 64-hex tenant key is read as a prefix", () => {
    const channel = parseCardCsv("Tarih;Açıklama;Tutar\n06.09.2026;TRUE REKLAM verax:abc:d1;-1,00\n", { currency: "TRY" });
    assert.equal(channel[0]?.ref, "abc");
  });
});
