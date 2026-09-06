import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import type { ApprovalRow } from "../src/approvals.ts";
import { parseCardCsv, parseChannelJsonl, reconcile } from "../src/reconcile.ts";
import type { LedgerEffect } from "../src/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const goldenEffects = join(here, "fixtures", "ledger-golden", "effects.jsonl");
const sentPath = join(here, "fixtures", "channel-sent.jsonl");

function loadEffects(): LedgerEffect[] {
  return readFileSync(goldenEffects, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as LedgerEffect);
}

describe("reconcile channel export against the ledger", () => {
  it("sent fixture: 3 matched, 2 ghost, 1 unsent, 0 outOfScope; msg-far is ghost", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    assert.equal(channel.length, 5);
    const report = reconcile(channel, loadEffects());
    assert.deepEqual(report.scope, {
      channel: "sent",
      windowStartMs: 20,
      windowEndMs: 180100,
      rowCount: 5,
    });
    assert.equal(report.matched.length, 3);
    assert.deepEqual(
      report.matched.map((m) => m.effect.ref),
      ["n1", "n2", "n3"],
    );
    assert.equal(report.ghost.length, 2);
    assert.deepEqual(
      report.ghost.map((g) => g.externalId).sort(),
      ["msg-far", "msg-ghost"],
    );
    assert.equal(
      report.ghost.find((g) => g.externalId === "msg-far")?.nearestEffectDtMs !== undefined,
      true,
    );
    assert.equal(report.unsent.length, 1);
    assert.equal(report.unsent[0]?.ref, "n6");
    assert.equal(report.outOfScope.length, 0);
  });

  it("a class match outside toleranceMs is ghost when no explicit window", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    const tight = reconcile(channel, loadEffects(), { toleranceMs: 1 });
    assert.equal(tight.outOfScope.length, 0);
    assert.ok(tight.ghost.some((r) => r.externalId === "msg-far"));
    const loose = reconcile(channel, loadEffects(), { toleranceMs: 200_000 });
    assert.equal(
      loose.ghost.some((r) => r.externalId === "msg-far"),
      false,
    );
    assert.ok(loose.matched.some((m) => m.effect.ref === "n6"));
  });

  it("an explicit window puts rows outside it in outOfScope", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    const report = reconcile(channel, loadEffects(), { window: { startMs: 20, endMs: 60 } });
    assert.deepEqual(report.scope, {
      channel: "sent",
      windowStartMs: 20,
      windowEndMs: 60,
      rowCount: 5,
    });
    assert.equal(report.outOfScope.length, 1);
    assert.equal(report.outOfScope[0]?.externalId, "msg-far");
    assert.ok(report.ghost.some((r) => r.externalId === "msg-ghost"));
    assert.equal(
      report.ghost.some((r) => r.externalId === "msg-far"),
      false,
    );
  });
});

describe("card:", () => {
  const noon = Date.UTC(2026, 8, 6, 12);
  const csvPath = join(here, "fixtures", "card-statement.csv");

  it("parseCardCsv reads a Turkish bank row and treats refunds as credits", () => {
    const rows = parseCardCsv(readFileSync(csvPath, "utf8"), { currency: "TRY" });
    assert.equal(rows.length, 4);
    assert.equal(rows[0]!.channel, "card");
    assert.equal(rows[0]!.subject, "spend");
    assert.equal(rows[0]!.ref, "d1");
    assert.equal(rows[0]!.amountMinor, 125_050);
    assert.equal(rows[0]!.currency, "TRY");
    assert.equal(rows[0]!.occurredAtMs, noon);
    const dotted = parseCardCsv("Date,Desc,Amt\n2026-09-06,TRUE verax:x,-1250.50\n", {
      currency: "TRY",
      columns: { date: "Date", amount: "Amt", description: "Desc" },
      delimiter: ",",
      decimal: ".",
      dateFormat: "YYYY-MM-DD",
    });
    assert.equal(dotted[0]!.amountMinor, 125_050);
    const refund = parseCardCsv("Tarih;Açıklama;Tutar\n06.09.2026;IADE;100,00\n", { currency: "TRY" });
    assert.equal(refund[0]!.credit, true);
    assert.equal(refund[0]!.amountMinor, 10_000);
  });

  it("fixture statement: 3 matched, 1 ghost, 1 authorizedUnpaid", () => {
    const channel = parseCardCsv(readFileSync(csvPath, "utf8"), { currency: "TRY" });
    const spend = (ref: string, allowRef: string, amountMinor: number): { effect: LedgerEffect; approval: ApprovalRow } => ({
      effect: {
        row: {
          ref: allowRef,
          effectHash: "11".repeat(32),
          effectClass: "spend",
          timestampMs: noon,
        },
        witnessClass: "self",
      },
      approval: {
        ref,
        requestHash: "00".repeat(32),
        subject: "spend",
        args: { amountMinor, currency: "TRY", payee: "true-ads", reference: `verax:${ref}` },
        ruleId: "spend-true",
        ruleText: "Spends need operator approval.",
        inputsSummary: { count: 0, ids: [] },
        amount: amountMinor,
        payee: "true-ads",
        currency: "TRY",
        createdAtMs: noon,
        expiresAtMs: noon + 86_400_000,
        status: "approved",
        brain: "brain-1",
        allowRef,
      },
    });
    const d1 = spend("d1", "a1", 125_050);
    const d2 = spend("d2", "a2", 10_000);
    const d3 = spend("d3", "a3", 5_000);
    const unpaid = spend("d4", "a4", 9_000);
    const report = reconcile(channel, [d1.effect, d2.effect, d3.effect, unpaid.effect], {
      toleranceMs: 3 * 86_400_000,
      approvals: [d1.approval, d2.approval, d3.approval, unpaid.approval],
    });
    assert.equal(report.matched.length, 3);
    assert.equal(report.ghost.length, 1);
    assert.equal(report.authorizedUnpaid.length, 1);
    assert.equal(report.authorizedUnpaid[0]?.ref, "a4");
    const refundRows = parseCardCsv("Tarih;Açıklama;Tutar\n06.09.2026;IADE;100,00\n", { currency: "TRY" });
    const refunded = reconcile(refundRows, [], { toleranceMs: 3 * 86_400_000 });
    assert.equal(refunded.outOfScope.length, 1);
  });

  it("D4: a verax ref with the wrong amount is ghost, not matched", () => {
    const noon = Date.UTC(2026, 8, 6, 12);
    const channel = parseCardCsv("Tarih;Açıklama;Tutar\n06.09.2026;TRUE REKLAM verax:d1;-2.000,00\n", {
      currency: "TRY",
    });
    const approval: ApprovalRow = {
      ref: "d1",
      requestHash: "00".repeat(32),
      subject: "spend",
      args: { amountMinor: 125_050, currency: "TRY", payee: "true-ads", reference: "verax:d1" },
      ruleId: "spend-true",
      ruleText: "t",
      inputsSummary: { count: 0, ids: [] },
      amount: 125_050,
      createdAtMs: noon,
      expiresAtMs: noon + 86_400_000,
      status: "approved",
      brain: "brain-1",
      allowRef: "g1",
    };
    const effect: LedgerEffect = {
      row: { ref: "g1", effectHash: "11".repeat(32), effectClass: "spend", timestampMs: noon },
      witnessClass: "self",
    };
    const report = reconcile(channel, [effect], { toleranceMs: 3 * 86_400_000, approvals: [approval] });
    assert.equal(report.matched.some((m) => m.channel.ref === "d1"), false);
    assert.equal(report.ghost.length, 1);
    assert.equal(report.ghost[0]!.reason, "amount-mismatch");
    assert.ok(report.ghost[0]!.nearestEffectDtMs !== undefined);
    assert.equal(report.authorizedUnpaid.length, 1);
    assert.equal(report.authorizedUnpaid[0]!.ref, "g1");
  });

  it("D1q: a quoted cell with the delimiter parses; a bad row is skipped", () => {
    const quoted = parseCardCsv('Tarih;Açıklama;Tutar\n06.09.2026;"TRUE; REKLAM verax:d3";-50,00\n', {
      currency: "TRY",
    });
    assert.equal(quoted.length, 1);
    assert.equal(quoted[0]!.ref, "d3");
    assert.equal(quoted[0]!.amountMinor, 5_000);
    const mixed = parseCardCsv(
      "Tarih;Açıklama;Tutar\nnot-a-date;x;-1,00\n06.09.2026;TRUE verax:d1;-1,00\n",
      { currency: "TRY" },
    );
    assert.equal(mixed.length, 1);
    assert.equal(mixed[0]!.ref, "d1");
    assert.equal(mixed.skipped.length, 1);
    assert.equal(mixed.skipped[0]!.line, 2);
  });
});
