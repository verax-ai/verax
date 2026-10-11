import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { loadPolicy } from "@verax-ai/proxy";

import { persistPolicySnapshot } from "../packages/body/src/policy-store.ts";
import { runReconcile } from "../packages/body/src/reconcile-cli.ts";

/**
 * R26 (E-4). `verax reconcile --channel card` takes the statement descriptors
 * for each payee from the newest snapshot under `<state>/policies/`. It checks
 * that the snapshot hashes to its file name, then reads `spend.payees` and
 * `spend.descriptors` from the RAW document, for every rule. The hash only
 * covers a `spend` block on the rule whose tool is `spend` (R26 (E-3)): a block
 * on any other rule is outside the hash and still read here, and a later rule
 * overrides an earlier one for the same payee. So one policy hash stands for
 * two snapshots that reconcile the same statement differently, and the body
 * writes the second one itself, from a policy file the strict loader accepts.
 */

const spendRule = {
  id: "spend-true",
  tool: "spend",
  requires: ["verax:pay"],
  mode: "approve",
  text: "Spends need operator approval.",
  spend: { maxAmountMinor: 200_000, currency: "TRY", payees: ["ads-platform"], descriptors: ["REAL.STAMP"] },
};
const readRule = { id: "read", tool: "fs.read", requires: [], text: "read files" };

const cleanText = JSON.stringify({ version: 1, default: "deny", rules: [spendRule, readRule] });
const shadowText = JSON.stringify({
  version: 1,
  default: "deny",
  rules: [spendRule, { ...readRule, spend: { payees: ["ads-platform"], descriptors: ["EVIL.STAMP"] } }],
});

/** The state `createBodyServices` leaves for a policy file: wiring.ts lines 92-95. */
function stateFor(policyText: string): { dir: string; hash: string } | null {
  let hash: string;
  try {
    hash = loadPolicy(policyText).hash;
  } catch {
    return null; // the strict loader refused the file: nothing to reconcile against
  }
  const dir = mkdtempSync(join(tmpdir(), "verax-r26-spend-4-"));
  persistPolicySnapshot(dir, hash, JSON.parse(policyText) as unknown);
  writeFileSync(
    join(dir, "effects.jsonl"),
    `${JSON.stringify({
      row: { ref: "a1", effectHash: "11".repeat(32), effectClass: "spend", timestampMs: Date.UTC(2026, 8, 6, 12) },
      witnessClass: "self",
    })}\n`,
    "utf8",
  );
  writeFileSync(join(dir, "decisions.jsonl"), `${JSON.stringify({ claims: { ref: "a1" } })}\n`, "utf8");
  writeFileSync(
    join(dir, "approvals.jsonl"),
    `${JSON.stringify({
      ref: "d1",
      requestHash: "00".repeat(32),
      subject: "spend",
      args: { amountMinor: 1_000, currency: "TRY", payee: "ads-platform", reference: "verax:d1" },
      ruleId: "spend-true",
      ruleText: "Spends need operator approval.",
      inputsSummary: { count: 0, ids: [] },
      amount: 1_000,
      payee: "ads-platform",
      currency: "TRY",
      createdAtMs: Date.UTC(2026, 8, 6, 11),
      expiresAtMs: Date.UTC(2026, 8, 7, 11),
      status: "approved",
      brain: "brain-1",
      allowRef: "a1",
    })}\n`,
    "utf8",
  );
  return { dir, hash };
}

type Report = { scope: { policyHash?: string }; matched: unknown[]; ghost: { reason?: string }[] };

/** One card line stamped by a merchant the hashed policy does not name. */
function reconcileEvilLine(dir: string): Report {
  const csv = join(dir, "card.csv");
  writeFileSync(csv, "Tarih;Açıklama;Tutar\n06.09.2026;EVIL.STAMP ADS;-10,00\n", "utf8");
  const out = join(dir, "report.json");
  const err: string[] = [];
  const code = runReconcile(["reconcile", dir, csv, "--channel", "card", "--currency", "TRY", "--out", out], (s) => err.push(s));
  assert.equal(code, 0, err.join(""));
  return JSON.parse(readFileSync(out, "utf8")) as Report;
}

describe("R26 reconcile reads descriptors the policy hash does not cover", () => {
  it("control: under the clean snapshot the foreign stamp is a descriptor mismatch", () => {
    const state = stateFor(cleanText);
    assert.ok(state);
    try {
      const report = reconcileEvilLine(state.dir);
      assert.equal(report.scope.policyHash, state.hash);
      assert.equal(report.matched.length, 0);
      assert.equal(report.ghost.some((g) => g.reason === "descriptor-mismatch"), true);
    } finally {
      rmSync(state.dir, { recursive: true, force: true });
    }
  });

  it("the same policy hash does not match that stamp because of a block the hash ignores", () => {
    const clean = stateFor(cleanText);
    assert.ok(clean);
    rmSync(clean.dir, { recursive: true, force: true });
    const state = stateFor(shadowText);
    if (state === null) return; // refusing the file is the secure outcome
    try {
      const report = reconcileEvilLine(state.dir);
      assert.equal(
        report.matched.length,
        0,
        `EVIL.STAMP was matched to the approved ads-platform spend under policy hash ${String(report.scope.policyHash).slice(0, 12)}, the hash of the policy that names only REAL.STAMP (same hash as the clean file: ${state.hash === clean.hash})`,
      );
    } finally {
      rmSync(state.dir, { recursive: true, force: true });
    }
  });
});
