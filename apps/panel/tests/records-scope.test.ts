import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { evidenceScope } from "../src/records/scope.ts";
import type { RailAction } from "../src/rail/types.ts";
import type { ReconcileCardReport } from "../src/ReconcileCard.tsx";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;

const spend: RailAction = {
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
    witnessClass: "self",
  },
  rule: null,
  finding: null,
  witnessClass: "self",
};

describe("evidence scope", () => {
  it("keeps signature, witness and external as three measured lines", () => {
    const report: ReconcileCardReport = {
      scope: { channel: "card", windowStartMs: 1, windowEndMs: 2, rowCount: 1 },
      ghost: [],
      matched: [{ effect: { ref: "398befdf-78f6-4780-833b-aa7c7ee5ef5d" } }],
    };
    const lines = evidenceScope(en, {
      action: spend,
      inspected: false,
      issuerMatches: null,
      pinSource: null,
      reconcile: report,
    });
    assert.equal(lines.signature, "Signature: not measured — inspect has not been run");
    assert.equal(lines.witness, "Witness: self");
    assert.equal(lines.external, "External: matched to a statement");
    assert.equal(/partially/i.test(`${lines.signature} ${lines.witness} ${lines.external}`), false);
  });

  it("says why a line could not be read", () => {
    const lines = evidenceScope(en, {
      action: { ...spend, effect: null, witnessClass: null },
      inspected: false,
      reconcile: null,
    });
    assert.match(lines.signature, /inspect has not been run/);
    assert.match(lines.witness, /no effect row names a witness/);
    assert.match(lines.external, /statement not bound/);
  });
});
