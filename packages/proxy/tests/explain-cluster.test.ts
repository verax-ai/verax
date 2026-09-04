import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { explain } from "../src/explain.ts";
import { runGoldenScenario } from "./golden-scenario.ts";

/** Signer-less explain on the six golden refs. The watcher measures the set. */
export const GOLDEN_EXPLAIN_TABLE = [
  { ref: "n1", code: null, summary: "audit: balanced", notApplicable: ["window-coverage"], balanced: true },
  { ref: "n2", code: null, summary: "audit: balanced", notApplicable: ["window-coverage"], balanced: true },
  { ref: "n3", code: null, summary: "audit: balanced", notApplicable: ["window-coverage"], balanced: true },
  { ref: "n4", code: null, summary: "audit: balanced", notApplicable: ["window-coverage"], balanced: true },
  { ref: "n5", code: null, summary: "audit: balanced", notApplicable: ["window-coverage"], balanced: true },
  {
    ref: "n6",
    code: "effect-mismatch",
    summary: "audit: 1 finding(s) → FAIL",
    notApplicable: ["window-coverage"],
    balanced: false,
  },
] as const;

describe("A+B explain cluster (golden ledger, no signer)", () => {
  it("six refs match the expected code/summary/notApplicable/balanced table", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-explain-cluster-"));
    const ledger = await runGoldenScenario(dir);
    const got = [];
    for (const row of GOLDEN_EXPLAIN_TABLE) {
      const result = await explain(ledger, row.ref);
      got.push({
        ref: row.ref,
        code: result.finding.code,
        summary: result.finding.summary,
        notApplicable: result.finding.notApplicable,
        balanced: result.balanced,
      });
    }
    assert.deepEqual(got, GOLDEN_EXPLAIN_TABLE);
  });
});
