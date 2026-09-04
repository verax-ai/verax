import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { explain } from "../src/explain.ts";
import { RECORD_SIGNER } from "./helpers.ts";
import { runGoldenScenario } from "./golden-scenario.ts";

describe("P1-5 effect hash contract and window coverage", () => {
  it("n1 is balanced, n6 stays effect-mismatch, n4 has no window-coverage", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-hash-"));
    const ledger = await runGoldenScenario(dir);
    const n1 = await explain(ledger, "n1", { checkpointSigner: RECORD_SIGNER });
    assert.equal(n1.finding.code, null, `n1 code: ${n1.finding.code} detail=${n1.finding.detail}`);
    assert.equal(n1.finding.summary, "audit: balanced");
    assert.equal(n1.finding.label, "conditional");

    const n6 = await explain(ledger, "n6", { checkpointSigner: RECORD_SIGNER });
    assert.equal(n6.finding.code, "effect-mismatch");

    const n4 = await explain(ledger, "n4", { checkpointSigner: RECORD_SIGNER });
    assert.notEqual(n4.finding.code, "window-coverage", `n4 code: ${n4.finding.code}`);
    const n4Codes = [n4.finding.code, n4.finding.detail].join(" ");
    assert.equal(n4Codes.includes("window-coverage"), false, n4Codes);
  });
});
