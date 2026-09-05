import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { explain } from "../src/explain.ts";
import { inputsLogFor } from "../src/inputs.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { runGoldenScenario } from "./golden-scenario.ts";

function flipCoseHex(hex: string): string {
  const last = hex.slice(-1);
  const flipped = last === "0" ? "1" : "0";
  return `${hex.slice(0, -1)}${flipped}`;
}

describe("3 ancestor chain break is visible on later refs", () => {
  it("explain(n3) after n2 signature flip is receipt-chain-break at n2; n1 stays clean", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-chain-break-"));
    const golden = await runGoldenScenario(dir);
    const decisions = await golden.decisions();
    const effects = await golden.effects();
    const n2 = decisions.find((d) => d.claims.ref === "n2");
    assert.ok(n2);
    n2.coseHex = flipCoseHex(n2.coseHex);
    const ledger = new MemoryLedger();
    const srcInputs = inputsLogFor(golden);
    const dstInputs = inputsLogFor(ledger);
    for (const d of decisions) {
      await ledger.appendDecision(d);
      const ref = d.claims.ref;
      if (!ref) continue;
      const doc = await srcInputs.get(ref);
      if (doc) await dstInputs.append(ref, doc);
    }
    for (const e of effects) {
      await ledger.appendEffect(e.row, e.witnessClass, e.resultHash);
    }

    const n3 = await explain(ledger, "n3");
    assert.deepEqual(
      {
        code: n3.finding.code,
        balanced: n3.balanced,
        intact: n3.chain.intact,
        breakAt: n3.chain.breakAt,
      },
      {
        code: "receipt-chain-break",
        balanced: false,
        intact: false,
        breakAt: "n2",
      },
    );
    assert.equal(n3.finding.detail?.includes("n2"), true, n3.finding.detail ?? "");

    const n1 = await explain(ledger, "n1");
    assert.deepEqual(
      { code: n1.finding.code, balanced: n1.balanced, intact: n1.chain.intact, breakAt: n1.chain.breakAt },
      { code: null, balanced: true, intact: true, breakAt: null },
    );
  });
});
