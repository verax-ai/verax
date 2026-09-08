import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { emptyGalaxy, parseInventory } from "@verax-ai/galaxy";
import { coverageLine, INVENTORY_STALE_MS } from "../src/galaxy/coverage-line.ts";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;
const sample = parseInventory(
  JSON.parse(
    readFileSync(join(here, "..", "..", "..", "packages", "galaxy", "tests", "fixtures", "inventory-sample.json"), "utf8"),
  ),
);
if (!sample.ok) throw new Error(sample.reason);

describe("coverageLine", () => {
  it("names unbound and writes no ratio when there is no inventory", () => {
    const line = coverageLine(null, emptyGalaxy(), 1, en);
    assert.equal(line.bound, false);
    assert.equal(line.text, "inventory not bound");
    assert.equal(/\d+\s*\/\s*\d+/.test(line.text), false);
  });

  it("counts from the inventory and the ledger intersection, and says when the snapshot is stale", () => {
    const ledger = emptyGalaxy();
    ledger.agents.push({
      id: "agent-1",
      label: "agent-1",
      planetId: null,
      lastActMs: { measured: true, value: 1, source: "ledger.timestampMs" },
    });
    const fresh = coverageLine(sample.value, ledger, sample.value.takenAtMs + 3_000, en);
    assert.equal(fresh.bound, true);
    assert.equal(fresh.stale, false);
    assert.match(fresh.text, /1 \/ 3 agents can account for themselves/);
    assert.match(fresh.text, /fixture-source/);
    assert.equal(/%/.test(fresh.text), false);

    const stale = coverageLine(sample.value, ledger, sample.value.takenAtMs + INVENTORY_STALE_MS + 1, en);
    assert.equal(stale.stale, true);
    assert.match(stale.text, /stale/);
  });
});
