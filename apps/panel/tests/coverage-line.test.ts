import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parseInventory } from "@verax-ai/inventory";
import { coverageLine, INVENTORY_STALE_MS } from "../src/rail/coverage.ts";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;
const sample = parseInventory(
  JSON.parse(
    readFileSync(join(here, "..", "..", "..", "packages", "inventory", "tests", "fixtures", "inventory-sample.json"), "utf8"),
  ),
);
if (!sample.ok) throw new Error(sample.reason);

describe("coverageLine", () => {
  it("names unbound and writes no ratio when there is no inventory", () => {
    const line = coverageLine(null, [], 1, en);
    assert.equal(line.bound, false);
    assert.equal(line.text, "inventory not bound");
    assert.equal(/\d+\s*\/\s*\d+/.test(line.text), false);
  });

  it("counts the roster agents the ledger names, and says when the snapshot is stale", () => {
    const fresh = coverageLine(sample.value, ["agent-1", "someone-the-roster-does-not-name"], sample.value.takenAtMs + 3_000, en);
    assert.equal(fresh.bound, true);
    assert.equal(fresh.stale, false);
    assert.match(fresh.text, /1 \/ 3 agents can account for themselves/);
    assert.match(fresh.text, /fixture-source/);
    assert.equal(/%/.test(fresh.text), false);

    const stale = coverageLine(sample.value, ["agent-1"], sample.value.takenAtMs + INVENTORY_STALE_MS + 1, en);
    assert.equal(stale.stale, true);
    assert.match(stale.text, /stale/);
  });

  it("counts an agent once, however many decisions name it", () => {
    const line = coverageLine(sample.value, ["agent-1", "agent-1", "agent-2"], sample.value.takenAtMs + 3_000, en);
    assert.match(line.text, /2 \/ 3 agents/);
  });

  it("does not claim the inventory is unbound while the sample scenario is on screen", () => {
    // The panel does not read the inventory in demo mode. Saying "not bound"
    // there is a claim about the body, and it can be false: the body may be
    // serving a full roster while the sample scenario is displayed.
    const line = coverageLine(null, [], Date.now(), en, true);
    assert.equal(line.bound, false);
    assert.notEqual(line.text, en["inventory.unbound"]);
    assert.equal(line.text, en["inventory.sample"]);
  });
});
