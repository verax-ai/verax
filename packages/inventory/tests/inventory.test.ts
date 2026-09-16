import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parseInventory, type Inventory } from "../src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sample = JSON.parse(readFileSync(join(here, "fixtures", "inventory-sample.json"), "utf8")) as unknown;

function mustParse(raw: unknown): Inventory {
  const parsed = parseInventory(raw);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

function agent(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: "a", label: "A", groupId: null, kind: "cron", lastRunMs: null, state: "live", ...over };
}

describe("parseInventory", () => {
  it("accepts the sample fixture and rejects a broken field without a partial model", () => {
    const ok = parseInventory(sample);
    assert.equal(ok.ok, true);
    if (ok.ok) {
      assert.equal(ok.value.source, "fixture-source");
      assert.equal(ok.value.agents.length, 3);
      assert.equal(ok.value.orphans[0]?.id, "pulse-1");
    }

    const missing = parseInventory({ ...mustParse(sample), agents: [{ id: "agent-1" }] });
    assert.equal(missing.ok, false);
    if (!missing.ok) assert.match(missing.reason, /invalid:agents\[0\]/);

    const badJsonShape = parseInventory({ takenAtMs: "soon", source: "x", groups: [], agents: [], orphans: [] });
    assert.equal(badJsonShape.ok, false);
    if (!badJsonShape.ok) assert.equal(badJsonShape.reason, "invalid:takenAtMs");
  });

  it("keeps a null lastRunMs as not known, and refuses a state off the list", () => {
    const ok = parseInventory({ takenAtMs: 1, source: "x", groups: [], agents: [agent()], orphans: [] });
    assert.equal(ok.ok, true);
    if (ok.ok) assert.equal(ok.value.agents[0]?.lastRunMs, null);

    const off = parseInventory({ takenAtMs: 1, source: "x", groups: [], agents: [agent({ state: "sleeping" })], orphans: [] });
    assert.equal(off.ok, false);
    if (!off.ok) assert.equal(off.reason, "invalid:agents[0].state");
  });

  it("refuses two agents or two groups under one id", () => {
    const agents = parseInventory({
      takenAtMs: 1,
      source: "x",
      groups: [],
      agents: [agent(), agent({ label: "B" })],
      orphans: [],
    });
    assert.equal(agents.ok, false);
    if (!agents.ok) assert.equal(agents.reason, "invalid:agents[1].id");

    const groups = parseInventory({
      takenAtMs: 1,
      source: "x",
      groups: [{ id: "g", label: "G" }, { id: "g", label: "H" }],
      agents: [],
      orphans: [],
    });
    assert.equal(groups.ok, false);
    if (!groups.ok) assert.equal(groups.reason, "invalid:groups[1].id");
  });
});
