import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  coverage,
  emptyGalaxy,
  inventoryToGalaxy,
  mergeGalaxy,
  parseInventory,
  type Inventory,
} from "../src/inventory.ts";
import { measured, unmeasured } from "../src/measured.ts";
import type { GalaxyModel } from "../src/model.ts";
import { placeScene } from "../src/place.ts";
import { galaxyTier, TIER_DUST } from "../src/quality.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sample = JSON.parse(readFileSync(join(here, "fixtures", "inventory-sample.json"), "utf8")) as unknown;

function mustParse(raw: unknown): Inventory {
  const parsed = parseInventory(raw);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

function ledgerModel(): GalaxyModel {
  return {
    core: { pulse: measured(1, "healthz.heartbeat.atMs"), label: "body" },
    planets: [
      {
        id: "tenant-1",
        label: "tenant-1",
        size: measured(2, "ledger.decisions"),
        freshness: measured(900, "ledger.timestampMs"),
      },
    ],
    stars: [{ id: "ref-1", planetId: "tenant-1", at: 900, kind: "allow" }],
    agents: [
      {
        id: "agent-1",
        label: "agent-1",
        planetId: "tenant-1",
        lastActMs: measured(900, "ledger.timestampMs"),
        witness: "self",
      },
      {
        id: "agent-ledger-only",
        label: "agent-ledger-only",
        planetId: "tenant-1",
        lastActMs: measured(800, "ledger.timestampMs"),
        witness: "same-org",
      },
    ],
    edges: [{ fromId: "agent:agent-1", toId: "ref-1", kind: "acted" }],
  };
}

function walkSources(model: GalaxyModel): string[] {
  const out: string[] = [];
  const push = (field: { measured: boolean; source?: string }) => {
    if (field.measured && field.source) out.push(field.source);
  };
  push(model.core.pulse);
  for (const p of model.planets) {
    push(p.size);
    push(p.freshness);
    if (p.ring) push(p.ring);
  }
  for (const a of model.agents) push(a.lastActMs);
  return out;
}

describe("parseInventory", () => {
  it("accepts the sample fixture and rejects a broken field without a partial model", () => {
    const ok = parseInventory(sample);
    assert.equal(ok.ok, true);
    if (ok.ok) {
      assert.equal(ok.value.source, "fixture-source");
      assert.equal(ok.value.agents.length, 3);
    }

    const missing = parseInventory({ ...mustParse(sample), agents: [{ id: "agent-1" }] });
    assert.equal(missing.ok, false);
    if (!missing.ok) assert.match(missing.reason, /invalid:agents\[0\]/);

    const badJsonShape = parseInventory({ takenAtMs: "soon", source: "x", groups: [], agents: [], orphans: [] });
    assert.equal(badJsonShape.ok, false);
    if (!badJsonShape.ok) assert.equal(badJsonShape.reason, "invalid:takenAtMs");
  });
});

describe("inventoryToGalaxy", () => {
  it("tags every measured field with the inventory source, never a ledger source", () => {
    const model = inventoryToGalaxy(mustParse(sample));
    const sources = walkSources(model);
    assert.ok(sources.includes("inventory:fixture-source.agents"));
    assert.ok(sources.includes("inventory:fixture-source.lastRun"));
    assert.equal(
      sources.some((s) => s.startsWith("ledger.") || s.startsWith("healthz.")),
      false,
      sources.join(","),
    );
    assert.equal("takenAtMs" in model, false);
  });

  it("does not attach a witness to an inventory agent", () => {
    const model = inventoryToGalaxy(mustParse(sample));
    for (const agent of model.agents) {
      assert.equal("witness" in agent, false, agent.id);
      assert.equal(agent.witness, undefined);
    }
  });

  it("treats unmonitored and unknown as unmeasured even when lastRunMs is present", () => {
    const model = inventoryToGalaxy(mustParse(sample));
    const live = model.agents.find((a) => a.id === "agent-1");
    const unmon = model.agents.find((a) => a.id === "agent-2");
    const unknown = model.agents.find((a) => a.id === "agent-3");
    assert.equal(live?.lastActMs.measured, true);
    if (live?.lastActMs.measured) {
      assert.equal(live.lastActMs.source, "inventory:fixture-source.lastRun");
      assert.equal(live.lastActMs.value, 1700000001000);
    }
    assert.equal(unmon?.lastActMs.measured, false);
    if (unmon && !unmon.lastActMs.measured) assert.equal(unmon.lastActMs.why, "unmonitored");
    assert.equal(unknown?.lastActMs.measured, false);
    if (unknown && !unknown.lastActMs.measured) assert.equal(unknown.lastActMs.why, "unknown");
  });

  it("places orphans as ghost stars and does not invent a planet for them", () => {
    const model = inventoryToGalaxy(mustParse(sample));
    assert.equal(model.planets.some((p) => p.id === "pulse-1"), false);
    const star = model.stars.find((s) => s.id === "pulse-1");
    assert.equal(star?.flag, "ghost");
    assert.equal(star?.planetId, null);
    const placed = placeScene(model);
    assert.equal(placed.stars.find((s) => s.id === "pulse-1")?.planetId, null);
    assert.equal(placed.planets.some((p) => p.id === "pulse-1"), false);
  });

  it("keeps 500 inventory agents; the quality ladder does not trim records", () => {
    const agents = Array.from({ length: 500 }, (_, i) => ({
      id: `agent-${i}`,
      label: `Agent ${i}`,
      groupId: "team-a",
      kind: "worker",
      lastRunMs: 1 + i,
      state: "live" as const,
    }));
    const inventory: Inventory = {
      takenAtMs: 1,
      source: "fixture-source",
      groups: [{ id: "team-a", label: "Team A" }],
      agents,
      orphans: [],
    };
    const model = inventoryToGalaxy(inventory);
    assert.equal(model.agents.length, 500);
    const placed = placeScene(model);
    assert.equal(placed.agents.length, 500);
    const tier = galaxyTier(2);
    assert.equal(tier.dust, TIER_DUST[2]);
    assert.notEqual(tier.dust, placed.agents.length);
    const draw = readFileSync(join(here, "..", "src", "Galaxy.tsx"), "utf8");
    assert.match(draw, /placed\.agents/);
    assert.doesNotMatch(draw, /agents\.slice\(|stars\.slice\(/);
  });
});

describe("mergeGalaxy", () => {
  it("keeps an inventory-only agent on the scene and unmeasured", () => {
    const merged = mergeGalaxy(emptyGalaxy(), inventoryToGalaxy(mustParse(sample)));
    const only = merged.agents.find((a) => a.id === "agent-2");
    assert.ok(only);
    assert.equal(only?.lastActMs.measured, false);
    assert.equal(only?.witness, undefined);
  });

  it("leaves a ledger-only agent unchanged", () => {
    const ledger = ledgerModel();
    const merged = mergeGalaxy(ledger, inventoryToGalaxy(mustParse(sample)));
    const only = merged.agents.find((a) => a.id === "agent-ledger-only");
    assert.deepEqual(only, ledger.agents[1]);
    assert.equal(only?.lastActMs.measured, true);
    if (only?.lastActMs.measured) assert.equal(only.lastActMs.source, "ledger.timestampMs");
    assert.equal(only?.witness, "same-org");
  });

  it("lets the ledger win measurements on overlap, and may take planet membership from inventory", () => {
    const ledger = ledgerModel();
    const merged = mergeGalaxy(ledger, inventoryToGalaxy(mustParse(sample)));
    const both = merged.agents.find((a) => a.id === "agent-1");
    assert.ok(both);
    assert.equal(both?.lastActMs.measured, true);
    if (both?.lastActMs.measured) {
      assert.equal(both.lastActMs.source, "ledger.timestampMs");
      assert.equal(both.lastActMs.value, 900);
    }
    assert.equal(both?.witness, "self");
    assert.equal(both?.planetId, "team-a");
    const team = merged.planets.find((p) => p.id === "team-a");
    assert.ok(team);
    const tenant = merged.planets.find((p) => p.id === "tenant-1");
    assert.ok(tenant);
    if (tenant) {
      assert.equal(tenant.size.measured, true);
      if (tenant.size.measured) assert.equal(tenant.size.source, "ledger.decisions");
    }
  });

  it("never copies an inventory source onto a field the ledger already measured", () => {
    const ledger = ledgerModel();
    const merged = mergeGalaxy(ledger, inventoryToGalaxy(mustParse(sample)));
    const overlapIds = new Set(["agent-1"]);
    for (const agent of merged.agents) {
      if (!overlapIds.has(agent.id)) continue;
      assert.equal(agent.lastActMs.measured, true);
      if (agent.lastActMs.measured) assert.equal(agent.lastActMs.source.startsWith("inventory:"), false);
    }
    const overlapPlanet = merged.planets.find((p) => p.id === "tenant-1");
    assert.ok(overlapPlanet);
    if (overlapPlanet?.size.measured) assert.equal(overlapPlanet.size.source.startsWith("inventory:"), false);
    if (overlapPlanet?.freshness.measured) {
      assert.equal(overlapPlanet.freshness.source.startsWith("inventory:"), false);
    }
  });
});

describe("coverage", () => {
  it("counts inventory agents as the total and the intersection as accountable", () => {
    const inv = inventoryToGalaxy(mustParse(sample));
    const counted = coverage(ledgerModel(), inv);
    assert.equal(counted.total, 3);
    assert.equal(counted.accountable, 1);
  });
});

describe("empty galaxy helper", () => {
  it("is unmeasured and empty", () => {
    const model = emptyGalaxy();
    assert.deepEqual(model.core.pulse, unmeasured("no heartbeat"));
    assert.equal(model.agents.length, 0);
  });
});
