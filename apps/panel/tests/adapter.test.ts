import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { UNMEASURED_RGB, placeScene } from "@verax-ai/galaxy";
import { ledgerToGalaxy, tenantGroup } from "../src/galaxy/adapter.ts";
import type { RailAction } from "../src/rail/types.ts";

function action(partial: {
  ref: string;
  decision?: "allow" | "deny" | "defer";
  reason?: string;
  brain?: string | null;
  iss?: string;
  at?: number;
  witness?: string;
}): RailAction {
  const principal =
    partial.brain === null
      ? undefined
      : {
          brain: partial.brain ?? "brain-1",
          scopes: ["verax:read"],
          iss: partial.iss,
        };
  return {
    record: {
      claims: {
        subject: "memory.get",
        decision: partial.decision ?? "allow",
        reasonCode: partial.reason ?? "ok",
        timestampMs: partial.at ?? 100,
        decider: "proxy",
        ref: partial.ref,
        policyHash: "aa".repeat(32),
        effectHash: null,
      },
    },
    effect: partial.witness
      ? {
          row: { ref: partial.ref, effectClass: "memory.get", effectHash: "bb".repeat(32), timestampMs: partial.at ?? 100 },
          witnessClass: partial.witness,
        }
      : null,
    rule: null,
    finding: null,
    inputs: principal ? { principal, inputs: [] } : undefined,
    witnessClass: partial.witness,
  };
}

describe("ledgerToGalaxy", () => {
  it("groups planets by iss+sub and does not invent a planet for nameless rows", () => {
    const model = ledgerToGalaxy(
      [
        action({ ref: "a1", iss: "https://a.example", brain: "alice", at: 10 }),
        action({ ref: "a2", iss: "https://a.example", brain: "alice", at: 20 }),
        action({ ref: "b1", iss: "https://b.example", brain: "bob", at: 15 }),
        action({ ref: "orphan", brain: null, at: 5 }),
      ],
      { heartbeat: { atMs: 99 } },
    );
    assert.equal(model.planets.length, 2);
    assert.equal(tenantGroup({ iss: "https://a.example", brain: "alice" }), model.planets[0]?.id || model.planets.find((p) => p.label.includes("alice"))?.id);
    const orphan = model.stars.find((s) => s.id === "orphan");
    assert.equal(orphan?.planetId, null);
    const placed = placeScene(model);
    assert.equal(placed.planets.length, 2);
    assert.equal(placed.stars.find((s) => s.id === "orphan")?.planetId, null);
  });

  it("core pulse is unmeasured when healthz has no heartbeat and no lastDecisionMs", () => {
    const model = ledgerToGalaxy([], null);
    assert.equal(model.core.pulse.measured, false);
    if (!model.core.pulse.measured) assert.equal(model.core.pulse.why, "no heartbeat");
    assert.deepEqual(placeScene(model).core.color, UNMEASURED_RGB);
  });

  it("prefers heartbeat.atMs over lastDecisionMs", () => {
    const model = ledgerToGalaxy([], { heartbeat: { atMs: 1 }, lastDecisionMs: 2 });
    assert.equal(model.core.pulse.measured, true);
    if (model.core.pulse.measured) assert.equal(model.core.pulse.source, "healthz.heartbeat.atMs");
  });

  it("marks deny, ghost and reauth flags from the ledger and reconcile report", () => {
    const model = ledgerToGalaxy(
      [
        action({ ref: "d1", decision: "deny", reason: "tenant-mismatch" }),
        action({ ref: "g1" }),
        action({ ref: "r1", reason: "spend-reauth-required" }),
      ],
      { lastDecisionMs: 1 },
      { scope: { channel: "card", windowStartMs: 0, windowEndMs: 1, rowCount: 1 }, ghost: ["g1"] },
    );
    assert.equal(model.stars.find((s) => s.id === "d1")?.flag, "deny");
    assert.equal(model.stars.find((s) => s.id === "g1")?.flag, "ghost");
    assert.equal(model.stars.find((s) => s.id === "r1")?.flag, "reauth");
  });

  it("copies same-org witness onto the agent, and stays ringless without it", () => {
    const withW = ledgerToGalaxy([action({ ref: "n1", brain: "w", witness: "same-org" })], { lastDecisionMs: 1 });
    const bare = ledgerToGalaxy([action({ ref: "n2", brain: "x" })], { lastDecisionMs: 1 });
    assert.equal(withW.agents[0]?.witness, "same-org");
    assert.equal(bare.agents[0]?.witness, undefined);
  });
});
