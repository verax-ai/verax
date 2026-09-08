import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { hash01, hashPoint } from "../src/address.ts";

function dist(a: { x: number; y: number; z: number }, b: { x: number; y: number; z: number }): number {
  const dx = a.x - b.x;
  const dy = a.y - b.y;
  const dz = a.z - b.z;
  return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

describe("hashPoint address", () => {
  it("returns the same point for the same id on two runs", () => {
    const a = hashPoint("decision:ref-aa", 10);
    const b = hashPoint("decision:ref-aa", 10);
    assert.deepEqual(a, b);
    assert.equal(hash01("decision:ref-aa:u"), hash01("decision:ref-aa:u"));
  });

  it("does not cluster sequential or sibling ids in one pocket", () => {
    const radius = 10;
    const ids = [
      "decision:1",
      "decision:2",
      "decision:3",
      "tenant:alpha",
      "tenant:beta",
      "brain:claude",
      "brain:codex",
      "ref:aaaa",
      "ref:aaab",
      "ref:cccc",
    ];
    const points = ids.map((id) => hashPoint(id, radius));
    for (let i = 0; i < points.length; i += 1) {
      for (let j = i + 1; j < points.length; j += 1) {
        assert.notDeepEqual(points[i], points[j], `${ids[i]} collided with ${ids[j]}`);
      }
    }
    const pairwise: number[] = [];
    for (let i = 0; i < points.length; i += 1) {
      for (let j = i + 1; j < points.length; j += 1) {
        pairwise.push(dist(points[i]!, points[j]!));
      }
    }
    const mean = pairwise.reduce((s, d) => s + d, 0) / pairwise.length;
    const xs = points.map((p) => p.x);
    const zs = points.map((p) => p.z);
    const spanX = Math.max(...xs) - Math.min(...xs);
    const spanZ = Math.max(...zs) - Math.min(...zs);
    assert.ok(mean > radius * 0.35, `mean pairwise ${mean} looks clustered`);
    assert.ok(spanX > radius * 0.6, `x span ${spanX} is a pocket, not a sky`);
    assert.ok(spanZ > radius * 0.6, `z span ${spanZ} is a pocket, not a sky`);
  });

  it("stays inside the asked radius (flattened Y)", () => {
    const p = hashPoint("anywhere", 8);
    const r = Math.sqrt(p.x * p.x + (p.y / 0.55) * (p.y / 0.55) + p.z * p.z);
    assert.ok(r <= 8 + 1e-9, `radius ${r} > 8`);
  });
});
