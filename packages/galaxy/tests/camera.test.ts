import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  cameraPosition,
  clampZoom,
  createOrbit,
  stepOrbit,
  zoomOrbit,
  ZOOM_MAX,
  ZOOM_MIN,
} from "../src/camera.ts";
import { labelVisible } from "../src/labels.ts";
import { BLOOM_FULL, galaxyTier, readForcedTier, TIER_DUST } from "../src/quality.ts";

describe("orbit camera", () => {
  it("clamps zoom to 45–700", () => {
    assert.equal(ZOOM_MIN, 45);
    assert.equal(ZOOM_MAX, 700);
    assert.equal(clampZoom(10), 45);
    assert.equal(clampZoom(900), 700);
    const o = createOrbit(120);
    zoomOrbit(o, 10_000);
    assert.equal(o.targetDistance, 700);
    zoomOrbit(o, -10_000);
    assert.equal(o.targetDistance, 45);
  });

  it("reduced motion freezes inertia and still looks at the core", () => {
    const o = createOrbit(120);
    o.velYaw = 0.4;
    o.targetYaw = 1.2;
    stepOrbit(o, true, 1000);
    assert.equal(o.velYaw, 0);
    assert.equal(o.yaw, o.targetYaw);
    const p = cameraPosition(o);
    assert.equal(p.lookX, 0);
    assert.equal(p.lookY, 0);
    assert.equal(p.lookZ, 0);
    assert.ok(Math.hypot(p.x, p.y, p.z) > 40);
  });
});

describe("quality ladder", () => {
  it("drops dust and bloom, never the record count", () => {
    assert.deepEqual([...TIER_DUST], [20_000, 10_000, 5_000]);
    assert.deepEqual(galaxyTier(0).bloom, BLOOM_FULL);
    assert.ok(galaxyTier(2).bloom.strength < galaxyTier(0).bloom.strength);
    assert.equal(galaxyTier(2).dust, 5_000);
  });

  it("snaps an unknown harness tier to the nearest dust count", () => {
    assert.equal(readForcedTier("?tier=20000"), 0);
    assert.equal(readForcedTier("?tier=10000"), 1);
    assert.equal(readForcedTier("?tier=5000"), 2);
    assert.equal(readForcedTier("?tier=15000"), 1);
    assert.equal(readForcedTier(""), null);
  });
});

describe("label LOD", () => {
  it("keeps planet names at galaxy distance and hides star names", () => {
    assert.equal(labelVisible("planet", 200, 48), true);
    assert.equal(labelVisible("star", 200, 48), false);
    assert.equal(labelVisible("star", 80, 48), true);
    assert.equal(labelVisible("planet", 0, 48), false);
  });
});
