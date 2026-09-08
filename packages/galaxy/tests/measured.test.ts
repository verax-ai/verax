import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  agentAppearance,
  coreAppearance,
  planetAppearance,
  planetRingAppearance,
  UNMEASURED_BRIGHTNESS,
  UNMEASURED_RGB,
} from "../src/draw.ts";
import { isMeasured, measured, unmeasured } from "../src/measured.ts";

describe("Measured visual language", () => {
  it("isMeasured follows the tag, not a default number", () => {
    assert.equal(isMeasured(measured(3, "healthz.heartbeat.atMs")), true);
    assert.equal(isMeasured(unmeasured("no heartbeat")), false);
  });

  it("unmeasured pulse / size / freshness / ring all draw the same purple mark", () => {
    const core = coreAppearance({ pulse: unmeasured("no heartbeat"), label: "body" });
    const planet = planetAppearance({
      id: "t",
      label: "t",
      size: unmeasured("no tenant count"),
      freshness: measured(1, "now"),
    });
    const ring = planetRingAppearance(unmeasured("no ring"));
    assert.equal(core.unmeasured, true);
    assert.equal(planet.unmeasured, true);
    assert.equal(ring.unmeasured, true);
    assert.deepEqual(core.color, UNMEASURED_RGB);
    assert.deepEqual(planet.color, UNMEASURED_RGB);
    assert.deepEqual(ring.color, UNMEASURED_RGB);
    assert.equal(core.brightness, UNMEASURED_BRIGHTNESS);
    assert.equal(planet.brightness, UNMEASURED_BRIGHTNESS);
  });

  it("a measured size does not rescue an unmeasured freshness", () => {
    const a = planetAppearance({
      id: "t",
      label: "t",
      size: measured(40, "ledger.decisions"),
      freshness: unmeasured("no freshness"),
    });
    assert.equal(a.unmeasured, true);
    assert.deepEqual(a.color, UNMEASURED_RGB);
  });

  it("measured fields do not collapse to the unmeasured mark", () => {
    const a = planetAppearance({
      id: "t",
      label: "t",
      size: measured(16, "ledger.decisions"),
      freshness: measured(0.8, "lastDecisionMs"),
    });
    assert.equal(a.unmeasured, false);
    assert.notDeepEqual(a.color, UNMEASURED_RGB);
    assert.ok(a.size > 1);
  });

  it("an unmeasured agent last-act is grey, not recent", () => {
    const a = agentAppearance({ id: "b", label: "b", lastActMs: unmeasured("no brain clock") });
    assert.equal(a.unmeasured, true);
    assert.ok(a.color.r < 0.5);
  });
});
