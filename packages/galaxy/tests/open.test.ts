import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { hashPoint } from "../src/address.ts";
import {
  CLOSED_RADIUS,
  REDUCED_OPEN_MS,
  defaultOpen,
  easeOpen,
  mix3,
  openDurationMs,
  parkPoint,
  readOpenQuery,
  stepOpen,
} from "../src/open.ts";

describe("opening", () => {
  it("parks the same id on the same closed-sphere seat twice", () => {
    const a = parkPoint("rec-1");
    const b = parkPoint("rec-1");
    assert.deepEqual(a, b);
    assert.deepEqual(a, hashPoint("park:rec-1", CLOSED_RADIUS));
  });

  it("mixes from the park to the hash address", () => {
    const park = parkPoint("star-a");
    const dest = hashPoint("star-a", 48);
    assert.deepEqual(mix3(park, dest, 0), park);
    assert.deepEqual(mix3(park, dest, 1), dest);
    const mid = mix3(park, dest, 0.5);
    assert.ok(Math.abs(mid.x - (park.x + dest.x) / 2) < 1e-9);
  });

  it("reduced motion is a 300 ms plain step, not an eased flight", () => {
    assert.equal(openDurationMs(true), REDUCED_OPEN_MS);
    assert.equal(easeOpen(0.25, true), 0.25);
    assert.ok(Math.abs(easeOpen(0.25, false) - 0.25) > 0.05);
    let t = 0;
    for (let i = 0; i < 3; i += 1) t = stepOpen(t, 1, 100, true);
    assert.equal(t, 1);
    let slow = 0;
    for (let i = 0; i < 3; i += 1) slow = stepOpen(slow, 1, 100, false);
    assert.ok(slow < 1);
  });

  it("readOpenQuery accepts 1/0 for the perf harness", () => {
    assert.equal(readOpenQuery("?tab=galaxy&open=1"), 1);
    assert.equal(readOpenQuery("open=0"), 0);
    assert.equal(readOpenQuery(""), null);
  });
});

describe("what the scene shows before anyone clicks", () => {
  it("opens itself when nobody asked for it to stay closed", () => {
    assert.equal(defaultOpen(undefined, null), 1);
  });

  it("stays closed when the URL asks for closed", () => {
    assert.equal(defaultOpen(undefined, 0), 0);
  });

  it("lets the caller override the URL", () => {
    assert.equal(defaultOpen(0, 1), 0);
    assert.equal(defaultOpen(1, 0), 1);
  });
});

