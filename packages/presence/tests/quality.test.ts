import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { createQuality } from "../src/quality.ts";

function feed(q: { push(ms: number): void }, clock: { t: number }, frameMs: number, windowMs: number): void {
  const start = clock.t;
  while (clock.t - start < windowMs) {
    clock.t += frameMs;
    q.push(frameMs);
  }
}

describe("adaptive quality", () => {
  it("stays at 60k when every frame is 8 ms", () => {
    const clock = { t: 0 };
    const q = createQuality(() => clock.t);
    for (let i = 0; i < 12; i += 1) feed(q, clock, 8, 2000);
    assert.equal(q.count, 60_000);
  });

  it("steps to the floor when every frame is 30 ms", () => {
    const clock = { t: 0 };
    const q = createQuality(() => clock.t);
    feed(q, clock, 30, 2000);
    feed(q, clock, 30, 2000);
    assert.equal(q.count, 30_000);
    feed(q, clock, 30, 2000);
    feed(q, clock, 30, 2000);
    assert.equal(q.count, 15_000);
    feed(q, clock, 30, 2000);
    feed(q, clock, 30, 2000);
    assert.equal(q.count, 15_000);
  });

  it("does not step down for a single 40 ms spike among 8 ms frames", () => {
    const clock = { t: 0 };
    const q = createQuality(() => clock.t);
    for (let i = 0; i < 200; i += 1) {
      q.push(8);
      clock.t += 8;
    }
    q.push(40);
    clock.t += 40;
    while (clock.t < 2000) {
      q.push(8);
      clock.t += 8;
    }
    q.push(8);
    clock.t += 8;
    for (let i = 0; i < 10; i += 1) feed(q, clock, 8, 2000);
    assert.equal(q.count, 60_000);
  });
});
