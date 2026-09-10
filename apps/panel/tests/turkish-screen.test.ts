import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { englishInterfaceLeftovers } from "./turkish-screen.ts";

describe("turkish screen leftovers", () => {
  it("lets a filled Turkish status sentence through", () => {
    assert.deepEqual(
      englishInterfaceLeftovers("Defterde 8 karar var.\nDefter kilidi: tutuluyor\nTanık: self 2"),
      [],
    );
  });

  it("flags held when the lock word bypasses the copy table", () => {
    assert.deepEqual(englishInterfaceLeftovers("Defter kilidi: held"), ["held"]);
  });

  it("flags the evidence-scope labels the first pass had to excuse", () => {
    // "guarantee unconditional pin: none" was on the Turkish screen with the
    // gate green, because the gate listed those words as ledger values.
    assert.deepEqual(englishInterfaceLeftovers("guarantee unconditional pin: none"), [
      "guarantee",
      "pin",
    ]);
  });

  it("reads a cut-short value as a value, not as a word", () => {
    // shortHash prints "demo-spe…"; "spe" is half a ledger ref, not English.
    assert.deepEqual(englishInterfaceLeftovers("Kanıt: demo-spe… held"), ["held"]);
  });

  it("does not excuse a word merely because a ledger token starts with it", () => {
    // "allow" excused "all"; "approval-required" excused "app".
    assert.deepEqual(englishInterfaceLeftovers("Defter kilidi: all app"), ["all", "app"]);
  });
});
