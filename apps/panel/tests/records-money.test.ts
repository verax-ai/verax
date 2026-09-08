import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { formatMinor } from "../src/records/money.ts";

describe("money read from the ledger", () => {
  it("reads a minor amount as the amount that was spent", () => {
    const ten = formatMinor(1000, "TRY", "en");
    assert.ok(ten !== null);
    assert.match(ten, /10\.00/);
    // The defect this guard exists for: the stored number printed as the amount.
    assert.equal(/(^|[^.\d])1000([^.\d]|$)/.test(ten), false, ten);
    const fiveHundred = formatMinor(50000, "TRY", "en");
    assert.ok(fiveHundred !== null);
    assert.match(fiveHundred, /500\.00/);
  });

  it("does not shift a currency that has no minor unit", () => {
    const yen = formatMinor(1000, "JPY", "en");
    assert.ok(yen !== null);
    assert.match(yen, /1,000/);
  });

  it("says nothing rather than something wrong", () => {
    assert.equal(formatMinor(undefined, "TRY", "en"), null);
    assert.equal(formatMinor(1000, undefined, "en"), null);
    assert.equal(formatMinor(1000, "", "en"), null);
    assert.equal(formatMinor(Number.NaN, "TRY", "en"), null);
    assert.equal(formatMinor("1000", "TRY", "en"), null);
    assert.equal(formatMinor(1000, "not-a-currency", "en"), null);
  });
});
