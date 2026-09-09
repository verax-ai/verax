import { strict as assert } from "node:assert";
import { globSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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

/**
 * The hundred-times fault has now been found twice: on the record screen,
 * where three tests had frozen it, and on the status tab, where one had. Both
 * times a file was consistent with itself. This compares the files instead:
 * a panel source that reads an amount off a row has to read it through the
 * one function that knows the ledger stores minor units.
 */
describe("no screen prints a stored amount raw", () => {
  it("routes every amount a panel source reads through formatMinor", () => {
    const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
    const offenders: string[] = [];
    for (const file of globSync(join(src, "**", "*.{ts,tsx}"))) {
      const path = file.split(String.fromCharCode(92)).join("/");
      if (path.endsWith("records/money.ts")) continue;
      const text = readFileSync(file, "utf8");
      if (!text.includes(".amount")) continue;
      if (!text.includes("formatMinor")) offenders.push(file);
    }
    assert.deepEqual(offenders, []);
  });
});
