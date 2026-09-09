import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "copy");

describe("panel copy keys", () => {
  it("en and tr key sets are identical", () => {
    const en = JSON.parse(readFileSync(join(dir, "en.json"), "utf8")) as Record<string, string>;
    const tr = JSON.parse(readFileSync(join(dir, "tr.json"), "utf8")) as Record<string, string>;
    assert.deepEqual(Object.keys(en).sort(), Object.keys(tr).sort());
  });

  it("no Turkish entry is still the English one", () => {
    // Matching key sets is what a copy file can check about itself, and it
    // stayed green while two rule lines and the refresh button were never
    // translated. Comparing the two files is the third thing that catches it.
    const en = JSON.parse(readFileSync(join(dir, "en.json"), "utf8")) as Record<string, string>;
    const tr = JSON.parse(readFileSync(join(dir, "tr.json"), "utf8")) as Record<string, string>;
    const untranslated = Object.keys(en).filter((k) => en[k] === tr[k]);
    assert.deepEqual(untranslated, [], `untranslated: ${untranslated.join(", ")}`);
  });
});
