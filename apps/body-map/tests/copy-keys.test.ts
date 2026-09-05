import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "copy");

describe("copy keys", () => {
  it("en and tr key sets are identical", () => {
    const en = JSON.parse(readFileSync(join(dir, "en.json"), "utf8")) as Record<string, string>;
    const tr = JSON.parse(readFileSync(join(dir, "tr.json"), "utf8")) as Record<string, string>;
    assert.deepEqual(Object.keys(en).sort(), Object.keys(tr).sort());
  });
});
