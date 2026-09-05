import { strict as assert } from "node:assert";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

describe("excluded product", () => {
  it("source tree does not mention wearu", () => {
    const hits: string[] = [];
    for (const file of walk(src)) {
      if (readFileSync(file, "utf8").toLowerCase().includes("wearu")) hits.push(file);
    }
    assert.deepEqual(hits, []);
  });
});
