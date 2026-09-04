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
    else if (/\.(ts|tsx|css)$/.test(name)) out.push(full);
  }
  return out;
}

describe("canvas traps", () => {
  it("does not use backdrop-filter or shadowBlur", () => {
    const hits: string[] = [];
    for (const file of walk(src)) {
      const text = readFileSync(file, "utf8");
      if (text.includes("backdrop-filter") || text.includes("shadowBlur")) {
        hits.push(file);
      }
    }
    assert.deepEqual(hits, []);
  });
});
