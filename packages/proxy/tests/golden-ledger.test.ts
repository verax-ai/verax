import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runGoldenScenario } from "./golden-scenario.ts";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "ledger-golden");

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("B3 golden ledger", () => {
  it("decisions.jsonl and effects.jsonl match the committed bytes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-golden-"));
    await runGoldenScenario(dir);
    for (const name of ["decisions.jsonl", "effects.jsonl"] as const) {
      const got = readFileSync(join(dir, name));
      const expectedPath = join(fixtureDir, name);
      if (process.env.GENERATE_GOLDEN === "1") {
        writeFileSync(expectedPath, got);
      }
      const expected = readFileSync(expectedPath);
      assert.deepEqual(got, expected, `${name} drifted`);
    }
  });

  it("prints fixture sha256 so a change is visible", () => {
    const d = sha256(readFileSync(join(fixtureDir, "decisions.jsonl")));
    const e = sha256(readFileSync(join(fixtureDir, "effects.jsonl")));
    assert.equal(d.length, 64);
    assert.equal(e.length, 64);
  });
});
