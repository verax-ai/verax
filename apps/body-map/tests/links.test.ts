import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const expected = ["tugra-ai.com", "talamus.dev", "verax-ai.com", "cedulon.com", "conarium.dev", "—", "verax-ai.com"];

describe("card links", () => {
  it("match the fixture list", () => {
    const en = JSON.parse(
      readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "copy", "en.json"), "utf8"),
    ) as Record<string, string>;
    const links = ["head", "face", "core", "hands", "torso", "ground", "whole"].map((g) => en[`${g}.link`]);
    assert.deepEqual(links, expected);
  });
});
