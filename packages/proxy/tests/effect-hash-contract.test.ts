import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "explain.ts"), "utf8");

describe("B explain does not mint a checkpoint", () => {
  it("explain.ts does not mint or accept a checkpoint signer", () => {
    const banned = ["sign", "Checkpoint"].join("");
    assert.equal(src.includes(banned), false);
    assert.equal(src.includes("produceCheckpoint"), false);
    assert.equal(src.includes("checkpointSigner"), false);
  });
});
