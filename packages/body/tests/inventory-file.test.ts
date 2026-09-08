import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { overlayInventoryArg } from "../src/config.ts";
import { inventoryHealth, readInventoryFile } from "../src/inventory-file.ts";

const sample = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "galaxy", "tests", "fixtures", "inventory-sample.json");

describe("readInventoryFile", () => {
  it("treats a missing path or missing file as absence, not a fault", () => {
    assert.deepEqual(readInventoryFile(null), { inventory: null });
    assert.deepEqual(readInventoryFile(""), { inventory: null });
    assert.deepEqual(readInventoryFile(join(tmpdir(), "verax-inventory-absent.json")), { inventory: null });
  });

  it("returns the document when it is valid", () => {
    const door = readInventoryFile(sample);
    assert.ok(door.inventory);
    assert.equal(door.inventory?.source, "fixture-source");
    assert.equal(door.inventory?.agents.length, 3);
    assert.deepEqual(inventoryHealth(door), {
      source: "fixture-source",
      takenAtMs: 1700000000000,
      agents: 3,
    });
  });

  it("returns null plus a reason for broken JSON or a missing field, never a partial model", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-inv-"));
    const badJson = join(dir, "bad.json");
    writeFileSync(badJson, "{", "utf8");
    const broken = readInventoryFile(badJson);
    assert.deepEqual(broken, { inventory: null, reason: "invalid-json" });

    const missing = join(dir, "missing.json");
    writeFileSync(missing, JSON.stringify({ takenAtMs: 1, source: "fixture-source", groups: [], orphans: [] }), "utf8");
    const gap = readInventoryFile(missing);
    assert.equal(gap.inventory, null);
    if (!gap.inventory) assert.match(gap.reason ?? "", /invalid:agents/);
  });
});

describe("overlayInventoryArg", () => {
  it("lets --inventory win over the environment", () => {
    const over = overlayInventoryArg({ VERAX_INVENTORY_FILE: "from-env.json" }, ["--inventory", "from-flag.json"]);
    assert.ok(!("error" in over));
    if (!("error" in over)) assert.equal(over.VERAX_INVENTORY_FILE, "from-flag.json");
  });

  it("rejects --inventory without a path", () => {
    const over = overlayInventoryArg({}, ["--inventory"]);
    assert.deepEqual(over, { error: "missing --inventory path" });
  });
});
