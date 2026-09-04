import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { memoryGet, memoryPut } from "../src/tools/memory.ts";

function callOf(id: string) {
  return {
    name: "memory.put",
    arguments: {
      id,
      body: { t: 1 },
      source: { uri: "file://t", retrievedAtMs: 1 },
      validUntilMs: 9_999_999,
    },
  };
}

function parse(result: { content: { text: string }[] }): Record<string, unknown> {
  return JSON.parse(result.content[0]?.text ?? "{}") as Record<string, unknown>;
}

describe("P1-2 memory id stays inside memoryDir", () => {
  it("rejects ../escaped, a/b, and encoded traversal; does not write outside memory/", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-mem-id-"));
    const leaked = join(stateDir, "escaped.json");

    const putEscape = await memoryPut(callOf("../escaped"), stateDir);
    if (existsSync(leaked)) {
      throw new Error(`P1-2 leak: wrote ${leaked}`);
    }
    assert.equal(putEscape.isError, true);
    assert.equal(parse(putEscape).error, "id-invalid");
    assert.equal(existsSync(leaked), false);

    const getEscape = await memoryGet({ name: "memory.get", arguments: { id: "../escaped" } }, stateDir, () => 0);
    assert.equal(getEscape.isError, true);
    assert.equal(parse(getEscape).error, "id-invalid");

    for (const id of ["a/b", "..%2Fx"]) {
      const put = await memoryPut(callOf(id), stateDir);
      assert.equal(put.isError, true, `put ${id}`);
      assert.equal(parse(put).error, "id-invalid", `put ${id} error`);
      const get = await memoryGet({ name: "memory.get", arguments: { id } }, stateDir, () => 0);
      assert.equal(get.isError, true, `get ${id}`);
      assert.equal(parse(get).error, "id-invalid", `get ${id} error`);
    }
  });
});
