import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { parseDesktopArgs } from "../src/desktop.ts";

describe("verax desktop args", () => {
  it("parseDesktopArgs requires --state", () => {
    const parsed = parseDesktopArgs(["desktop"]);
    assert.deepEqual(parsed, { error: "usage" });
  });
});
