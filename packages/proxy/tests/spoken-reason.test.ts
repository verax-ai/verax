import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { spokenReason } from "../src/spoken-reason.ts";

describe("spoken reason table", () => {
  it("maps tenant-mismatch to the not-found family and leaves other codes alone", () => {
    assert.equal(spokenReason("tenant-mismatch"), "not-found");
    assert.equal(spokenReason("scope-missing"), "scope-missing");
    assert.equal(spokenReason("egress-blocked"), "egress-blocked");
    assert.equal(spokenReason("allow"), "allow");
    assert.equal(spokenReason("inputs-required"), "inputs-required");
  });
});
