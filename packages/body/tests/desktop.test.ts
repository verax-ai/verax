import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { issuerEnv, parseDesktopArgs } from "../src/desktop.ts";

describe("verax desktop args", () => {
  it("parseDesktopArgs requires --state", () => {
    const parsed = parseDesktopArgs(["desktop"]);
    assert.deepEqual(parsed, { error: "usage" });
  });
});

describe("verax desktop wiring", () => {
  it("tells the issuer which port this run put the panel on", () => {
    const env = issuerEnv(
      {},
      { stateDir: "/tmp/state", issuerPort: 8791, panelPort: 5200 },
      "http://127.0.0.1:8787",
      "http://127.0.0.1:8791",
    );
    // Without this the panel's own origin is not on the allow-list and the code
    // flow stops at `invalid_request` on any port but the default.
    assert.equal(env.VERAX_DEV_REDIRECT_URIS, "http://127.0.0.1:5200/");
    assert.equal(env.VERAX_DEV_ISSUER_PORT, "8791");
  });
});
