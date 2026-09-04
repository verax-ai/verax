import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { doctorExit, runDoctor } from "../src/doctor.ts";

describe("doctor", () => {
  it("fails when argv carries sk-test-not-a-key", () => {
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
      },
      ["node", "cli.ts", "doctor", "sk-test-not-a-key"],
    );
    assert.equal(doctorExit(checks), 1);
    assert.ok(checks.some((c) => c.id === "secrets-on-argv" && c.level === "fail"));
  });
});
