import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { runDoctor } from "../src/doctor.ts";

const BASE = {
  VERAX_ISSUER: "http://127.0.0.1:8790",
  VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
  VERAX_AUDIENCE: "http://127.0.0.1:8787",
  VERAX_STATE_DIR: ".",
  VERAX_POLICY_FILE: "x",
};

describe("P2-10 doctor spots JWT-shaped env tokens", () => {
  it("fails on VERAX_DEV_TOKEN=eyJ... and does not print the value", () => {
    const token = "eyJhbGciOiJFUzI1NiJ.payload-not-a-secret";
    const checks = runDoctor({ ...BASE, VERAX_DEV_TOKEN: token }, ["node", "cli.ts", "doctor"]);
    const dumped = JSON.stringify(checks);
    assert.equal(dumped.includes(token), false, dumped);
    assert.equal(dumped.includes("eyJhbGciOiJFUzI1NiJ"), false, dumped);
    const hit = checks.find((c) => c.id === "secrets-on-argv" || c.id === "secrets-in-env");
    assert.ok(hit, dumped);
    assert.equal(hit?.level, "fail", dumped);
    assert.match(hit?.detail ?? "", /VERAX_DEV_TOKEN/);
  });
});
