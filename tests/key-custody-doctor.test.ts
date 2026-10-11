import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { doctorExit, runDoctor } from "../packages/body/src/doctor.ts";

function stateWithKey(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-key-custody-"));
  mkdirSync(join(dir, "keys"), { recursive: true, mode: 0o700 });
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(dir, "keys", "record.private.pem"), privateKey.export({ type: "pkcs8", format: "pem" }).toString(), {
    mode: 0o600,
  });
  return dir;
}

/**
 * In local mode the body and the agent run as one OS user, so the agent can
 * read the key the body signs records with. doctor says so in red instead of
 * leaving it to THREAT_MODEL.
 */
describe("doctor key custody", () => {
  it("fails when this unelevated user can read the record key", () => {
    const dir = stateWithKey();
    try {
      const checks = runDoctor({ VERAX_STATE_DIR: dir, VERAX_JWKS_FILE: join(dir, "jwks.json") }, [], {
        elevated: () => false,
      });
      const check = checks.find((c) => c.id === "key-custody");
      assert.equal(check?.level, "fail", JSON.stringify(checks));
      assert.match(check?.detail ?? "", /^local mode: /);
      assert.match(check?.detail ?? "", /an agent running as this user can sign records as the body/);
      assert.equal(doctorExit(checks), 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an elevated session reading it is a warning, not the agent's reach", () => {
    const dir = stateWithKey();
    try {
      const check = runDoctor({ VERAX_STATE_DIR: dir }, [], { elevated: () => true }).find((c) => c.id === "key-custody");
      assert.equal(check?.level, "warn");
      assert.match(check?.detail ?? "", /elevated/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("says nothing when there is no record key yet", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-key-custody-none-"));
    try {
      const check = runDoctor({ VERAX_STATE_DIR: dir }, [], { elevated: () => false }).find((c) => c.id === "key-custody");
      assert.equal(check, undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
