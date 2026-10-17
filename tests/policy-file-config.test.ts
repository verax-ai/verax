import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { EX_CONFIG, loadConfig } from "../packages/body/src/config.ts";

function env(policyFile: string): NodeJS.ProcessEnv {
  return {
    VERAX_ISSUER: "https://issuer.example",
    VERAX_JWKS_URL: "https://issuer.example/jwks",
    VERAX_AUDIENCE: "verax",
    VERAX_STATE_DIR: tmpdir(),
    VERAX_POLICY_FILE: policyFile,
  };
}

function refused(policyFile: string): { code: number; reason: string } {
  const loaded = loadConfig(env(policyFile));
  assert.equal(loaded.ok, false);
  if (loaded.ok) return { code: 0, reason: "" };
  return { code: loaded.code, reason: loaded.reason };
}

describe("VERAX_POLICY_FILE", () => {
  it("a directory exits 78 with one line and no stack", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-policy-dir-"));
    const got = refused(dir);
    assert.equal(got.code, EX_CONFIG);
    assert.equal(got.reason, `VERAX_POLICY_FILE is a directory: ${dir}`);
    assert.equal(got.reason.includes("\n"), false);
    assert.equal(got.reason.includes("at "), false);
  });

  it("a readable file is accepted", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-policy-file-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, "{}\n", "utf8");
    const loaded = loadConfig(env(file));
    assert.equal(loaded.ok, true, loaded.ok ? "" : loaded.reason);
  });
});
