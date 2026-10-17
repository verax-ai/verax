import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { EX_CONFIG, loadConfig } from "../packages/body/src/config.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const main = join(root, "packages", "body", "src", "main.ts");

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

  it("a path that is not there exits 78 with one line and no stack", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-policy-missing-"));
    const missing = join(stateDir, "no-such-policy.json");
    const child = spawn(process.execPath, ["--experimental-strip-types", main], {
      cwd: root,
      env: {
        ...process.env,
        VERAX_ISSUER: "https://issuer.example",
        VERAX_JWKS_URL: "https://issuer.example/jwks",
        VERAX_AUDIENCE: "verax",
        VERAX_STATE_DIR: stateDir,
        VERAX_POLICY_FILE: missing,
        VERAX_BIND: "127.0.0.1:0",
        VERAX_JWKS_FILE: "",
        VERAX_JWKS_PIN: "",
        VERAX_DOWNSTREAM: "",
        VERAX_OPERATOR_DOOR: "",
        VERAX_DESKTOP_PARENT_PID: "",
        VERAX_TLS_TERMINATED: "",
        VERAX_INVENTORY_FILE: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += String(chunk);
    });
    const timer = setTimeout(() => child.kill(), 20_000);
    const code = await new Promise<number | null>((resolve) => {
      child.once("exit", (status) => resolve(status));
    });
    clearTimeout(timer);
    rmSync(stateDir, { recursive: true, force: true });
    const lines = stderr.split(/\r?\n/).filter((line) => line !== "");
    assert.equal(lines.length, 1, JSON.stringify(stderr));
    assert.equal(lines[0]?.includes("VERAX_POLICY_FILE"), true, stderr);
    assert.equal(lines[0]?.includes(missing), true, stderr);
    assert.equal(lines.some((line) => line.startsWith("    at ")), false, stderr);
    assert.equal(code, EX_CONFIG, stderr);
  });

  it("a readable file is accepted", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-policy-file-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, "{}\n", "utf8");
    const loaded = loadConfig(env(file));
    assert.equal(loaded.ok, true, loaded.ok ? "" : loaded.reason);
  });
});
