import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { PAIRING_MAX_ATTEMPTS, pairingPath, writePairing } from "../packages/body/src/operator-pairing.ts";
import { refusedAsElevated } from "./elevated-refusal.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

describe("verax operator enroll", () => {
  it("prints an 8-digit code and writes only its hash", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-enroll-"));
    const ran = spawnSync(
      process.execPath,
      ["--experimental-strip-types", cli, "operator", "enroll", "--state", stateDir],
      { encoding: "utf8", windowsHide: true },
    );
    if (refusedAsElevated(ran.status, ran.stderr ?? "")) return;
    assert.equal(ran.status, 0, ran.stderr);
    const code = (ran.stdout ?? "").trim();
    assert.match(code, /^\d{8}$/);
    const stored = readFileSync(pairingPath(stateDir), "utf8");
    assert.equal(stored.includes(code), false);
    assert.match(stored, /"hash":"[0-9a-f]{64}"/);
  });

  it("a second enroll says the earlier code no longer works", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-operator-enroll-again-"));
    const args = ["--experimental-strip-types", cli, "operator", "enroll", "--state", stateDir];
    const first = spawnSync(process.execPath, args, { encoding: "utf8", windowsHide: true });
    if (refusedAsElevated(first.status, first.stderr ?? "")) return;
    assert.equal(first.status, 0, first.stderr);
    assert.equal(first.stderr ?? "", "");
    assert.match((first.stdout ?? "").trim(), /^\d{8}$/);
    const second = spawnSync(process.execPath, args, { encoding: "utf8", windowsHide: true });
    if (refusedAsElevated(second.status, second.stderr ?? "")) return;
    assert.equal(second.status, 0, second.stderr);
    assert.equal(second.stderr, "the earlier pairing code no longer works\n");
    assert.match((second.stdout ?? "").trim(), /^\d{8}$/);
  });

  it("an expired or burned code is replaced without that line", () => {
    const expiredDir = mkdtempSync(join(tmpdir(), "verax-operator-enroll-expired-"));
    writePairing(expiredDir, { hash: "ab".repeat(32), expiresAtMs: Date.now() - 1_000, attempts: 0 });
    const burnedDir = mkdtempSync(join(tmpdir(), "verax-operator-enroll-burned-"));
    writePairing(burnedDir, {
      hash: "cd".repeat(32),
      expiresAtMs: Date.now() + 60_000,
      attempts: PAIRING_MAX_ATTEMPTS,
    });
    for (const stateDir of [expiredDir, burnedDir]) {
      const ran = spawnSync(
        process.execPath,
        ["--experimental-strip-types", cli, "operator", "enroll", "--state", stateDir],
        { encoding: "utf8", windowsHide: true },
      );
      if (refusedAsElevated(ran.status, ran.stderr ?? "")) return;
      assert.equal(ran.status, 0, ran.stderr);
      assert.equal(ran.stderr ?? "", "");
      assert.match((ran.stdout ?? "").trim(), /^\d{8}$/);
    }
  });
});
