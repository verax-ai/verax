import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  PAIRING_MAX_ATTEMPTS,
  PAIRING_TTL_MS,
  beginPairing,
  checkPairing,
  consumePairing,
  pairingPath,
  readPairing,
} from "../src/operator-pairing.ts";

function dir(): string {
  return mkdtempSync(join(tmpdir(), "verax-pairing-"));
}

describe("operator pairing code", () => {
  it("stores only the hash, and a wrong code does not enroll", () => {
    const stateDir = dir();
    const { code } = beginPairing(stateDir, 1_000);
    assert.match(code, /^\d{8}$/);
    const stored = readFileSync(pairingPath(stateDir), "utf8");
    assert.equal(stored.includes(code), false);
    assert.equal(checkPairing(stateDir, "00000000", 1_000).ok, false);
    assert.equal(checkPairing(stateDir, code, 1_000).ok, true);
  });

  it("burns after five mismatches, so the sixth correct code is refused", () => {
    const stateDir = dir();
    const { code } = beginPairing(stateDir, 1_000);
    for (let i = 0; i < PAIRING_MAX_ATTEMPTS; i += 1) {
      const got = checkPairing(stateDir, "11111111", 1_000);
      assert.equal(got.ok, false);
    }
    const sixth = checkPairing(stateDir, code, 1_000);
    assert.deepEqual(sixth, { ok: false, reason: "burned" });
  });

  it("refuses an expired code even when the digits match", () => {
    const stateDir = dir();
    const { code } = beginPairing(stateDir, 1_000);
    const late = checkPairing(stateDir, code, 1_000 + PAIRING_TTL_MS + 1);
    assert.deepEqual(late, { ok: false, reason: "expired" });
  });

  it("consumePairing spends the code so it cannot be reused", () => {
    const stateDir = dir();
    const { code } = beginPairing(stateDir, 1_000);
    consumePairing(stateDir);
    assert.deepEqual(checkPairing(stateDir, code, 1_000), { ok: false, reason: "burned" });
    assert.equal(existsSync(pairingPath(stateDir)), true);
    assert.equal(readPairing(stateDir)?.attempts, PAIRING_MAX_ATTEMPTS);
  });
});
