import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { pairingPath } from "../packages/body/src/operator-pairing.ts";

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
    assert.equal(ran.status, 0, ran.stderr);
    const code = (ran.stdout ?? "").trim();
    assert.match(code, /^\d{8}$/);
    const stored = readFileSync(pairingPath(stateDir), "utf8");
    assert.equal(stored.includes(code), false);
    assert.match(stored, /"hash":"[0-9a-f]{64}"/);
  });
});
