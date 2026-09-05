import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { loadOrCreateSigners } from "../src/keys.ts";

describe("P2-8 partial key set", () => {
  it("does not rotate the remaining pair when effect.private.pem is missing", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-keys-"));
    const first = loadOrCreateSigners(stateDir);
    const recPubPath = join(stateDir, "keys", "record.public.pem");
    const before = readFileSync(recPubPath, "utf8");
    unlinkSync(join(stateDir, "keys", "effect.private.pem"));
    assert.equal(before, first.recordSigner.publicKeyPem);

    let second: ReturnType<typeof loadOrCreateSigners> | undefined;
    try {
      second = loadOrCreateSigners(stateDir);
    } catch (err) {
      assert.ok(err instanceof Error);
      assert.match(err.message, /keys-partial/);
      assert.equal(readFileSync(recPubPath, "utf8"), before, "record public key must stay");
      return;
    }
    if (second.recordSigner.publicKeyPem !== before) {
      throw new Error("P2-8 rotated record public key");
    }
    throw new Error("expected keys-partial");
  });
});
