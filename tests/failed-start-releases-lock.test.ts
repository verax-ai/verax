import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createBodyServices } from "../packages/body/src/wiring.ts";

/**
 * 0.5.0 refuses policy files that 0.4.8 loaded: a key the parser does not
 * know, an unmarked `message.send` rule, a host list no rule reads. The body
 * opened its ledger, and so took the ledger lock, before it read the policy,
 * and did not release it when the policy was refused. An operator who then
 * fixed the file met a second refusal, this time for the lock the failed
 * start had left behind.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const shipped = JSON.parse(readFileSync(join(root, "packages", "proxy", "policy", "default.json"), "utf8")) as Record<
  string,
  unknown
>;

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("a start the policy stops leaves no ledger lock", () => {
  for (const [label, bad, reason] of [
    ["a key 0.4.8 dropped", { ...shipped, note: "ops: reviewed in March" }, /policy-unknown-key:note/],
    ["a file that is not JSON", "{ this is not json", /./],
  ] as const) {
    it(`${label}: the next start, with the file fixed, opens`, () => {
      const dir = mkdtempSync(join(tmpdir(), "verax-failed-start-"));
      const policyFile = join(dir, "policy.json");
      const signer = keys();
      const open = () =>
        createBodyServices({ stateDir: dir, policyFile, recordSigner: signer, effectSigner: signer });
      try {
        writeFileSync(policyFile, typeof bad === "string" ? bad : `${JSON.stringify(bad)}\n`, "utf8");
        assert.throws(open, reason);
        assert.equal(existsSync(join(dir, "ledger.lock")), false, "the refused start left ledger.lock behind");

        writeFileSync(policyFile, `${JSON.stringify(shipped)}\n`, "utf8");
        const services = open();
        services.ledger.close();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  it("a missing policy file does the same", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-failed-start-"));
    const signer = keys();
    try {
      assert.throws(() =>
        createBodyServices({
          stateDir: dir,
          policyFile: join(dir, "no-such-policy.json"),
          recordSigner: signer,
          effectSigner: signer,
        }),
      );
      assert.equal(existsSync(join(dir, "ledger.lock")), false, "the refused start left ledger.lock behind");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
