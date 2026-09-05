import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createBodyServices } from "../src/wiring.ts";

const policyFile = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "proxy",
  "policy",
  "default.json",
);

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("explain does not sign a window extract", () => {
  it("6: audit.explain presents the call-time receipt; exportExtract is not called", async () => {
    delete process.env.VERAX_RECORD_PUBKEY_PIN;
    const dir = mkdtempSync(join(tmpdir(), "verax-no-resign-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      now: (() => {
        let t = 1_000;
        return () => (t += 10);
      })(),
      nonce: (() => {
        const q = ["allow-1", "explain-1"];
        return () => {
          const next = q.shift();
          if (!next) throw new Error("nonce-exhausted");
          return next;
        };
      })(),
    });
    let exports = 0;
    const orig = services.ledger.exportExtract.bind(services.ledger);
    services.ledger.exportExtract = async (window, signer) => {
      exports += 1;
      return orig(window, signer);
    };
    const allowed = await services.proxy.call(
      {
        name: "memory.put",
        arguments: {
          id: "note-1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: 9_999,
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    assert.equal(allowed.isError, false);
    exports = 0;
    const explained = await services.proxy.call(
      { name: "audit.explain", arguments: { ref: "allow-1" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    assert.equal(exports, 0, `exportExtract called ${exports} time(s) at explain`);
    const body = JSON.parse(explained.content[0]?.text ?? "{}") as {
      warnings?: { id: string; code: string; detail: string }[];
    };
    const extract = body.warnings?.find((w) => w.id === "extract");
    assert.ok(extract, JSON.stringify(body.warnings));
    assert.match(extract.detail, /no verifier-supplied/);
    services.ledger.close();
  });
});
