import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { generateKeyPairSync } from "node:crypto";

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

describe("B6 stale memory", () => {
  it("does not return the body when validUntilMs is in the past", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-mem-"));
    let t = 1_000;
    let n = 0;
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      now: () => t,
      nonce: () => `n-${t}-${++n}`,
    });
    const put = await services.proxy.call(
      {
        name: "memory.put",
        arguments: {
          id: "note-1",
          body: { secret: "hidden" },
          source: { uri: "file://fixture", retrievedAtMs: 1 },
          validFromMs: 1,
          validUntilMs: 50,
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    assert.equal(put.isError, false);
    t = 100;
    const got = await services.proxy.call(
      { name: "memory.get", arguments: { id: "note-1" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    const parsed = JSON.parse(got.content[0]?.text ?? "{}") as {
      stale?: boolean;
      body?: unknown;
    };
    assert.equal(parsed.stale, true);
    assert.equal(parsed.body, undefined);
    assert.equal(JSON.stringify(parsed).includes("hidden"), false);
  });

  it("c: does not return the body when validFromMs is in the future", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-mem-from-"));
    let t = 1_000;
    let n = 0;
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      now: () => t,
      nonce: () => `n-${t}-${++n}`,
    });
    const put = await services.proxy.call(
      {
        name: "memory.put",
        arguments: {
          id: "note-2",
          body: { secret: "hidden-future" },
          source: { uri: "file://fixture", retrievedAtMs: 1 },
          validFromMs: 5_000,
          validUntilMs: 9_000,
        },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    assert.equal(put.isError, false);
    const putBody = JSON.parse(put.content[0]?.text ?? "{}") as { versionHash?: string };
    assert.equal(typeof putBody.versionHash, "string");
    assert.equal(putBody.versionHash?.length, 64);
    t = 1_000;
    const got = await services.proxy.call(
      { name: "memory.get", arguments: { id: "note-2" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    const parsed = JSON.parse(got.content[0]?.text ?? "{}") as {
      notYetValid?: boolean;
      body?: unknown;
    };
    assert.equal(got.isError, false);
    assert.equal(parsed.notYetValid, true);
    assert.equal(parsed.body, undefined);
    assert.equal(JSON.stringify(parsed).includes("hidden-future"), false);
  });
});
