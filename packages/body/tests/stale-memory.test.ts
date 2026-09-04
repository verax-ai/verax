import { strict as assert } from "node:assert";
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

const keys = {
  privateKeyPem: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINzlJna6Owm08CZZR86n0YkAKTnSfONQQ46fSbBmoS7l
-----END PRIVATE KEY-----
`,
  publicKeyPem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2R1wiqm2GNoE2kyz8xTaWOJCePoHgIwyMVty5zV6WIQ=
-----END PUBLIC KEY-----
`,
};

describe("B6 stale memory", () => {
  it("does not return the body when validUntilMs is in the past", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-mem-"));
    let t = 1_000;
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      now: () => t,
      nonce: () => `n-${t}`,
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
});
