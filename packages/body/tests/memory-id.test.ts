import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync } from "node:fs";
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

function parse(result: { content: { text: string }[] }): Record<string, unknown> {
  return JSON.parse(result.content[0]?.text ?? "{}") as Record<string, unknown>;
}

describe("P1-2 memory id stays inside memoryDir", () => {
  it("rejects ../escaped, a/b, and encoded traversal; does not write outside memory/", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-mem-id-"));
    const leaked = join(stateDir, "escaped.json");
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    const writer = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

    const putEscape = await services.proxy.call(
      {
        name: "memory.put",
        arguments: {
          id: "../escaped",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: 9_999_999,
        },
      },
      writer,
    );
    if (existsSync(leaked)) {
      throw new Error(`P1-2 leak: wrote ${leaked}`);
    }
    assert.equal(putEscape.isError, true);
    assert.equal(parse(putEscape).error, "id-invalid");
    assert.equal(existsSync(leaked), false);

    const getEscape = await services.proxy.call(
      { name: "memory.get", arguments: { id: "../escaped" } },
      reader,
    );
    assert.equal(getEscape.isError, true);
    assert.equal(parse(getEscape).error, "id-invalid");

    for (const id of ["a/b", "..%2Fx"]) {
      const put = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id,
            body: { t: 1 },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999_999,
          },
        },
        writer,
      );
      assert.equal(put.isError, true, `put ${id}`);
      assert.equal(parse(put).error, "id-invalid", `put ${id} error`);
      const get = await services.proxy.call({ name: "memory.get", arguments: { id } }, reader);
      assert.equal(get.isError, true, `get ${id}`);
      assert.equal(parse(get).error, "id-invalid", `get ${id} error`);
    }
  });
});
