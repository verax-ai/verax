import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { openDownstream } from "../packages/body/src/downstream.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests", "fixtures", "downstream-media.mjs");

const MEDIA_POLICY = JSON.stringify({
  version: 1,
  default: "deny",
  rules: [
    {
      id: "media-blocks",
      tool: "media.blocks",
      requires: ["verax:read"],
      text: "Calling the media downstream needs the read scope.",
    },
  ],
});

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("downstream media blocks", { timeout: 60_000 }, () => {
  it("keeps image and audio blocks and turns the rest into JSON text", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-down-media-"));
    const policyFile = join(dir, "policy.json");
    writeFileSync(policyFile, `${MEDIA_POLICY}\n`, "utf8");
    const keys = testKeys();
    let n = 0;
    const session = await openDownstream({
      prefix: "media",
      command: process.execPath,
      args: [fixture],
      cwd: root,
      trust: "same-user",
    });
    try {
      const services = createBodyServices({
        stateDir: dir,
        policyFile,
        recordSigner: keys,
        effectSigner: keys,
        now: () => Date.now(),
        nonce: () => `n${++n}`,
        extraTools: session.tools,
      });
      try {
        const result = await services.proxy.call(
          { name: "media.blocks", arguments: {} },
          { brain: "brain-1", scopes: new Set(["verax:read"]) },
        );
        assert.equal(result.isError, false);
        const blocks = result.content;
        assert.equal(blocks.length, 5);
        assert.deepEqual(blocks[0], { type: "text", text: "hello-media" });
        assert.deepEqual(blocks[1], { type: "image", data: "aW1n", mimeType: "image/png" });
        assert.deepEqual(blocks[2], { type: "audio", data: "YXVk", mimeType: "audio/mpeg" });
        assert.equal(blocks[3]?.type, "text");
        assert.match(blocks[3] && blocks[3].type === "text" ? blocks[3].text : "", /resource/);
        assert.equal(blocks[4]?.type, "text");
        assert.match(blocks[4] && blocks[4].type === "text" ? blocks[4].text : "", /resource_link/);
      } finally {
        services.ledger.close();
      }
    } finally {
      await session.close();
    }
  });
});
