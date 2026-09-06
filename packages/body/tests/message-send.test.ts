import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createBodyServices } from "../src/wiring.ts";

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("message.send stub", () => {
  it("queues on outbox.jsonl through proxy.call and does not name a network API", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-send-stub-"));
    const policyFile = join(dir, "policy.json");
    writeFileSync(
      policyFile,
      `${JSON.stringify({
        version: 1,
        default: "deny",
        egress: ["mail.example"],
        rules: [
          {
            id: "message-send",
            tool: "message.send",
            requires: ["verax:act"],
            text: "Sending a message needs the act scope.",
            egress: true,
          },
        ],
      })}\n`,
      "utf8",
    );
    const keys = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const out = await services.proxy.call(
        { name: "message.send", arguments: { to: "alice@mail.example", text: "hi" } },
        { brain: "brain-1", scopes: new Set(["verax:act"]) },
      );
      assert.equal(out.isError, false);
      const line = JSON.parse(readFileSync(join(dir, "outbox.jsonl"), "utf8").trim()) as {
        to: string;
        text: string;
        ref: string;
      };
      assert.equal(line.to, "alice@mail.example");
      assert.equal(line.text, "hi");
      assert.equal(typeof line.ref, "string");
    } finally {
      services.ledger.close();
    }
    const toolSrc = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "tools", "message.ts"), "utf8");
    assert.doesNotMatch(toolSrc, /\bfetch\s*\(|\bcreateConnection\b|\bdns\b/);
  });
});
