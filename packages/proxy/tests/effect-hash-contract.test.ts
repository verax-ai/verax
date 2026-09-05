import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { verifyEffectExtract } from "@cedulon/effect-extract";

import { MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "explain.ts"), "utf8");
const policy = loadPolicy(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "default.json"), "utf8"),
);

describe("B explain does not mint a checkpoint", () => {
  it("explain.ts does not mint or accept a checkpoint signer", () => {
    const banned = ["sign", "Checkpoint"].join("");
    assert.equal(src.includes(banned), false);
    assert.equal(src.includes("produceCheckpoint"), false);
    assert.equal(src.includes("checkpointSigner"), false);
  });
});

describe("effect receipt at call time", () => {
  it("a written row carries a receipt that verifies and matches the row", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["eff-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      { name: "memory.get", arguments: { id: "x" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    const effect = (await ledger.effects())[0];
    assert.ok(effect?.receipt);
    assert.equal(verifyEffectExtract(effect.receipt, EFFECT_SIGNER.publicKeyPem), true);
    assert.deepEqual(effect.receipt.body.effects[0], effect.row);
  });

  it("a tampered receipt row fails verify", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["eff-2"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      { name: "memory.get", arguments: { id: "x" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    const effect = (await ledger.effects())[0];
    assert.ok(effect?.receipt);
    const tampered = {
      ...effect.receipt,
      body: {
        ...effect.receipt.body,
        effects: [{ ...effect.receipt.body.effects[0]!, effectHash: "0".repeat(64) }],
      },
    };
    assert.equal(verifyEffectExtract(tampered, EFFECT_SIGNER.publicKeyPem), false);
  });

  it("a deny has no receipt", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["den-1"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    assert.equal((await ledger.effects()).length, 0);
  });
});
