import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { findDecisionRecordChainBreak } from "@cedulon/core";

import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import type { Ledger } from "../src/types.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "./helpers.ts";

const policy = loadPolicy(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "default.json"), "utf8"),
);

async function storm(ledger: Ledger): Promise<void> {
  let n = 0;
  const proxy = createProxy({
    policy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: () => {
      n += 1;
      return n * 10;
    },
    nonce: () => `race-${n}-${Math.random().toString(16).slice(2)}`,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  const principal = { brain: "brain-1", scopes: new Set(["verax:read"]) };
  await Promise.all(
    Array.from({ length: 25 }, (_, i) =>
      proxy.call({ name: "memory.get", arguments: { id: `note-${i}` } }, principal),
    ),
  );
}

describe("P1-4 concurrent proxy.call keeps a single chain", () => {
  it("MemoryLedger and FileLedger survive 25 parallel calls without a chain break or duplicate-effect", async () => {
    for (const ledger of [new MemoryLedger(), new FileLedger(mkdtempSync(join(tmpdir(), "verax-race-")))]) {
      await storm(ledger);
      const decisions = await ledger.decisions();
      assert.equal(decisions.length, 25);
      const broken = findDecisionRecordChainBreak(decisions, [RECORD_SIGNER.publicKeyPem]);
      assert.equal(broken, null, `${ledger.constructor.name} chain break: ${JSON.stringify(broken)}`);
      const effects = await ledger.effects();
      assert.equal(
        effects.filter((e) => e.row.effectClass === "duplicate-effect").length,
        0,
      );
      assert.equal(effects.length, 25);
    }
  });
});
