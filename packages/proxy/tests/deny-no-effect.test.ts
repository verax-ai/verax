import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { verifyDecisionRecord } from "@cedulon/core";

import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const policy = loadPolicy(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "default.json"), "utf8"),
);

describe("B2 deny leaves no effect", () => {
  it("does not call inner, writes one deny record with a ref, verifies", async () => {
    let innerCalls = 0;
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["ref-deny-1"]),
      inner: async () => {
        innerCalls += 1;
        return { content: [{ type: "text", text: "should-not-run" }], isError: false };
      },
    });
    const result = await proxy.call(
      { name: "memory.get", arguments: { id: "x" } },
      { brain: "brain-1", scopes: new Set() },
    );
    assert.equal(innerCalls, 0);
    assert.equal(result.isError, true);
    assert.equal(result.content[0]?.text, "denied:scope-missing:ref-deny-1");
    assert.equal((await ledger.effects()).length, 0);
    const decisions = await ledger.decisions();
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].claims.decision, "deny");
    assert.equal(decisions[0].claims.ref, "ref-deny-1");
    assert.equal(decisions[0].claims.effectHash, null);
    assert.equal(verifyDecisionRecord(decisions[0], RECORD_SIGNER.publicKeyPem), true);
  });
});
