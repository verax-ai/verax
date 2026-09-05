import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { explain } from "../src/explain.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";
import { runGoldenScenario } from "./golden-scenario.ts";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const policy = loadPolicy(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "default.json"), "utf8"),
);

function warningIds(result: Awaited<ReturnType<typeof explain>>): string[] {
  return (result.warnings ?? []).map((w) => w.id);
}

describe("explain guarantee and general warnings", () => {
  it("1: a solid deny with no pin is conditional and shows the issuer warning", async () => {
    delete process.env.VERAX_RECORD_PUBKEY_PIN;
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["deny-1"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    const result = await explain(ledger, "deny-1");
    assert.equal(result.guarantee, "conditional");
    assert.ok(warningIds(result).includes("issuer"));
    assert.equal(result.witnessClass, null);
    assert.equal(result.finding.label, "conditional");
    assert.match(result.finding.summary, /balanced \(/);
    assert.equal(result.finding.summary.includes("audit: balanced") && !result.finding.summary.includes("("), false);
  });

  it("2: a self allow is conditional because of self witness", async () => {
    delete process.env.VERAX_RECORD_PUBKEY_PIN;
    const dir = mkdtempSync(join(tmpdir(), "verax-g3-self-"));
    const ledger = await runGoldenScenario(dir);
    const result = await explain(ledger, "n1");
    assert.equal(result.guarantee, "conditional");
    assert.equal(result.witnessClass, "self");
    assert.match(result.finding.summary, /self witness/);
  });

  it("3: a foreign-key record against a pin is a finding", async () => {
    delete process.env.VERAX_RECORD_PUBKEY_PIN;
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: EFFECT_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["foreign-1"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    const result = await explain(ledger, "foreign-1", {
      issuerTrust: { publicKeyPem: RECORD_SIGNER.publicKeyPem },
    });
    const codes = [
      result.finding.code,
      ...(result.warnings ?? []).map((w) => w.code),
    ];
    assert.ok(
      codes.includes("issuer-key-mismatch") || codes.includes("unauthenticated-issuer"),
      `expected an issuer finding, got ${JSON.stringify(codes)}`,
    );
  });

  it("4: a missing signed extract is an extract warning", async () => {
    delete process.env.VERAX_RECORD_PUBKEY_PIN;
    const dir = mkdtempSync(join(tmpdir(), "verax-g3-extract-"));
    const ledger = await runGoldenScenario(dir);
    const result = await explain(ledger, "n4");
    assert.ok(warningIds(result).includes("extract"));
  });
});
