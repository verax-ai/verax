import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { loadPolicy, parsePolicyDocument } from "../src/policy.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { createProxy } from "../src/proxy.ts";
import { spokenReason } from "../src/spoken-reason.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const defaultJson = JSON.parse(readFileSync(join(here, "..", "policy", "default.json"), "utf8")) as {
  version: 1;
  default: "deny";
  rules: unknown[];
};

const RULES = defaultJson.rules;

function policyWith(extra: Record<string, unknown>) {
  return loadPolicy({ version: 1, default: "deny", rules: RULES, ...extra });
}

const SCOPED = { brain: "brain-1", scopes: new Set(["verax:read"]) };

describe("policy.requireInputs", () => {
  it("lives on the document root; absent means today's allow of an undeclared call", async () => {
    const parsed = parsePolicyDocument(defaultJson);
    assert.equal("requireInputs" in parsed, false);
    const policy = loadPolicy(defaultJson);
    assert.notEqual(policy.requireInputs, true);
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["open-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call({ name: "memory.get", arguments: { id: "x" } }, SCOPED);
    assert.equal(out.isError, false);
    const rec = (await ledger.decisions())[0];
    assert.equal(rec?.claims.decision, "allow");
    assert.equal(rec?.claims.reasonCode, "allow");
  });

  it("requireInputs: true and no _inputs is a signed deny inputs-required", async () => {
    const policy = policyWith({ requireInputs: true });
    assert.equal(policy.requireInputs, true);
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["need-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call({ name: "memory.get", arguments: { id: "x" } }, SCOPED);
    assert.equal(out.isError, true);
    assert.match(out.content[0]?.text ?? "", /denied:inputs-required:need-1/);
    const rec = (await ledger.decisions())[0];
    assert.equal(rec?.claims.decision, "deny");
    assert.equal(rec?.claims.reasonCode, "inputs-required");
    assert.equal(rec?.claims.effectHash, null);
    assert.equal((await ledger.effects()).length, 0);
  });

  it("an empty _inputs array is a declaration, not inputs-required", async () => {
    const policy = policyWith({ requireInputs: true });
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["empty-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call(
      { name: "memory.get", arguments: { id: "x", _inputs: [] } },
      SCOPED,
    );
    assert.equal(out.isError, false, out.content[0]?.text);
    const rec = (await ledger.decisions())[0];
    assert.equal(rec?.claims.decision, "allow");
    assert.equal(rec?.claims.reasonCode, "allow");
  });

  it("a broken _inputs declaration stays input-invalid", async () => {
    const policy = policyWith({ requireInputs: true });
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["inv-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call(
      { name: "memory.get", arguments: { id: "x", _inputs: "nope" } },
      SCOPED,
    );
    assert.equal(out.isError, true);
    assert.match(out.content[0]?.text ?? "", /denied:input-invalid:inv-1/);
    assert.equal((await ledger.decisions())[0]?.claims.reasonCode, "input-invalid");
  });

  it("inputs-required is spoken as itself", () => {
    assert.equal(spokenReason("inputs-required"), "inputs-required");
  });

  it("DecisionInputRow still names validFromMs and validUntilMs", async () => {
    const policy = policyWith({ requireInputs: true });
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["row-1"]),
      resolveInput: async () => ({
        versionHash: "a".repeat(64),
        validFromMs: 1,
        validUntilMs: 9_999,
      }),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "memory.get",
        arguments: {
          id: "x",
          _inputs: [
            {
              id: "note-1",
              versionHash: "a".repeat(64),
              source: { kind: "memory" },
            },
          ],
        },
      },
      SCOPED,
    );
    const inputs = await proxy.inputsLog.get("row-1");
    const row = inputs?.inputs[0];
    assert.ok(row);
    assert.equal(row.validFromMs, 1);
    assert.equal(row.validUntilMs, 9_999);
    assert.equal(Object.hasOwn(row, "validFrom"), false);
    assert.equal(Object.hasOwn(row, "validUntil"), false);
    assert.deepEqual(row.source, { kind: "memory" });
  });

  it("refuses a non-boolean requireInputs", () => {
    assert.throws(() => policyWith({ requireInputs: "yes" }), /policy-require-inputs/);
  });
});
