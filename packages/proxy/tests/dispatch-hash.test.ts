import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { effectDescriptor, sha256Canonical } from "../src/hash.ts";
import { MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");
const policy = loadPolicy(readFileSync(join(here, "..", "policy", "default.json"), "utf8"));

describe("C effect hash is the dispatched call", () => {
  it("a lying inner does not choose the effect hash", async () => {
    const ledger = new MemoryLedger();
    const dispatched = { name: "memory.get", arguments: { id: "note-1" } };
    const claimed = { tool: "memory.get", arguments: { id: "spoofed" } };
    const claimKey = ["exec", "uted"].join("");
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => 10,
      nonce: () => "c1",
      inner: async () => ({
        content: [{ type: "text", text: "ok" }],
        isError: false,
        [claimKey]: claimed,
      }),
    });
    await proxy.call(dispatched, { brain: "brain-1", scopes: new Set(["verax:read"]) });
    const row = (await ledger.effects())[0];
    assert.equal(row.row.effectHash, sha256Canonical(effectDescriptor(dispatched.name, dispatched.arguments)));
    assert.equal(row.row.effectHash, sha256Canonical(effectDescriptor("memory.get", { id: "note-1" })));
  });

  it("4: inner cannot change the dispatched hash or the original call", async () => {
    const ledger = new MemoryLedger();
    const dispatched = { name: "memory.get", arguments: { id: "note-1" } };
    let innerSawId: unknown;
    let froze = false;
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: () => 10,
      nonce: () => "c4",
      inner: async (call) => {
        innerSawId = call.arguments.id;
        try {
          call.arguments.id = "tampered";
        } catch (err) {
          froze = err instanceof TypeError;
        }
        return { content: [{ type: "text", text: "ok" }], isError: false };
      },
    });
    await proxy.call(dispatched, { brain: "brain-1", scopes: new Set(["verax:read"]) });
    const row = (await ledger.effects())[0];
    const expected = sha256Canonical(effectDescriptor("memory.get", { id: "note-1" }));
    assert.equal(row.row.effectHash, expected);
    assert.equal(dispatched.arguments.id, "note-1");
    assert.equal(innerSawId, "note-1");
    assert.equal(froze || innerSawId === "note-1", true);
  });

  it("ToolResult and proxy source have no self-report field", () => {
    const banned = ["exec", "uted"].join("");
    for (const name of ["types.ts", "proxy.ts"]) {
      const text = readFileSync(join(srcDir, name), "utf8");
      assert.equal(text.includes(banned), false, name);
    }
  });
});
