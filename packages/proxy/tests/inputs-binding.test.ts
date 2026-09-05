import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { explain } from "../src/explain.ts";
import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const policy = loadPolicy(readFileSync(join(here, "..", "policy", "default.json"), "utf8"));
const fixtureDir = join(here, "fixtures", "policy");

describe("inputs binding", () => {
  it("a: a deny record binds identity under inputsHash", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["deny-id-1"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    const rec = (await ledger.decisions())[0];
    assert.equal(rec.claims.decision, "deny");
    assert.equal(typeof rec.claims.inputsHash, "string");
    assert.equal((rec.claims.inputsHash as string).length, 64);
    assert.notEqual(rec.claims.inputsHash, null);
  });

  it("b: a wrong _inputs versionHash is deny input-invalid", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["inv-1"]),
      resolveInput: async () => ({ versionHash: "a".repeat(64), validFromMs: 0, validUntilMs: 9_999 }),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call(
      {
        name: "memory.get",
        arguments: { id: "x", _inputs: [{ id: "note-1", versionHash: "b".repeat(64) }] },
      },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    assert.equal(out.isError, true);
    assert.match(out.content[0]?.text ?? "", /denied:input-invalid:inv-1/);
    assert.equal((await ledger.effects()).length, 0);
  });

  it("d: a tampered inputs.jsonl is an explain finding", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-inputs-"));
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["tamp-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    const path = join(dir, "inputs.jsonl");
    const raw = readFileSync(path, "utf8");
    const rows = raw
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { ref: string; inputs: { principal: { brain: string } } });
    rows[0]!.inputs.principal.brain = "attacker";
    writeFileSync(path, `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`);
    const result = await explain(ledger, "tamp-1");
    assert.equal(result.finding.code, "inputs-hash-mismatch");
    ledger.close();
  });

  it("f: a missing inputs document is reported, not read as balanced", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-inputs-miss-"));
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["miss-1"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    unlinkSync(join(dir, "inputs.jsonl"));
    const result = await explain(ledger, "miss-1");
    assert.ok(
      result.warnings.some((w) => w.code === "inputs-document-missing"),
      JSON.stringify(result.warnings),
    );
    assert.equal(result.finding.label, "conditional");
    ledger.close();
  });

  it("e: every policy fixture names a principal", () => {
    const files = readdirSync(fixtureDir).filter((n) => n.endsWith(".json"));
    assert.ok(files.length >= 1);
    for (const name of files) {
      const fx = JSON.parse(readFileSync(join(fixtureDir, name), "utf8")) as {
        principal?: { brain?: string; scopes?: string[] };
      };
      assert.equal(typeof fx.principal?.brain, "string", name);
      assert.ok(Array.isArray(fx.principal?.scopes), name);
    }
  });
});
