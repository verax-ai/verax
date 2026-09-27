import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import type { LedgerEffect } from "../src/types.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const REF = "dup-ref";

/**
 * A refused duplicate is a real ledger row. It is bound by the writer's fixed
 * refusal hash and by the effect signature, not by the decision's effectHash.
 * On the tree before F7c the row is unsigned, so the first test fails.
 */
async function ledgerThatRefusedADuplicate(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-dup-verify-"));
  const ledger = new FileLedger(dir);
  try {
    const proxy = createProxy({
      policy: loadPolicy({
        version: 1,
        default: "deny",
        rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
      }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce([REF]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      { name: "memory.get", arguments: { id: "a", _ref: REF } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    await assert.rejects(
      () =>
        ledger.appendEffect({
          ref: REF,
          effectHash: "ab".repeat(32),
          effectClass: "memory.get",
          timestampMs: 99,
          actor: "brain-1",
        }),
      /duplicate-effect:dup-ref/,
    );
  } finally {
    ledger.close();
  }
  return dir;
}

function editDuplicate(dir: string, edit: (row: LedgerEffect) => void): void {
  const path = join(dir, "effects.jsonl");
  const lines = readFileSync(path, "utf8").split("\n");
  const at = lines.findIndex((line) => line.includes('"duplicate-effect"'));
  assert.ok(at >= 0, "duplicate-effect row missing");
  const row = JSON.parse(lines[at]!) as LedgerEffect;
  assert.equal(row.row.effectClass, "duplicate-effect");
  edit(row);
  lines[at] = JSON.stringify(row);
  writeFileSync(path, lines.join("\n"), "utf8");
}

describe("verifyLedger — duplicate-effect", () => {
  it("accepts a FileLedger that refused a duplicate", async () => {
    const dir = await ledgerThatRefusedADuplicate();
    try {
      const result = await verifyLedger(dir);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.effectsOrphaned, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a duplicate row whose effectHash is not the fixed refusal", async () => {
    const dir = await ledgerThatRefusedADuplicate();
    try {
      editDuplicate(dir, (row) => {
        row.row.effectHash = "cd".repeat(32);
      });
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => problem === `duplicate-effect hash is not the fixed refusal: ref ${REF}`),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a duplicate row whose signature was stripped", async () => {
    const dir = await ledgerThatRefusedADuplicate();
    try {
      editDuplicate(dir, (row) => {
        delete row.attestation;
        delete row.receipt;
      });
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => problem === `effect attestation does not cover the row: ref ${REF}`),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("verifyLedger — effect hash binding", () => {
  it("rejects a correctly signed effect whose effectHash is not its decision's", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-hash-verify-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: loadPolicy({ version: 1, default: "deny", rules: [] }),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["denied-ref"]),
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        { name: "memory.get", arguments: { id: "a", _ref: "denied-ref" } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      // The writer signs whatever it is handed; only the verifier can tie it back.
      await ledger.appendEffect({
        ref: "denied-ref",
        effectHash: "cd".repeat(32),
        effectClass: "memory.get",
        timestampMs: 99,
        actor: "brain-1",
      });
    } finally {
      ledger.close();
    }
    try {
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(result.problems.some((p) => /effect hash does not match its decision: ref denied-ref/.test(p)), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
