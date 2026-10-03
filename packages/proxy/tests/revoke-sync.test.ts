import { strict as assert } from "node:assert";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import type { DecisionInputs } from "../src/types.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, tickingNow } from "./helpers.ts";

const policy = loadPolicy({
  version: 1,
  default: "deny",
  rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
});

const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

function revokeLine(dir: string, row: Record<string, unknown>): void {
  appendFileSync(join(dir, "revoked-jti.jsonl"), `${JSON.stringify(row)}\n`, "utf8");
}

function inputsFor(dir: string, ref: string): DecisionInputs {
  let found: DecisionInputs | undefined;
  for (const line of readFileSync(join(dir, "inputs.jsonl"), "utf8").split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: DecisionInputs };
    if (row.ref === ref && row.inputs) found = row.inputs;
  }
  if (!found) throw new Error(`inputs-missing:${ref}`);
  return found;
}

function open(dir: string, ledger = new FileLedger(dir)) {
  let n = 0;
  const proxy = createProxy({
    policy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(1_700_000_000_000, 10),
    nonce: () => `${dir.length}-${Date.now()}-${++n}`,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  return { ledger, proxy };
}

async function revokes(ledger: FileLedger, dir: string) {
  const out: Array<{ reason: string; decision: string; jti: string; action: string; by: string; via: string }> = [];
  for (const d of await ledger.decisions()) {
    if (d.claims.subject !== "verax.revoke") continue;
    const row = inputsFor(dir, d.claims.ref ?? "").revoke;
    assert.ok(row);
    out.push({ reason: d.claims.reasonCode, decision: d.claims.decision, jti: row.jti, action: row.action, by: row.by, via: row.via });
  }
  return out;
}

describe("token revocations in the ledger", () => {
  it("R1 a revoked jti becomes one signed deny that names who revoked it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r1-"));
    revokeLine(dir, { jti: "leaked-1", by: "operator-7", atMs: 1_700_000_000_500 });
    const { ledger, proxy } = open(dir);
    try {
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.deepEqual(await revokes(ledger, dir), [
        { reason: "token-revoked", decision: "deny", jti: "leaked-1", action: "revoke", by: "operator-7", via: "http" },
      ]);
      const record = (await ledger.decisions()).find((d) => d.claims.subject === "verax.revoke");
      assert.equal(record?.claims.effectClass, "verax.control");
      assert.equal(record?.claims.effectHash, null);
      assert.equal(record?.claims.timestampMs, 1_700_000_000_500);
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, verified.problems.join("\n"));
  });

  it("R2 a reopened body does not record the same revocation twice", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r2-"));
    revokeLine(dir, { jti: "j-1" });
    const first = open(dir);
    await first.proxy.syncControlRecords();
    first.ledger.close();
    const second = open(dir);
    try {
      await second.proxy.syncControlRecords();
      await second.proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      const rows = await revokes(second.ledger, dir);
      assert.equal(rows.length, 1);
      assert.equal(rows[0]?.by, "unknown");
      assert.equal(rows[0]?.via, "file");
    } finally {
      second.ledger.close();
    }
  });

  it("R3 a line removed by hand is recorded as revoke-removed, and a revoke again after it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r3-"));
    revokeLine(dir, { jti: "keep" });
    revokeLine(dir, { jti: "lifted" });
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      writeFileSync(join(dir, "revoked-jti.jsonl"), `${JSON.stringify({ jti: "keep" })}\n`, "utf8");
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      revokeLine(dir, { jti: "lifted", by: "operator-2" });
      await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.deepEqual(
        (await revokes(ledger, dir)).map((row) => [row.reason, row.jti]),
        [
          ["token-revoked", "keep"],
          ["token-revoked", "lifted"],
          ["revoke-removed", "lifted"],
          ["token-revoked", "lifted"],
        ],
      );
    } finally {
      ledger.close();
    }
  });

  it("R7 a reopened body replays a removal and does not record it again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r7-"));
    revokeLine(dir, { jti: "gone" });
    const first = open(dir);
    await first.proxy.syncControlRecords();
    writeFileSync(join(dir, "revoked-jti.jsonl"), "", "utf8");
    await first.proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
    first.ledger.close();
    const second = open(dir);
    try {
      await second.proxy.syncControlRecords();
      revokeLine(dir, { jti: "gone", by: "operator-9" });
      await second.proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.deepEqual(
        (await revokes(second.ledger, dir)).map((row) => [row.reason, row.by]),
        [
          ["token-revoked", "unknown"],
          ["revoke-removed", "unknown"],
          ["token-revoked", "operator-9"],
        ],
      );
    } finally {
      second.ledger.close();
    }
  });

  it("R8 an unreadable revocation list does not make every call read the ledger again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r8-"));
    mkdirSync(join(dir, "revoked-jti.jsonl"));
    const ledger = new FileLedger(dir);
    let reads = 0;
    const counting = new Proxy(ledger, {
      get(target, prop) {
        if (prop === "decisions") {
          return async () => {
            reads += 1;
            return target.decisions();
          };
        }
        const value = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as FileLedger;
    const { proxy } = open(dir, counting);
    try {
      for (let i = 0; i < 10; i += 1) {
        const result = await proxy.call({ name: "memory.get", arguments: { id: `r8-${i}` } }, reader);
        assert.equal(result.isError, false);
      }
      assert.equal(reads, 1);
    } finally {
      ledger.close();
    }
  });

  it("R4 a revocation inside a halt window is not an allow-while-halted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r4-"));
    writeFileSync(join(dir, "halted"), "", "utf8");
    appendFileSync(join(dir, "halt-history.jsonl"), `${JSON.stringify({ action: "halt", atMs: 1000, by: "op", via: "cli" })}\n`, "utf8");
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      revokeLine(dir, { jti: "during-halt", by: "operator-7" });
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.equal((await revokes(ledger, dir)).length, 1);
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, verified.problems.join("\n"));
    assert.equal(verified.control.windows, 1);
  });

  it("R5 lines with no usable jti are not recorded and do not stop the sync", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r5-"));
    appendFileSync(join(dir, "revoked-jti.jsonl"), "{torn\n", "utf8");
    revokeLine(dir, { jti: "" });
    revokeLine(dir, { jti: "x".repeat(257) });
    revokeLine(dir, { jti: "ok-1", by: "y".repeat(300) });
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      assert.deepEqual(
        (await revokes(ledger, dir)).map((row) => [row.jti, row.by]),
        [["ok-1", "unknown"]],
      );
    } finally {
      ledger.close();
    }
  });

  it("R6 twenty calls with a revocation file read decisions once", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-revoke-r6-"));
    revokeLine(dir, { jti: "first" });
    const ledger = new FileLedger(dir);
    let reads = 0;
    const counting = new Proxy(ledger, {
      get(target, prop) {
        if (prop === "decisions") {
          return async () => {
            reads += 1;
            return target.decisions();
          };
        }
        const value = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as FileLedger;
    const { proxy } = open(dir, counting);
    try {
      for (let i = 0; i < 20; i += 1) {
        if (i === 10) revokeLine(dir, { jti: "second" });
        await proxy.call({ name: "memory.get", arguments: { id: `r6-${i}` } }, reader);
      }
      assert.equal(reads, 1);
      assert.deepEqual(
        (await revokes(ledger, dir)).map((row) => row.jti),
        ["first", "second"],
      );
    } finally {
      ledger.close();
    }
  });
});
