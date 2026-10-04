import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const FIRST = "allow-first";
const SECOND = "allow-second";
const DENIED = "deny-third";

/** Two allowed reads and one refused write, written by the proxy as it runs. */
async function ledgerWithTwoAllows(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-dwe-"));
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
      nonce: queuedNonce([FIRST, SECOND, DENIED]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const caller = { brain: "brain-1", scopes: new Set(["verax:read"]) };
    await proxy.call({ name: "memory.get", arguments: { id: "a", _ref: FIRST } }, caller);
    await proxy.call({ name: "memory.get", arguments: { id: "b", _ref: SECOND } }, caller);
    await proxy.call({ name: "memory.put", arguments: { id: "c", _ref: DENIED } }, caller);
  } finally {
    ledger.close();
  }
  return dir;
}

/** Removes the effect row of `ref`, as a writer that crashed after the allow would leave it. */
function dropEffectRow(dir: string, ref: string): void {
  const path = join(dir, "effects.jsonl");
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
  const kept = lines.filter((line) => (JSON.parse(line) as { row?: { ref?: string } }).row?.ref !== ref);
  assert.equal(kept.length, lines.length - 1, `one effect row for ${ref}`);
  writeFileSync(path, kept.map((line) => `${line}\n`).join(""), "utf8");
}

/** Says, as the unsigned index would let anyone say, that `ref` had no effect. */
function indexSaysNoEffect(dir: string, ref: string): void {
  const path = join(dir, "index.jsonl");
  if (!existsSync(path)) return;
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
  const edited = lines
    .map((line) => JSON.parse(line) as { ref?: string; hasEffect?: boolean; kind?: string })
    .filter((row) => !(row.ref === ref && row.kind === "effect"))
    .map((row) => {
      if (row.ref === ref) row.hasEffect = false;
      return JSON.stringify(row);
    });
  writeFileSync(path, edited.map((line) => `${line}\n`).join(""), "utf8");
}

describe("verifyLedger — decision-without-effect", () => {
  it("passes a ledger where every allow has its row and the refusal has none", async () => {
    const dir = await ledgerWithTwoAllows();
    try {
      const result = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.deepEqual(result.effectsDeferred, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("names an allow with no effect row outside the allowance, whatever the index says", async () => {
    const dir = await ledgerWithTwoAllows();
    try {
      dropEffectRow(dir, FIRST);
      indexSaysNoEffect(dir, FIRST);
      const result = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(result.problems.includes(`decision-without-effect ${FIRST}`), JSON.stringify(result.problems));
      assert.ok(!result.problems.some((p) => p.includes(DENIED)), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("defers an allow with no row within the allowance of the newest record", async () => {
    const dir = await ledgerWithTwoAllows();
    try {
      dropEffectRow(dir, SECOND);
      indexSaysNoEffect(dir, SECOND);
      const result = await verifyLedger(dir);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.deepEqual(result.effectsDeferred, [SECOND]);
      assert.ok(!result.problems.some((p) => p.startsWith("decision-without-effect")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
