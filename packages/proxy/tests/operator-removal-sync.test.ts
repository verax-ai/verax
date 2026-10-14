import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger } from "../src/ledger.ts";
import { OPERATOR_REMOVED_DIR, operatorRemovalMark } from "../src/operator-removal-sync.ts";
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

// Written out here and not taken from the module: a mark scheme changed there fails here.
const markOf = (id: string) => createHash("sha256").update(id, "utf8").digest("hex");

/** What `verax operator remove` leaves behind: a file named by the hash of the passkey's id. */
function mark(dir: string, id: string): void {
  mkdirSync(join(dir, "operator-removed"), { recursive: true });
  writeFileSync(join(dir, "operator-removed", markOf(id)), `${id}\n`, "utf8");
}

function unmark(dir: string, id: string): void {
  rmSync(join(dir, "operator-removed", markOf(id)));
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

/** A ledger that counts how often its decisions are read whole. */
function counted(dir: string): { ledger: FileLedger; reads: () => number } {
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
  return { ledger: counting, reads: () => reads };
}

async function removals(ledger: FileLedger, dir: string) {
  const out: Array<{ reason: string; decision: string; mark: string; action: string; by: string; via: string }> = [];
  for (const d of await ledger.decisions()) {
    if (d.claims.subject !== "verax.operator") continue;
    const row = inputsFor(dir, d.claims.ref ?? "").operatorRemoval;
    assert.ok(row);
    out.push({ reason: d.claims.reasonCode, decision: d.claims.decision, mark: row.mark, action: row.action, by: row.by, via: row.via });
  }
  return out;
}

describe("passkey removals in the ledger", () => {
  it("O0 the directory and the mark are named in one place, and the mark is the hash of the id", () => {
    assert.equal(OPERATOR_REMOVED_DIR, "operator-removed");
    assert.equal(operatorRemovalMark("passkey-a"), markOf("passkey-a"));
    assert.match(operatorRemovalMark("passkey-a"), /^[0-9a-f]{64}$/);
    assert.notEqual(operatorRemovalMark("passkey-a"), operatorRemovalMark("passkey-b"));
  });

  it("O1 a removed passkey becomes one signed deny that names its mark", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o1-"));
    mark(dir, "passkey-a");
    const { ledger, proxy } = open(dir);
    try {
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.deepEqual(await removals(ledger, dir), [
        { reason: "passkey-removed", decision: "deny", mark: markOf("passkey-a"), action: "remove", by: "unknown", via: "file" },
      ]);
      const record = (await ledger.decisions()).find((d) => d.claims.subject === "verax.operator");
      assert.equal(record?.claims.effectClass, "verax.control");
      assert.equal(record?.claims.effectHash, null);
      assert.equal(record?.claims.decider, "verax-proxy");
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, verified.problems.join("\n"));
  });

  it("O2 a reopened body does not record the same removal twice", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o2-"));
    mark(dir, "passkey-a");
    const first = open(dir);
    await first.proxy.syncControlRecords();
    first.ledger.close();
    const second = open(dir);
    try {
      await second.proxy.syncControlRecords();
      await second.proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.equal((await removals(second.ledger, dir)).length, 1);
    } finally {
      second.ledger.close();
    }
  });

  it("O3 a mark taken away by hand is recorded as undone, and a removal again after it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o3-"));
    mark(dir, "kept");
    mark(dir, "lifted");
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      unmark(dir, "lifted");
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      mark(dir, "lifted");
      await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      const rows = await removals(ledger, dir);
      // The two first removals are found together, in no promised order.
      assert.deepEqual(
        rows.slice(0, 2).map((row) => [row.reason, row.mark]).sort(),
        [
          ["passkey-removed", markOf("kept")],
          ["passkey-removed", markOf("lifted")],
        ].sort(),
      );
      assert.deepEqual(
        rows.slice(2).map((row) => [row.reason, row.action, row.mark]),
        [
          ["passkey-removal-undone", "restore", markOf("lifted")],
          ["passkey-removed", "remove", markOf("lifted")],
        ],
      );
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, verified.problems.join("\n"));
  });

  it("O4 a removal inside a halt window is not an allow-while-halted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o4-"));
    writeFileSync(join(dir, "halted"), "", "utf8");
    appendFileSync(join(dir, "halt-history.jsonl"), `${JSON.stringify({ action: "halt", atMs: 1000, by: "op", via: "cli" })}\n`, "utf8");
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      mark(dir, "during-halt");
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.equal((await removals(ledger, dir)).length, 1);
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, verified.problems.join("\n"));
    assert.equal(verified.control.windows, 1);
  });

  it("O5 a name that is not a mark is not recorded, and a mark is one whatever it is or holds", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o5-"));
    const removed = join(dir, "operator-removed");
    mkdirSync(removed);
    writeFileSync(join(removed, "notes.txt"), "x");
    writeFileSync(join(removed, markOf("upper").toUpperCase()), "x");
    writeFileSync(join(removed, markOf("short").slice(0, 63)), "x");
    writeFileSync(join(removed, `${markOf("long")}0`), "x");
    // The body goes by the name alone, so these two remove a passkey as surely as a mark the CLI wrote.
    writeFileSync(join(removed, markOf("empty")), "");
    mkdirSync(join(removed, markOf("a-directory")));
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      assert.deepEqual(
        (await removals(ledger, dir)).map((row) => row.mark).sort(),
        [markOf("a-directory"), markOf("empty")].sort(),
      );
    } finally {
      ledger.close();
    }
  });

  it("O6 twenty calls with marks read decisions once, and a mark added on the way is recorded", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o6-"));
    mark(dir, "first");
    const { ledger, reads } = counted(dir);
    const { proxy } = open(dir, ledger);
    try {
      for (let i = 0; i < 20; i += 1) {
        if (i === 10) mark(dir, "second");
        await proxy.call({ name: "memory.get", arguments: { id: `o6-${i}` } }, reader);
      }
      assert.equal(reads(), 1);
      assert.deepEqual(
        (await removals(ledger, dir)).map((row) => row.mark),
        [markOf("first"), markOf("second")],
      );
    } finally {
      ledger.close();
    }
  });

  it("O7 a reopened body replays an undone removal and does not record it again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o7-"));
    mark(dir, "gone");
    const first = open(dir);
    await first.proxy.syncControlRecords();
    unmark(dir, "gone");
    await first.proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
    first.ledger.close();
    const second = open(dir);
    try {
      await second.proxy.syncControlRecords();
      await second.proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.deepEqual(
        (await removals(second.ledger, dir)).map((row) => row.reason),
        ["passkey-removed", "passkey-removal-undone"],
      );
      mark(dir, "gone");
      await second.proxy.call({ name: "memory.get", arguments: { id: "c" } }, reader);
      assert.deepEqual(
        (await removals(second.ledger, dir)).map((row) => row.reason),
        ["passkey-removed", "passkey-removal-undone", "passkey-removed"],
      );
    } finally {
      second.ledger.close();
    }
  });

  it("O8 marks that cannot be listed are not read as marks taken away, and do not make every call read the ledger again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o8-"));
    mark(dir, "passkey-a");
    const { ledger, reads } = counted(dir);
    const { proxy } = open(dir, ledger);
    try {
      await proxy.call({ name: "memory.get", arguments: { id: "before" } }, reader);
      assert.equal((await removals(ledger, dir)).length, 1);
      const readsBefore = reads();

      // A file where the directory was. The body leaves no passkey in use then;
      // the ledger must not say the removal was undone, because it was not.
      rmSync(join(dir, "operator-removed"), { recursive: true });
      writeFileSync(join(dir, "operator-removed"), "", "utf8");
      for (let i = 0; i < 10; i += 1) {
        const result = await proxy.call({ name: "memory.get", arguments: { id: `o8-${i}` } }, reader);
        assert.equal(result.isError, false);
      }
      assert.deepEqual((await removals(ledger, dir)).map((row) => row.reason), ["passkey-removed"]);

      // The directory back with the same mark is nothing new either.
      rmSync(join(dir, "operator-removed"));
      mark(dir, "passkey-a");
      await proxy.call({ name: "memory.get", arguments: { id: "after" } }, reader);
      assert.deepEqual((await removals(ledger, dir)).map((row) => row.reason), ["passkey-removed"]);
      // `removals` reads the decisions itself, twice since the count was taken; the proxy must not have read them again at all.
      assert.equal(reads() - readsBefore, 2);
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, verified.problems.join("\n"));
  });

  it("O9 a body opened with marks it cannot list records nothing, and records them once it can", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-removal-o9-"));
    writeFileSync(join(dir, "operator-removed"), "", "utf8");
    const { ledger, proxy } = open(dir);
    try {
      await proxy.syncControlRecords();
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.deepEqual(await removals(ledger, dir), []);
      rmSync(join(dir, "operator-removed"));
      mark(dir, "passkey-a");
      await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.deepEqual((await removals(ledger, dir)).map((row) => row.reason), ["passkey-removed"]);
    } finally {
      ledger.close();
    }
  });
});
