import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger, lockHolderAlive } from "@verax-ai/proxy";

import { runUnlock } from "../packages/body/src/unlock.ts";

function temp(): string {
  return mkdtempSync(join(tmpdir(), "verax-stale-lock-"));
}

function writeLock(dir: string, lock: Record<string, unknown>): void {
  writeFileSync(join(dir, "ledger.lock"), `${JSON.stringify(lock)}\n`, "utf8");
}

function openError(dir: string): string {
  try {
    new FileLedger(dir).close();
    return "opened";
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

/**
 * A container restarted on the same volume runs the body as PID 1 again,
 * and so does the old lock. A PID that is alive is not proof the holder is:
 * a lock written before this process started cannot be held by it.
 */
describe("a lock whose pid was reused", () => {
  it("this process's own pid, written before it started, is stale", () => {
    const dir = temp();
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      assert.match(openError(dir), /^ledger-locked-stale:/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("this process's own pid, written after it started, is still held", () => {
    const dir = temp();
    try {
      writeLock(dir, { pid: process.pid, startedAt: Date.now(), token: "same-process" });
      assert.match(openError(dir), /^ledger-locked:/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verax unlock removes a lock that names its own pid", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000 });
      assert.equal(runUnlock(dir, (s) => err.push(s)), 0, err.join(""));
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
      const rows = readFileSync(join(dir, "unlocks.jsonl"), "utf8").trim().split("\n");
      assert.match(rows[rows.length - 1]!, /"result":"removed"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a lock from another boot is stale even when its pid is alive", () => {
    assert.equal(lockHolderAlive({ pid: process.ppid, startedAt: 1, bootId: "another-boot" }, "this-boot"), false);
    assert.equal(lockHolderAlive({ pid: process.ppid, startedAt: 1, bootId: "this-boot" }, "this-boot"), true);
    // Without a boot id on either side the pid decides, as before.
    assert.equal(lockHolderAlive({ pid: process.ppid, startedAt: 1 }, null), true);
  });

  it("a live holder of another pid still refuses unlock", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.ppid, startedAt: 1 });
      assert.equal(runUnlock(dir, (s) => err.push(s)), 1);
      assert.match(err.join(""), /^still-running:/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
