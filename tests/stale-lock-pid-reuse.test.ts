import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger, lockHolderAlive } from "@verax-ai/proxy";

import { clearStaleLockAtStart, runUnlock } from "../packages/body/src/unlock.ts";

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

/**
 * Windows ends a service without giving it time to remove its lock, and a service manager
 * restarts it with nobody at the keyboard. The start clears only a lock `verax unlock` would clear.
 */
describe("a service start and the lock it finds", () => {
  it("removes a lock whose holder is gone and records it", () => {
    const dir = temp();
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000 });
      clearStaleLockAtStart(dir, () => undefined);
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
      assert.match(readFileSync(join(dir, "unlocks.jsonl"), "utf8"), /"result":"removed"/);
      assert.equal(openError(dir), "opened");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps a new lock another start took while this one was judging the old lock", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      const code = runUnlock(dir, (s) => err.push(s), {
        afterJudge: () => writeLock(dir, { pid: process.ppid, startedAt: Date.now(), token: "new" }),
      });
      assert.equal(code, 1);
      assert.match(err.join(""), /^lock-changed/);
      assert.match(readFileSync(join(dir, "ledger.lock"), "utf8"), /"token":"new"/);
      assert.deepEqual(readdirSync(dir).filter((name) => name.startsWith("ledger.lock.")), []);
      const rows = readFileSync(join(dir, "unlocks.jsonl"), "utf8");
      assert.match(rows, /"result":"lock-changed"/);
      assert.doesNotMatch(rows, /"result":"removed"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not touch a new lock it can already see differs from the one it judged", () => {
    const dir = temp();
    const moved: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      const code = runUnlock(dir, () => undefined, {
        afterJudge: () => writeLock(dir, { pid: process.ppid, startedAt: Date.now(), token: "new" }),
        beforeMove: () => moved.push("moved"),
      });
      assert.equal(code, 1);
      assert.deepEqual(moved, []);
      assert.match(readFileSync(join(dir, "ledger.lock"), "utf8"), /"token":"new"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("puts back a new lock that appeared in the last moment before the move", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      const code = runUnlock(dir, (s) => err.push(s), {
        beforeMove: () => writeLock(dir, { pid: process.ppid, startedAt: Date.now(), token: "new" }),
      });
      assert.equal(code, 1);
      assert.match(err.join(""), /^lock-changed/);
      assert.match(readFileSync(join(dir, "ledger.lock"), "utf8"), /"token":"new"/);
      assert.deepEqual(readdirSync(dir).filter((name) => name.startsWith("ledger.lock.")), []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leaves a lock that became unreadable after it was judged", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      const lock = join(dir, "ledger.lock");
      const code = runUnlock(dir, (s) => err.push(s), {
        afterJudge: () => {
          rmSync(lock);
          mkdirSync(lock);
        },
      });
      assert.equal(code, 1);
      assert.match(err.join(""), /^lock-changed/);
      assert.equal(existsSync(lock), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not remove a lock it could not read at all, even when forced", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      mkdirSync(join(dir, "ledger.lock"));
      assert.equal(runUnlock(dir, (s) => err.push(s), { force: true }), 1);
      assert.match(err.join(""), /^lock-unreadable/);
      assert.equal(existsSync(join(dir, "ledger.lock")), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports no removal when another start removed the lock first", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      const code = runUnlock(dir, (s) => err.push(s), { afterJudge: () => rmSync(join(dir, "ledger.lock")) });
      assert.equal(code, 1);
      assert.match(err.join(""), /^no-lock/);
      assert.doesNotMatch(readFileSync(join(dir, "unlocks.jsonl"), "utf8"), /"result":"removed"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("puts the judged lock back when it cannot be removed", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      writeLock(dir, { pid: process.pid, startedAt: performance.timeOrigin - 60_000, token: "old" });
      const refuse = (): void => {
        throw Object.assign(new Error("refused"), { code: "EPERM" });
      };
      assert.equal(runUnlock(dir, (s) => err.push(s), { unlink: refuse }), 1);
      assert.match(err.join(""), /^unlink-failed:EPERM/);
      assert.match(readFileSync(join(dir, "ledger.lock"), "utf8"), /"token":"old"/);
      assert.deepEqual(readdirSync(dir).filter((name) => name.startsWith("ledger.lock.")), []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("removes a still lock whose pid another process now has, and records why", () => {
    const dir = temp();
    try {
      writeLock(dir, { pid: process.ppid, startedAt: Date.now() - 1000, beatMs: 20, token: "before-the-reboot" });
      clearStaleLockAtStart(dir, () => undefined);
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
      const rows = readFileSync(join(dir, "unlocks.jsonl"), "utf8");
      assert.match(rows, /"reason":"not-beating"/);
      assert.match(rows, /"result":"removed"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("removes a lock a power loss left unreadable, and records why", () => {
    const dir = temp();
    try {
      writeFileSync(join(dir, "ledger.lock"), "{", "utf8");
      clearStaleLockAtStart(dir, () => undefined);
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
      assert.match(readFileSync(join(dir, "unlocks.jsonl"), "utf8"), /"reason":"unreadable"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("says nothing and records nothing when there is no lock", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      clearStaleLockAtStart(dir, (s) => err.push(s));
      assert.deepEqual(err, []);
      assert.equal(existsSync(join(dir, "unlocks.jsonl")), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leaves the lock of a live holder, and the body still refuses to open", () => {
    const dir = temp();
    try {
      writeLock(dir, { pid: process.ppid, startedAt: 1 });
      clearStaleLockAtStart(dir, () => undefined);
      assert.equal(existsSync(join(dir, "ledger.lock")), true);
      assert.match(openError(dir), /^ledger-locked:/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
