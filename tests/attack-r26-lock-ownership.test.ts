import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { FileLedger, lockHolderAlive } from "@verax-ai/proxy";

import { runUnlock } from "../packages/body/src/unlock.ts";
import { watchLock } from "../packages/proxy/src/ledger.ts";

/**
 * R26 (E-1, E-2). Who holds `ledger.lock` used to be read from a pid and a
 * wall clock. Two states defeated that:
 *
 * - A lock naming this pid with a start time in the future (a container
 *   restarted as PID 1 after its clock stepped back) was read as this
 *   process's own: the body answered `ledger-locked` and `verax unlock`
 *   answered `still-running`, with nothing left but deleting the file by hand.
 * - Two containers on one volume both run the body as PID 1. The second one
 *   read the first one's lock as a leftover of its own pid, told the operator
 *   to run `verax unlock`, and unlock removed the lock of a running body.
 *
 * A held lock is now touched every two seconds and a reader watches it move.
 * A lock from a version that did not beat is still judged by its pid.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const proxyUrl = pathToFileURL(join(root, "packages", "proxy", "src", "index.ts")).href;
const unlockUrl = pathToFileURL(join(root, "packages", "body", "src", "unlock.ts")).href;
const HOUR = 60 * 60 * 1000;

const HOLDER = `
const { FileLedger } = await import(process.env.R26_PROXY_URL);
const beat = Number(process.env.R26_BEAT_MS);
const ledger = new FileLedger(process.env.R26_DIR, beat > 0 ? { lockBeatMs: beat } : undefined);
process.stdout.write("held\\n");
setInterval(() => ledger.lockStatus(), 1000);
`;

// A body that is alive and not beating: its event loop is held, as by a long synchronous call.
const FROZEN = `
const { FileLedger } = await import(process.env.R26_PROXY_URL);
new FileLedger(process.env.R26_DIR, { lockBeatMs: Number(process.env.R26_BEAT_MS) });
process.stdout.write("held\\n");
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60000);
`;

// The second container: another process whose pid reads the same as the holder's.
const JUDGE = `
Object.defineProperty(process, "pid", { value: Number(process.env.R26_HOLDER_PID), configurable: true });
const { runUnlock } = await import(process.env.R26_UNLOCK_URL);
let err = "";
const code = runUnlock(process.env.R26_DIR, (s) => { err += s; });
process.stdout.write(JSON.stringify({ code, err, pid: process.pid }) + "\\n");
`;

function temp(): string {
  return mkdtempSync(join(tmpdir(), "verax-r26-lock-"));
}

function run(code: string, env: Record<string, string>): ChildProcess {
  return spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", code], {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function firstLine(child: ChildProcess, ms: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let out = "";
    let errText = "";
    const timer = setTimeout(() => reject(new Error(`no output in ${ms} ms: ${errText}`)), ms);
    child.stderr!.on("data", (c) => {
      errText += String(c);
    });
    child.stdout!.on("data", (c) => {
      out += String(c);
      const at = out.indexOf("\n");
      if (at !== -1) {
        clearTimeout(timer);
        resolve(out.slice(0, at));
      }
    });
    child.on("close", () => {
      clearTimeout(timer);
      if (!out.includes("\n")) reject(new Error(`exited without output: ${errText}`));
    });
  });
}

function ended(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) resolve();
    else child.once("close", () => resolve());
  });
}

function openError(dir: string): string {
  try {
    new FileLedger(dir).close();
    return "opened";
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

function leftover(dir: string, lock: Record<string, unknown>): void {
  writeFileSync(join(dir, "ledger.lock"), `${JSON.stringify(lock)}\n`, "utf8");
}

describe("R26 a lock on this pid that this process did not write", () => {
  it("is not held when its start time has not come yet", () => {
    assert.equal(lockHolderAlive({ pid: process.pid, startedAt: Date.now() + HOUR }), false);
  });

  it("the body names it stale, as it does for a lock from before it started", () => {
    const dir = temp();
    try {
      leftover(dir, { pid: process.pid, startedAt: Date.now() + HOUR, token: "previous-run" });
      assert.match(openError(dir), /^ledger-locked-stale:/, "the body reports the previous run's lock as live");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verax unlock removes it instead of answering still-running for its own pid", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      leftover(dir, { pid: process.pid, startedAt: Date.now() + HOUR, token: "previous-run" });
      const code = runUnlock(dir, (s) => err.push(s));
      assert.equal(code, 0, `unlock refused a lock no live process can hold: ${err.join("").trim()}`);
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a start time that is not a finite number is an unreadable lock, not a live holder", () => {
    const dir = temp();
    const err: string[] = [];
    try {
      // JSON.parse reads 1e999 as Infinity, which passes `typeof === "number"`.
      writeFileSync(join(dir, "ledger.lock"), `{"pid":${process.pid},"startedAt":1e999}\n`, "utf8");
      assert.equal(runUnlock(dir, (s) => err.push(s)), 1);
      assert.equal(err.join("").trim(), "lock-unreadable");
      assert.equal(lockHolderAlive({ pid: process.pid, startedAt: Infinity }), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a second ledger opened by this same process is still refused as locked, not stale", () => {
    const dir = temp();
    const first = new FileLedger(dir);
    try {
      assert.match(openError(dir), /^ledger-locked:\d+$/);
    } finally {
      first.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("R26 a held lock beats", { timeout: 120_000 }, () => {
  it("records its beat and is touched while the ledger is open", async () => {
    const dir = temp();
    const ledger = new FileLedger(dir, { lockBeatMs: 40 });
    try {
      const lockPath = join(dir, "ledger.lock");
      assert.equal(JSON.parse(readFileSync(lockPath, "utf8")).beatMs, 40);
      const before = statSync(lockPath).mtimeMs;
      await new Promise((r) => setTimeout(r, 400));
      assert.notEqual(statSync(lockPath).mtimeMs, before, "the open ledger did not touch its lock");
      ledger.recordListenPort(4242);
      assert.equal(JSON.parse(readFileSync(lockPath, "utf8")).beatMs, 40, "recording the port dropped the beat");
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a watcher reads a file nobody touches as still, and a missing one as gone", () => {
    const dir = temp();
    try {
      const lockPath = join(dir, "ledger.lock");
      leftover(dir, { pid: 1, startedAt: 1, beatMs: 20 });
      assert.equal(watchLock(lockPath, 20), "still");
      assert.equal(watchLock(join(dir, "absent.lock"), 20), "gone");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verax unlock does not remove the lock of a body running under the same pid elsewhere", async () => {
    const dir = temp();
    const holder = run(HOLDER, { R26_PROXY_URL: proxyUrl, R26_DIR: dir, R26_BEAT_MS: "100" });
    try {
      assert.equal(await firstLine(holder, 30_000), "held");
      const judge = run(JUDGE, { R26_UNLOCK_URL: unlockUrl, R26_DIR: dir, R26_HOLDER_PID: String(holder.pid) });
      const answer = JSON.parse(await firstLine(judge, 30_000)) as { code: number; err: string; pid: number };
      assert.equal(answer.pid, holder.pid, "the judge kept its own pid; the run proves nothing");
      assert.equal(holder.exitCode, null, "the holder exited before the check; the run proves nothing");
      assert.equal(existsSync(join(dir, "ledger.lock")), true, `unlock removed the lock of a live body (exit ${answer.code}, "${answer.err.trim()}")`);
      assert.equal(answer.code, 1);
      assert.match(answer.err, /^still-running:/);
    } finally {
      holder.kill();
      await ended(holder);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a second body is told the ledger is locked, not sent to verax unlock, while the first one runs", async () => {
    const dir = temp();
    const holder = run(HOLDER, { R26_PROXY_URL: proxyUrl, R26_DIR: dir, R26_BEAT_MS: "100" });
    try {
      assert.equal(await firstLine(holder, 30_000), "held");
      assert.match(openError(dir), /^ledger-locked:\d+$/);
    } finally {
      holder.kill();
      await ended(holder);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a live holder that has stopped beating keeps its lock: stillness alone does not make it stale", async () => {
    const dir = temp();
    const holder = run(FROZEN, { R26_PROXY_URL: proxyUrl, R26_DIR: dir, R26_BEAT_MS: "100" });
    try {
      assert.equal(await firstLine(holder, 30_000), "held");
      const err: string[] = [];
      const code = runUnlock(dir, (s) => err.push(s));
      assert.equal(holder.exitCode, null, "the holder exited before the check; the run proves nothing");
      assert.equal(existsSync(join(dir, "ledger.lock")), true, "unlock removed the lock of a live process that had only stopped beating");
      assert.equal(code, 1);
      assert.equal(err.join("").trim(), `still-running:${holder.pid}`);
      assert.match(openError(dir), /^ledger-locked:\d+$/);
    } finally {
      holder.kill("SIGKILL");
      await ended(holder);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("once the holder is killed the lock stops moving: the body names it stale and unlock removes it", async () => {
    const dir = temp();
    const holder = run(HOLDER, { R26_PROXY_URL: proxyUrl, R26_DIR: dir, R26_BEAT_MS: "100" });
    try {
      assert.equal(await firstLine(holder, 30_000), "held");
      holder.kill("SIGKILL");
      await ended(holder);
      assert.equal(existsSync(join(dir, "ledger.lock")), true, "a killed holder cannot have removed its lock");
      assert.match(openError(dir), /^ledger-locked-stale:/);
      const err: string[] = [];
      assert.equal(runUnlock(dir, (s) => err.push(s)), 0, err.join("").trim());
      assert.equal(existsSync(join(dir, "ledger.lock")), false);
      assert.equal(openError(dir), "opened");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
