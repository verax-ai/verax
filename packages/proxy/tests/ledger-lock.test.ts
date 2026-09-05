import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { FileLedger } from "../src/ledger.ts";

const worker = join(dirname(fileURLToPath(import.meta.url)), "lock-open-worker.ts");

function deadPid(): number {
  let pid = 1_000_000;
  while (pid < 1_000_200) {
    try {
      process.kill(pid, 0);
      pid += 1;
    } catch {
      return pid;
    }
  }
  throw new Error("no-dead-pid");
}

type SpawnedOpener = {
  child: ChildProcess;
  firstLine: Promise<string>;
  done: Promise<string>;
};

function spawnOpener(dir: string): SpawnedOpener {
  const child = spawn(process.execPath, ["--experimental-strip-types", worker], {
    env: { ...process.env, VERAX_LOCK_DIR: dir },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let out = "";
  let firstSettled = false;
  let firstResolve: ((line: string) => void) | undefined;
  const firstLine = new Promise<string>((resolve, reject) => {
    firstResolve = resolve;
    child.on("error", reject);
  });
  const feed = (chunk: Buffer | string) => {
    out += String(chunk);
    if (firstSettled) return;
    const nl = out.search(/\r?\n/);
    if (nl >= 0) {
      firstSettled = true;
      firstResolve?.(out.slice(0, nl));
    }
  };
  child.stdout.on("data", feed);
  child.stderr.on("data", feed);
  const done = new Promise<string>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", () => {
      if (!firstSettled) {
        firstSettled = true;
        firstResolve?.(out.trim().split(/\r?\n/)[0] ?? "");
      }
      resolve(out.trim());
    });
  });
  return { child, firstLine, done };
}

describe("D FileLedger directory lock", () => {
  it("a second FileLedger on the same dir throws ledger-locked", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-lock-"));
    const first = new FileLedger(dir);
    assert.throws(() => new FileLedger(dir), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, new RegExp(`^ledger-locked:${process.pid}$`));
      return true;
    });
    first.close();
    const again = new FileLedger(dir);
    again.close();
  });

  it("1: a dead-pid lock is refused as ledger-locked-stale", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dead-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    assert.throws(() => new FileLedger(dir), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, new RegExp(`^ledger-locked-stale:${pid}\\b`));
      assert.match(err.message, /run: verax unlock /);
      return true;
    });
  });

  it("3: after a manual unlock the old owner cannot append or close the new lock", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-lost-"));
    const lock = join(dir, "ledger.lock");
    const first = new FileLedger(dir);
    unlinkSync(lock);
    const second = new FileLedger(dir);
    let appendCode = "";
    try {
      await first.appendEffect({
        ref: "lost-1",
        effectHash: "00",
        effectClass: "probe",
        timestampMs: 1,
      });
    } catch (err) {
      appendCode = err instanceof Error ? err.message : "unknown";
    }
    assert.equal(appendCode, "ledger-lost-lock");
    first.close();
    assert.equal(existsSync(lock), true, "old owner close() removed the new lock");
    second.close();
  });

  it("1: two spawned bodies on the same dir leave one writer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-two-"));
    const first = spawnOpener(dir);
    const openedLine = await first.firstLine;
    assert.match(openedLine, /^OPENED:/);
    const second = spawnOpener(dir);
    const secondLine = await second.firstLine;
    assert.match(secondLine, /^ERR:ledger-locked:/);
    first.child.stdin?.end();
    const lines = (await Promise.all([first.done, second.done])).map((s) => s.split(/\r?\n/)[0] ?? "");
    const opened = lines.filter((l) => l.startsWith("OPENED:"));
    const locked = lines.filter((l) => l.startsWith("ERR:ledger-locked:"));
    assert.deepEqual({ opened: opened.length, locked: locked.length }, { opened: 1, locked: 1 });
  });
});
