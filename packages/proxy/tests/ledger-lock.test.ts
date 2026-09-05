import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
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

function spawnOpener(dir: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", worker], {
      env: { ...process.env, VERAX_LOCK_DIR: dir },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.on("data", (chunk) => {
      out += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      out += String(chunk);
    });
    child.on("error", reject);
    child.on("close", () => resolve(out.trim()));
  });
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
    const started = Date.now();
    while (Date.now() - started < 5000 && !existsSync(join(dir, "ledger.lock"))) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const second = spawnOpener(dir);
    const lines = (await Promise.all([first, second])).map((s) => s.split("\n")[0] ?? "");
    const opened = lines.filter((l) => l.startsWith("OPENED:"));
    const locked = lines.filter((l) => l.startsWith("ERR:ledger-locked:"));
    assert.deepEqual({ opened: opened.length, locked: locked.length }, { opened: 1, locked: 1 });
  });
});
