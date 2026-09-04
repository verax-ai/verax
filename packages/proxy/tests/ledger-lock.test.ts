import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { FileLedger } from "../src/ledger.ts";

const worker = join(dirname(fileURLToPath(import.meta.url)), "lock-takeover-worker.ts");
const epermHolder = join(dirname(fileURLToPath(import.meta.url)), "lock-eperm-holder.ts");

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

  it("a stale lock from a dead pid is replaced", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-stale-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const ledger = new FileLedger(dir);
    ledger.close();
  });

  async function raceTakeover(workers: number): Promise<{ opened: number; locked: number; lines: string[] }> {
    const dir = mkdtempSync(join(tmpdir(), "verax-takeover-"));
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: deadPid(), startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const pending = Array.from(
      { length: workers },
      () =>
        new Promise<string>((resolve, reject) => {
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
        }),
    );
    const started = Date.now();
    while (Date.now() - started < 15000) {
      if (readdirSync(dir).filter((n) => n.startsWith("ready-")).length >= workers) break;
    }
    assert.equal(
      readdirSync(dir).filter((n) => n.startsWith("ready-")).length >= workers,
      true,
      `expected ${workers} ready workers`,
    );
    writeFileSync(join(dir, "GO"), "1\n");
    const lines = (await Promise.all(pending)).map((s) => s.split("\n")[0] ?? "");
    return {
      opened: lines.filter((l) => l === "OPENED").length,
      locked: lines.filter((l) => l.startsWith("ERR:ledger-locked:")).length,
      lines,
    };
  }

  it("1: eight concurrent stale takeovers leave exactly one writer", { timeout: 120000 }, async () => {
    const trials: Array<{ opened: number; locked: number; lines: string[] }> = [];
    const forked: number[] = [];
    for (let i = 0; i < 20; i += 1) {
      const result = await raceTakeover(8);
      trials.push(result);
      if (result.opened >= 2) forked.push(i);
    }
    assert.equal(forked.length, 0, `forked trials ${JSON.stringify(forked)} results=${JSON.stringify(trials)}`);
    for (const result of trials) {
      assert.deepEqual({ opened: result.opened, locked: result.locked }, { opened: 1, locked: 7 });
    }
  });

  it("2: a live pid with mtime older than 30s is taken over", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-mtime-"));
    const lock = join(dir, "ledger.lock");
    writeFileSync(lock, `${JSON.stringify({ pid: process.pid, startedAt: Date.now() })}\n`, {
      encoding: "utf8",
    });
    const aged = (Date.now() - 60_000) / 1000;
    utimesSync(lock, aged, aged);
    const ledger = new FileLedger(dir);
    ledger.close();
  });

  it("2: a paused owner does not delete a taken-over lock", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-owner-"));
    const lock = join(dir, "ledger.lock");
    const first = new FileLedger(dir);
    const aged = (Date.now() - 60_000) / 1000;
    utimesSync(lock, aged, aged);
    const second = new FileLedger(dir);
    first.close();
    assert.equal(existsSync(lock), true, "taken-over lock was removed by the old owner");
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
    second.close();
  });

  it("3: rename retries while another process holds the stale lock", { timeout: 10000 }, async () => {
    if (process.platform !== "win32") {
      assert.equal("not applicable", "not applicable");
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), "verax-eperm-"));
    const lock = join(dir, "ledger.lock");
    const ready = join(dir, "holder-ready");
    writeFileSync(lock, `${JSON.stringify({ pid: deadPid(), startedAt: 1 })}\n`, { encoding: "utf8" });
    const child = spawn(process.execPath, ["--experimental-strip-types", epermHolder], {
      env: { ...process.env, VERAX_LOCK_PATH: lock, VERAX_READY_PATH: ready },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const started = Date.now();
    while (Date.now() - started < 5000 && !existsSync(ready)) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(existsSync(ready), true, "holder did not open the stale lock");
    let opened = false;
    let errMessage = "";
    try {
      const ledger = new FileLedger(dir);
      opened = true;
      ledger.close();
    } catch (err) {
      errMessage = err instanceof Error ? err.message : "unknown";
    }
    child.kill();
    assert.equal(opened, true, errMessage);
  });

  it("2: heartbeat is unrefed and close() stops it", async () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "ledger.ts"), "utf8");
    assert.equal(src.includes(".unref()"), true);
    const dir = mkdtempSync(join(tmpdir(), "verax-hb-"));
    const ledger = new FileLedger(dir);
    ledger.close();
    const lock = join(dir, "ledger.lock");
    writeFileSync(lock, `${JSON.stringify({ pid: 1, startedAt: 1 })}\n`, { encoding: "utf8" });
    const t0 = statSync(lock).mtimeMs;
    await new Promise((resolve) => setTimeout(resolve, 5500));
    const t1 = statSync(lock).mtimeMs;
    assert.equal(t1, t0, `heartbeat still writing after close (${t0} -> ${t1})`);
  });
});
