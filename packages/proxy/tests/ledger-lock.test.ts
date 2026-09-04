import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { FileLedger } from "../src/ledger.ts";

const worker = join(dirname(fileURLToPath(import.meta.url)), "lock-takeover-worker.ts");

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

  it("1: two concurrent stale takeovers leave exactly one writer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-takeover-"));
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: deadPid(), startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const run = (yieldMs: string): Promise<string> =>
      new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ["--experimental-strip-types", worker], {
          env: { ...process.env, VERAX_LOCK_DIR: dir, VERAX_LOCK_YIELD_MS: yieldMs },
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
    const pending = [run("0"), run("80")];
    const started = Date.now();
    while (Date.now() - started < 5000) {
      const ready = readdirSync(dir).filter((n) => n.startsWith("ready-"));
      if (ready.length >= 2) break;
    }
    assert.equal(readdirSync(dir).filter((n) => n.startsWith("ready-")).length >= 2, true, "both workers ready");
    writeFileSync(join(dir, "GO"), "1\n");
    const lines = (await Promise.all(pending)).map((s) => s.split("\n")[0] ?? "");
    const opened = lines.filter((l) => l === "OPENED");
    const locked = lines.filter((l) => l.startsWith("ERR:ledger-locked:"));
    assert.deepEqual(
      { opened: opened.length, locked: locked.length, lines },
      { opened: 1, locked: 1, lines },
    );
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
