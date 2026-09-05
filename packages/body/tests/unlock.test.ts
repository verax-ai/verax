import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger } from "@verax-ai/proxy";
import { runUnlock } from "../src/unlock.ts";

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

describe("2 verax unlock", () => {
  it("removes a dead-pid lock and appends unlocks.jsonl", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-dead-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 11 })}\n`,
      { encoding: "utf8" },
    );
    const code = runUnlock(dir);
    assert.equal(code, 0);
    assert.equal(existsSync(join(dir, "ledger.lock")), false);
    const lines = readFileSync(join(dir, "unlocks.jsonl"), "utf8")
      .trim()
      .split("\n")
      .filter((l) => l !== "");
    assert.equal(lines.length, 2);
    const first = JSON.parse(lines[0] ?? "{}") as {
      atMs?: number;
      removedPid?: number;
      startedAt?: number;
      operator?: string;
      result?: string;
    };
    const second = JSON.parse(lines[1] ?? "{}") as { result?: string; removedPid?: number };
    assert.equal(first.result, "removing");
    assert.equal(second.result, "removed");
    assert.equal(first.removedPid, pid);
    assert.equal(second.removedPid, pid);
    assert.equal(first.startedAt, 11);
    assert.equal(typeof first.atMs, "number");
    assert.equal(typeof first.operator, "string");
    assert.equal((first.operator ?? "").length > 0, true);
  });

  it("refuses a live-pid lock and leaves the file", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-live-"));
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 22 })}\n`,
      { encoding: "utf8" },
    );
    const code = runUnlock(dir);
    assert.equal(code, 1);
    assert.equal(existsSync(join(dir, "ledger.lock")), true);
  });

  it("2: after unlock a FileLedger can open", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-open-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    assert.equal(runUnlock(dir), 0);
    const ledger = new FileLedger(dir);
    ledger.close();
  });
});
