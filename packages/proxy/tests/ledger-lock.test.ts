import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger } from "../src/ledger.ts";

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
});
