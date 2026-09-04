import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { FileLedger } from "@verax-ai/proxy";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

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

describe("2 verax unlock CLI", () => {
  it("spawned unlock then FileLedger opens", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-cli-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "unlock", dir], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 0);
    const ledger = new FileLedger(dir);
    ledger.close();
  });
});
