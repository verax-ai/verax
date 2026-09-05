import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

  it("EISDIR on unlocks.jsonl leaves the lock and exits 1", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-eisdir-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    mkdirSync(join(dir, "unlocks.jsonl"));
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "unlock", dir], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 1);
    assert.equal(existsSync(join(dir, "ledger.lock")), true);
    assert.match(stderr, /record-failed:EISDIR/);
  });

  it("normal unlock writes removing then removed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-two-"));
    const pid = deadPid();
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid, startedAt: 7 })}\n`,
      { encoding: "utf8" },
    );
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "unlock", dir], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 0);
    assert.equal(existsSync(join(dir, "ledger.lock")), false);
    const lines = readFileSync(join(dir, "unlocks.jsonl"), "utf8")
      .trim()
      .split("\n")
      .filter((l) => l !== "");
    assert.equal(lines.length, 2);
    const first = JSON.parse(lines[0] ?? "{}") as { result?: string; removedPid?: number };
    const second = JSON.parse(lines[1] ?? "{}") as { result?: string; removedPid?: number };
    assert.equal(first.result, "removing");
    assert.equal(second.result, "removed");
    assert.equal(first.removedPid, pid);
    assert.equal(second.removedPid, pid);
  });

  it("unreadable lock stays without --force and clears with it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-unlock-force-"));
    writeFileSync(join(dir, "ledger.lock"), "{not-json\n", { encoding: "utf8" });
    const refused = spawn(process.execPath, ["--experimental-strip-types", cli, "unlock", dir], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let refusedErr = "";
    refused.stderr.on("data", (buf: Buffer) => {
      refusedErr += String(buf);
    });
    const refusedCode = await new Promise<number>((resolve) => {
      refused.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(refusedCode, 1);
    assert.match(refusedErr, /lock-unreadable/);
    assert.equal(existsSync(join(dir, "ledger.lock")), true);

    const forced = spawn(
      process.execPath,
      ["--experimental-strip-types", cli, "unlock", "--force", dir],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const forcedCode = await new Promise<number>((resolve) => {
      forced.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(forcedCode, 0);
    assert.equal(existsSync(join(dir, "ledger.lock")), false);
    const lines = readFileSync(join(dir, "unlocks.jsonl"), "utf8")
      .trim()
      .split("\n")
      .filter((l) => l !== "");
    assert.equal(lines.length, 2);
    const first = JSON.parse(lines[0] ?? "{}") as { result?: string; reason?: string };
    const second = JSON.parse(lines[1] ?? "{}") as { result?: string; reason?: string };
    assert.equal(first.result, "removing");
    assert.equal(second.result, "removed");
    assert.equal(first.reason, "unreadable");
    assert.equal(second.reason, "unreadable");
  });
});
