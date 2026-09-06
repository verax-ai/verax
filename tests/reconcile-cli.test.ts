import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const stateDir = join(root, "packages", "proxy", "tests", "fixtures", "ledger-golden");
const channel = join(root, "packages", "proxy", "tests", "fixtures", "channel-sent.jsonl");

function spawnCli(args: string[]): Promise<{ code: number; err: string }> {
  const child = spawn(process.execPath, ["--experimental-strip-types", cli, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let err = "";
  child.stderr.on("data", (c) => {
    err += String(c);
  });
  return new Promise((resolve) => {
    child.on("close", (exit) => resolve({ code: exit ?? 1, err }));
  });
}

describe("verax reconcile CLI", () => {
  it("writes a report with 3 matched, 2 ghost, 1 unsent, 0 outOfScope", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reconcile-cli-"));
    const out = join(dir, "report.json");
    const ran = await spawnCli(["reconcile", stateDir, channel, "--out", out]);
    assert.equal(ran.code, 0, ran.err);
    const report = JSON.parse(readFileSync(out, "utf8")) as {
      matched: unknown[];
      ghost: unknown[];
      unsent: unknown[];
      outOfScope: unknown[];
      scope: { channel: string; windowStartMs: number; windowEndMs: number; rowCount: number };
    };
    assert.deepEqual(report.scope, {
      channel: "sent",
      windowStartMs: 20,
      windowEndMs: 180100,
      rowCount: 5,
    });
    assert.equal(report.matched.length, 3);
    assert.equal(report.ghost.length, 2);
    assert.equal(report.unsent.length, 1);
    assert.equal(report.outOfScope.length, 0);
  });

  it("--window-start/--window-end puts msg-far in outOfScope", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reconcile-win-"));
    const out = join(dir, "report.json");
    const ran = await spawnCli([
      "reconcile",
      stateDir,
      channel,
      "--window-start",
      "20",
      "--window-end",
      "60",
      "--out",
      out,
    ]);
    assert.equal(ran.code, 0, ran.err);
    const report = JSON.parse(readFileSync(out, "utf8")) as {
      ghost: { externalId: string }[];
      outOfScope: { externalId: string }[];
    };
    assert.equal(report.outOfScope.length, 1);
    assert.equal(report.outOfScope[0]?.externalId, "msg-far");
    assert.equal(
      report.ghost.some((g) => g.externalId === "msg-far"),
      false,
    );
  });

  it("usage without --out exits 78", async () => {
    const ran = await spawnCli(["reconcile", stateDir, channel]);
    assert.equal(ran.code, 78);
    assert.match(ran.err, /verax reconcile /);
  });

  it("S2F-1: card stderr names unknown when the snapshot has no amount", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reconcile-unknown-"));
    const csv = join(dir, "card.csv");
    writeFileSync(csv, "Tarih;Açıklama;Tutar\n06.09.2026;UNKNOWN MERCHANT;-10,00\n", "utf8");
    writeFileSync(
      join(dir, "effects.jsonl"),
      `${JSON.stringify({
        row: {
          ref: "probe-x",
          effectHash: "11".repeat(32),
          effectClass: "spend",
          timestampMs: Date.UTC(2026, 8, 6, 12),
        },
        witnessClass: "self",
      })}\n`,
      "utf8",
    );
    const out = join(dir, "report.json");
    const ran = await spawnCli(["reconcile", dir, csv, "--channel", "card", "--currency", "TRY", "--out", out]);
    assert.equal(ran.code, 0, ran.err);
    assert.match(ran.err, /unknown 1/);
    assert.match(ran.err, /matched 0/);
    assert.match(ran.err, /ghost 1/);
  });
});
