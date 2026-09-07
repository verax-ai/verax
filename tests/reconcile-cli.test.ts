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

  it("--tz-offset places a printed time on the clock; without it the row stays a day row", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reconcile-tz-"));
    const csv = join(dir, "card.csv");
    writeFileSync(csv, "Tarih;Açıklama;Tutar\n06.09.2026 14:30;ADS PLATFORM;-10,00\n", "utf8");
    writeFileSync(
      join(dir, "effects.jsonl"),
      `${JSON.stringify({
        row: {
          ref: "a1",
          effectHash: "11".repeat(32),
          effectClass: "spend",
          timestampMs: Date.UTC(2026, 8, 6, 11, 30, 20), // 14:30 in Istanbul
        },
        witnessClass: "self",
      })}\n`,
      "utf8",
    );
    writeFileSync(
      join(dir, "approvals.jsonl"),
      `${JSON.stringify({
        ref: "d1",
        requestHash: "00".repeat(32),
        subject: "spend",
        args: { amountMinor: 1_000, currency: "TRY", payee: "ads-platform", reference: "verax:d1" },
        ruleId: "spend-true",
        ruleText: "Spends need operator approval.",
        inputsSummary: { count: 0, ids: [] },
        amount: 1_000,
        payee: "ads-platform",
        currency: "TRY",
        createdAtMs: Date.UTC(2026, 8, 6, 11),
        expiresAtMs: Date.UTC(2026, 8, 7, 11),
        status: "approved",
        brain: "brain-1",
        allowRef: "a1",
      })}\n`,
      "utf8",
    );
    const out = join(dir, "report.json");
    const withOffset = await spawnCli([
      "reconcile",
      dir,
      csv,
      "--channel",
      "card",
      "--currency",
      "TRY",
      "--tz-offset",
      "180",
      "--out",
      out,
    ]);
    assert.equal(withOffset.code, 0, withOffset.err);
    assert.match(withOffset.err, /matched 1/);
    const report = JSON.parse(readFileSync(out, "utf8")) as {
      matched: { datePrecision?: string; toleranceMs?: number }[];
    };
    assert.equal(report.matched[0]?.datePrecision, "minute");
    assert.equal(report.matched[0]?.toleranceMs, 120_000);

    const naive = await spawnCli([
      "reconcile",
      dir,
      csv,
      "--channel",
      "card",
      "--currency",
      "TRY",
      "--out",
      out,
    ]);
    assert.equal(naive.code, 0, naive.err);
    assert.match(naive.err, /matched 1/);
    const dayReport = JSON.parse(readFileSync(out, "utf8")) as { matched: { datePrecision?: string }[] };
    assert.equal(dayReport.matched[0]?.datePrecision, "day");
  });

  it("a tz offset outside a day is refused", async () => {
    const ran = await spawnCli(["reconcile", stateDir, channel, "--tz-offset", "2000", "--out", "x.json"]);
    assert.equal(ran.code, 78);
    assert.match(ran.err, /tz-offset-invalid/);
  });
});
