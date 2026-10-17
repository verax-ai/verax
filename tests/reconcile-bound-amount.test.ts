import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { sha256Canonical } from "../packages/proxy/src/hash.ts";
import { refusedAsElevated } from "./elevated-refusal.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

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

// The approved request: 10.00 TRY. Its hash is what the defer and the allow
// records carry. The approvals file is not signed; a row in it may say anything.
const approvedArgs = { amountMinor: 1_000, currency: "TRY", payee: "ads-platform", reference: "verax:d1" };
const approvedHash = sha256Canonical({ name: "spend", arguments: approvedArgs });

function stateWith(rowArgs: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-reconcile-bound-"));
  writeFileSync(
    join(dir, "effects.jsonl"),
    `${JSON.stringify({
      row: {
        ref: "a1",
        effectHash: "11".repeat(32),
        effectClass: "spend",
        timestampMs: Date.UTC(2026, 9, 17, 9),
      },
      witnessClass: "self",
    })}\n`,
    "utf8",
  );
  writeFileSync(
    join(dir, "decisions.jsonl"),
    [
      { claims: { ref: "d1", decision: "defer", subject: "spend", requestHash: approvedHash } },
      { claims: { ref: "a1", decision: "allow", subject: "spend", requestHash: approvedHash } },
    ]
      .map((r) => JSON.stringify(r))
      .join("\n") + "\n",
    "utf8",
  );
  writeFileSync(
    join(dir, "approvals.jsonl"),
    `${JSON.stringify({
      ref: "d1",
      // A row edited after the approval keeps the hash it had and changes the arguments.
      requestHash: approvedHash,
      subject: "spend",
      args: rowArgs,
      ruleId: "spend-true",
      ruleText: "Spends need operator approval.",
      inputsSummary: { count: 0, ids: [] },
      createdAtMs: Date.UTC(2026, 9, 17, 8),
      expiresAtMs: Date.UTC(2026, 9, 18, 8),
      status: "approved",
      brain: "brain-1",
      allowRef: "a1",
    })}\n`,
    "utf8",
  );
  return dir;
}

function card(dir: string, major: string): string {
  const csv = join(dir, "card.csv");
  writeFileSync(csv, `Tarih;Açıklama;Tutar\n17.10.2026;ADS PLATFORM verax:d1;-${major}\n`, "utf8");
  return csv;
}

async function run(dir: string, csv: string) {
  const out = join(dir, "report.json");
  const ran = await spawnCli(["reconcile", dir, csv, "--channel", "card", "--currency", "TRY", "--out", out]);
  return { ran, out };
}

describe("card reconcile reads an amount only from a queue row that hashes to the approved request", () => {
  it("an untouched row: the 10.00 charge matches", async () => {
    const dir = stateWith(approvedArgs);
    const { ran } = await run(dir, card(dir, "10,00"));
    if (refusedAsElevated(ran.code, ran.err)) return;
    assert.equal(ran.code, 0, ran.err);
    assert.match(ran.err, /matched 1/);
  });

  it("a row edited to 50.00 after approval does not make a 50.00 charge match", async () => {
    const dir = stateWith({ ...approvedArgs, amountMinor: 5_000 });
    const { ran, out } = await run(dir, card(dir, "50,00"));
    if (refusedAsElevated(ran.code, ran.err)) return;
    assert.equal(ran.code, 0, ran.err);
    assert.match(ran.err, /matched 0/);
    assert.match(ran.err, /unknown 1/);
    const report = JSON.parse(readFileSync(out, "utf8")) as { ghost: { reason?: string }[] };
    assert.equal(report.ghost[0]?.reason, "amount-unknown");
  });

  it("a row edited to 50.00 does not turn the real 10.00 charge into a mismatch", async () => {
    const dir = stateWith({ ...approvedArgs, amountMinor: 5_000 });
    const { ran } = await run(dir, card(dir, "10,00"));
    if (refusedAsElevated(ran.code, ran.err)) return;
    assert.equal(ran.code, 0, ran.err);
    assert.match(ran.err, /mismatch 0/);
    assert.match(ran.err, /unknown 1/);
  });

  it("a row whose payee was edited is not read, even when its amount is right", async () => {
    const dir = stateWith({ ...approvedArgs, payee: "other-shop" });
    const { ran } = await run(dir, card(dir, "10,00"));
    if (refusedAsElevated(ran.code, ran.err)) return;
    assert.equal(ran.code, 0, ran.err);
    assert.match(ran.err, /matched 0/);
  });
});
