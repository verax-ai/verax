// The tail pin: an index that still names a removed decision must not verify,
// and a ledger with no index file is not a failure by itself.

import { strict as assert } from "node:assert";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger } from "@verax-ai/proxy";
import { runVerify } from "../packages/body/src/verify-cli.ts";

const golden = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "tests", "fixtures", "ledger-golden");

function copyGolden(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-verify-tail-"));
  for (const name of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, name), join(dir, name));
  }
  return dir;
}

type DecisionLine = { claims: { ref?: string } };
type EffectLine = {
  row?: { ref?: string };
  receipt?: { body?: { effects?: { ref?: string }[] } };
};

function effectRef(line: string): string | null {
  const parsed = JSON.parse(line) as EffectLine;
  if (typeof parsed.row?.ref === "string") return parsed.row.ref;
  const nested = parsed.receipt?.body?.effects?.find((row) => typeof row.ref === "string");
  return nested?.ref ?? null;
}

describe("verify pins the tail", () => {
  it("a ledger with no index file still verifies", async () => {
    const dir = copyGolden();
    const result = await verifyLedger(dir);
    assert.equal(result.ok, true, JSON.stringify(result.problems));
    assert.equal(result.index.present, false);
    assert.equal(result.index.line, "index: none (cannot check for removed records)");
    assert.match(result.tail.line, /^tail:/);
    const lines: string[] = [];
    const code = await runVerify([dir], (s) => lines.push(s));
    assert.equal(code, 0, lines.join("\n"));
    const text = lines.join("\n");
    assert.match(text, /index: none \(cannot check for removed records\)/);
    assert.match(text, /^tail:/m);
    assert.equal(
      result.problems.some((p) => /index is missing|no index/i.test(p)),
      false,
      JSON.stringify(result.problems),
    );
  });

  it("dropping the last decision and its effect does not verify while the index names it", async () => {
    const dir = copyGolden();
    const decisionPath = join(dir, "decisions.jsonl");
    const effectPath = join(dir, "effects.jsonl");
    const decisions = readFileSync(decisionPath, "utf8").trim().split("\n");
    const effects = readFileSync(effectPath, "utf8").trim().split("\n");
    assert.ok(decisions.length >= 2, "golden ledger is shorter than this test");
    const dropped = JSON.parse(decisions[decisions.length - 1]!) as DecisionLine;
    const ref = dropped.claims.ref;
    assert.equal(typeof ref, "string");
    const indexRefs = decisions.map((line) => (JSON.parse(line) as DecisionLine).claims.ref).filter((r) => typeof r === "string");
    writeFileSync(
      join(dir, "index.jsonl"),
      `${indexRefs.map((named) => JSON.stringify({ ref: named, piece: "legacy" })).join("\n")}\n`,
    );
    decisions.pop();
    const keptEffects = effects.filter((line) => effectRef(line) !== ref);
    assert.ok(keptEffects.length < effects.length, "no effect row matched the dropped decision");
    writeFileSync(decisionPath, `${decisions.join("\n")}\n`);
    writeFileSync(effectPath, `${keptEffects.join("\n")}\n`);

    const result = await verifyLedger(dir);
    assert.equal(result.ok, false, "removed tail still verified");
    assert.match(result.index.line, /^index names \d+ record\(s\) the ledger no longer holds$/);
    assert.match(result.tail.line, /^tail:/);
    const lines: string[] = [];
    const code = await runVerify([dir], (s) => lines.push(s));
    const text = lines.join("\n");
    assert.equal(code, 1, text);
    assert.match(text, /index names \d+ record\(s\) the ledger no longer holds/);
    assert.match(text, /^tail:/m);
    assert.match(text, /NOT VERIFIED/);
  });
});
