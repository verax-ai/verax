import { strict as assert } from "node:assert";
import { appendFileSync, cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runVerify } from "../packages/body/src/verify-cli.ts";
import { firstStage } from "../test-vectors/tools/stages.ts";

const validFull = join(dirname(fileURLToPath(import.meta.url)), "..", "test-vectors", "v1", "valid-full");

type Report = { ok: boolean; decisions: number; index: { present: boolean }; problems: string[] };

/** valid-full with one line appended to its unsigned index, verified in process. */
async function verifyWithIndexLine(line: string): Promise<Report> {
  const dir = mkdtempSync(join(tmpdir(), "verax-index-line-"));
  try {
    cpSync(validFull, dir, { recursive: true });
    appendFileSync(join(dir, "ledger", "index.jsonl"), `${line}\n`);
    const pins = join(dir, "pins");
    const out: string[] = [];
    await runVerify(
      [
        join(dir, "ledger"),
        "--key", join(pins, "record-key.pem"),
        "--witness-key", join(pins, "witness-key.pem"),
        "--checkpoint-key", join(pins, "witness-key.pem"),
        "--operator-credentials", join(pins, "operator-credentials.json"),
        "--json",
      ],
      (s) => out.push(s),
    );
    return JSON.parse(out.join("\n")) as Report;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("an index line that is JSON but not an object", () => {
  for (const line of ["null", "[]", "7", '"text"']) {
    it(`${line}: a named index problem, and the rest of the ledger is still verified`, async () => {
      const report = await verifyWithIndexLine(line);
      assert.equal(report.ok, false);
      assert.deepEqual(firstStage(report.problems)?.stages, ["index"], report.problems.join(" | "));
      assert.match(report.problems.join("\n"), /index line \d+ is not a JSON object/);
      assert.equal(report.decisions, 8, "the run stopped before the decisions were counted");
      assert.equal(report.index.present, true);
    });
  }

  it("control: valid-full with no extra line is VALID", async () => {
    const report = await verifyWithIndexLine("");
    assert.equal(report.ok, true, report.problems.join(" | "));
    assert.equal(report.decisions, 8);
  });
});
