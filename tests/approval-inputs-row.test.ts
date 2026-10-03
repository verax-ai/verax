import { strict as assert } from "node:assert";
import { appendFileSync, copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runVerify } from "../packages/body/src/verify-cli.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function copyVector(id: string): { dir: string; pins: string } {
  const dir = mkdtempSync(join(tmpdir(), "verax-approval-row-"));
  const ledger = join(root, "test-vectors", "v1", id, "ledger");
  for (const name of readdirSync(ledger)) copyFileSync(join(ledger, name), join(dir, name));
  return { dir, pins: join(root, "test-vectors", "v1", id, "pins") };
}

function approvedRef(dir: string): string {
  for (const line of readFileSync(join(dir, "decisions.jsonl"), "utf8").split("\n")) {
    if (line === "") continue;
    const claims = (JSON.parse(line) as { claims: { reasonCode: string; ref: string } }).claims;
    if (claims.reasonCode === "approved-by-operator") return claims.ref;
  }
  throw new Error("no approved allow");
}

async function verify(dir: string, pins: string): Promise<{ code: number; report: { approvalSignatures: { signedVerified: number; signedFailed: number; cli: number } } }> {
  const out: string[] = [];
  const code = await runVerify(
    [
      dir,
      "--key", join(pins, "record-key.pem"),
      "--witness-key", join(pins, "witness-key.pem"),
      "--checkpoint-key", join(pins, "witness-key.pem"),
      "--operator-credentials", join(pins, "operator-credentials.json"),
      "--json",
    ],
    (s) => out.push(s),
  );
  return { code, report: JSON.parse(out.join("\n")) };
}

/**
 * An inputs row with no record is tolerated: a crash leaves one. The approval
 * check must still read the row the allow's signed inputsHash names, not
 * whichever row under that ref came last, or one appended line turns a failed
 * signature into an unsigned CLI approval and the ledger verifies.
 */
describe("approval signatures read the inputs row the record names", () => {
  it("an appended unsigned row does not hide a signature that fails", async () => {
    const { dir, pins } = copyVector("fail-approval-signature");
    try {
      appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: approvedRef(dir), inputs: { approver: { via: "cli" } } })}\n`);
      const { code, report } = await verify(dir, pins);
      assert.equal(code, 1);
      assert.equal(report.approvalSignatures.signedFailed, 1);
      assert.equal(report.approvalSignatures.cli, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an appended unsigned row does not replace a signature that verifies", async () => {
    const { dir, pins } = copyVector("valid-full");
    try {
      appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: approvedRef(dir), inputs: { approver: { via: "cli" } } })}\n`);
      const { code, report } = await verify(dir, pins);
      assert.equal(code, 0);
      assert.equal(report.approvalSignatures.signedVerified, 1);
      assert.equal(report.approvalSignatures.cli, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
