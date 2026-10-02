import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { appendFileSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildCheckpointClaims,
  redactCheckpointTotals,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { decisionRecordHash, signDecisionRecord, type SignedDecisionRecord } from "@cedulon/core";

import { sha256Canonical } from "../src/hash.ts";
import { FileLedger } from "../src/ledger.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { RECORD_SIGNER } from "./helpers.ts";

const golden = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "ledger-golden");

function copyGolden(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-verify-inputs-"));
  for (const name of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, name), join(dir, name));
  }
  return dir;
}

function lines(path: string): string[] {
  return readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
}

function records(dir: string): SignedDecisionRecord[] {
  return lines(join(dir, "decisions.jsonl")).map((line) => JSON.parse(line) as SignedDecisionRecord);
}

const WITNESS = (() => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
})();

function writeCheckpoint(dir: string, over: (claims: SignedCheckpoint["claims"]) => SignedCheckpoint["claims"]): void {
  const rows = records(dir);
  const endMs = Math.max(...rows.map((r) => r.claims.timestampMs)) + 1;
  const claims = buildCheckpointClaims(
    0,
    rows,
    0,
    endMs,
    null,
    totalsFromDecisionRecords,
    (row: SignedDecisionRecord) => decisionRecordHash(row),
  );
  const signed = signCheckpoint(over(claims), WITNESS.privateKeyPem, WITNESS.publicKeyPem);
  writeFileSync(join(dir, "checkpoints.jsonl"), `${JSON.stringify(signed)}\n`, "utf8");
}

/**
 * The writer appends a call's inputs row before the record whose inputsHash
 * commits to it. The approver of an approval lives in that row, so a row the
 * verifier does not hold to its hash could be rewritten from a signed
 * approval into an unsigned one and still read as verified.
 */
describe("verifyLedger inputs rows", () => {
  it("states that each record found its inputs row", async () => {
    const dir = copyGolden();
    try {
      const result = await verifyLedger(dir);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.inputs.matched, result.decisions);
      assert.match(result.inputs.line, /each with its inputs row/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a row with no record is the crash case and is not named", async () => {
    const dir = copyGolden();
    try {
      appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: "never-recorded", inputs: { a: 1 } })}\n`);
      const first = JSON.parse(lines(join(dir, "inputs.jsonl"))[0]!) as { ref: string };
      // A second row under a ref that has a record, with other content: a retry's row.
      appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: first.ref, inputs: { retry: true } })}\n`);
      const result = await verifyLedger(dir);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("two records under one ref each need a row of their own", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-verify-inputs-ref-"));
    const ledger = new FileLedger(dir);
    try {
      const first = { principal: { brain: "brain-1", scopes: ["verax:read"] }, inputs: [], n: 1 };
      const second = { ...first, n: 2 };
      for (const [i, inputs] of [first, second].entries()) {
        appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: "shared", inputs })}\n`);
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.get",
              requestHash: sha256Canonical({ name: "memory.get", n: i }),
              policyHash: sha256Canonical({ policy: 1 }),
              inputsHash: sha256Canonical(inputs),
              decision: "deny",
              reasonCode: "no-rule",
              ref: "shared",
              effectHash: null,
              effectClass: "memory.get",
              timestampMs: 10 + i,
              nonce: `shared-${i}`,
              prevRecordHash: prev,
            },
            RECORD_SIGNER.privateKeyPem,
            RECORD_SIGNER.publicKeyPem,
          ),
        );
      }
      const both = await verifyLedger(dir);
      assert.equal(both.ok, true, JSON.stringify(both.problems));
      assert.equal(both.inputs.matched, 2);
      // One row cannot answer for two records.
      const path = join(dir, "inputs.jsonl");
      const rows = lines(path);
      writeFileSync(path, `${rows[0]}
${rows[0]}
`, "utf8");
      const one = await verifyLedger(dir);
      assert.equal(one.ok, false);
      assert.equal(one.inputs.mismatched, 1);
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("one row cannot answer for two records that carry the same inputsHash", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-verify-inputs-same-"));
    const ledger = new FileLedger(dir);
    try {
      const inputs = { principal: { brain: "brain-1", scopes: ["verax:read"] }, inputs: [] };
      appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: "same", inputs })}\n`);
      for (const i of [0, 1]) {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.get",
              requestHash: sha256Canonical({ name: "memory.get", n: i }),
              policyHash: sha256Canonical({ policy: 1 }),
              inputsHash: sha256Canonical(inputs),
              decision: "deny",
              reasonCode: "no-rule",
              ref: "same",
              effectHash: null,
              effectClass: "memory.get",
              timestampMs: 10 + i,
              nonce: `same-${i}`,
              prevRecordHash: prev,
            },
            RECORD_SIGNER.privateKeyPem,
            RECORD_SIGNER.publicKeyPem,
          ),
        );
      }
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false);
      assert.equal(result.inputs.matched, 1);
      assert.equal(result.inputs.missing, 1);
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an edited inputs row fails, naming the record", async () => {
    const dir = copyGolden();
    try {
      const path = join(dir, "inputs.jsonl");
      const rows = lines(path);
      const row = JSON.parse(rows[0]!) as { ref: string; inputs: Record<string, unknown> };
      row.inputs = { ...row.inputs, edited: true };
      rows[0] = JSON.stringify(row);
      writeFileSync(path, `${rows.join("\n")}\n`, "utf8");
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false);
      assert.equal(result.inputs.mismatched, 1);
      assert.ok(
        result.problems.some((p) => p.startsWith("inputs row does not match its record's inputsHash: record 0")),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a removed inputs row fails as missing", async () => {
    const dir = copyGolden();
    try {
      const path = join(dir, "inputs.jsonl");
      writeFileSync(path, `${lines(path).slice(1).join("\n")}\n`, "utf8");
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false);
      assert.equal(result.inputs.missing, 1);
      assert.ok(result.problems.some((p) => p.startsWith("inputs row missing: record 0")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a removed inputs file fails for every record that carries an inputsHash", async () => {
    const dir = copyGolden();
    try {
      rmSync(join(dir, "inputs.jsonl"));
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false);
      assert.equal(result.inputs.missing, result.decisions);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** Decision profile 4.4: a difference in totals is checkpoint-total-mismatch. */
describe("verifyLedger checkpoint totals", () => {
  it("totals that match the window pass", async () => {
    const dir = copyGolden();
    try {
      writeCheckpoint(dir, (claims) => claims);
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: WITNESS.publicKeyPem });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a signed total that differs from the records fails", async () => {
    const dir = copyGolden();
    try {
      writeCheckpoint(dir, (claims) => ({
        ...claims,
        totals: { ...(claims.totals as Record<string, string>), deny: "99" },
      }));
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: WITNESS.publicKeyPem });
      assert.equal(result.ok, false);
      assert.ok(
        result.problems.includes("checkpoint totals do not match the records in its window: checkpoint 0"),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a record appended after the checkpoint with a time inside its window does not change what it counted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-verify-totals-late-"));
    const ledger = new FileLedger(dir);
    const append = async (i: number) => {
      const inputs = { principal: { brain: "brain-1", scopes: ["verax:read"] }, inputs: [], n: i };
      appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: `late-${i}`, inputs })}\n`);
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.get",
            requestHash: sha256Canonical({ name: "memory.get", n: i }),
            policyHash: sha256Canonical({ policy: 1 }),
            inputsHash: sha256Canonical(inputs),
            decision: "deny",
            reasonCode: "no-rule",
            ref: `late-${i}`,
            effectHash: null,
            effectClass: "memory.get",
            // Both calls took their time before either was written.
            timestampMs: 10,
            nonce: `late-${i}`,
            prevRecordHash: prev,
          },
          RECORD_SIGNER.privateKeyPem,
          RECORD_SIGNER.publicKeyPem,
        ),
      );
    };
    try {
      await append(0);
      writeCheckpoint(dir, (claims) => claims);
      await append(1);
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: WITNESS.publicKeyPem });
      assert.ok(
        !result.problems.some((p) => p.startsWith("checkpoint totals")),
        JSON.stringify(result.problems),
      );
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("redacted totals are not compared", async () => {
    const dir = copyGolden();
    try {
      writeCheckpoint(dir, (claims) => redactCheckpointTotals(claims));
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: WITNESS.publicKeyPem });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
