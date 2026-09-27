// R5: layers R1–R4 did not attack. R5-1 and R5-2 assert the safe behaviour.
// R5-3 keeps the committed test keys inside the fixture rule.

import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildCheckpointClaims,
  checkpointHash,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";

import type { LedgerEffect } from "../packages/proxy/src/types.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const golden = join(root, "packages", "proxy", "tests", "fixtures", "ledger-golden");

function copyGolden(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-attack-r5-"));
  for (const name of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, name), join(dir, name));
  }
  return dir;
}

function readDecisions(dir: string): SignedDecisionRecord[] {
  return readFileSync(join(dir, "decisions.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as SignedDecisionRecord);
}

function witnessKeys(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function signOver(
  records: SignedDecisionRecord[],
  keys: { privateKeyPem: string; publicKeyPem: string },
  prev: string | null,
  epoch: number,
): SignedCheckpoint {
  const times = records.map((row) => row.claims.timestampMs);
  const startMs = Math.min(...times);
  const endMs = Math.max(...times) + 1;
  const claims = buildCheckpointClaims(
    epoch,
    records,
    startMs,
    endMs,
    prev,
    totalsFromDecisionRecords,
    (row) => decisionRecordHash(row),
  );
  return signCheckpoint(claims, keys.privateKeyPem, keys.publicKeyPem);
}

function writeCheckpoints(dir: string, rows: readonly SignedCheckpoint[]): void {
  writeFileSync(join(dir, "checkpoints.jsonl"), `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
}

/** Drops the last decision and every effect that names its ref. Returns how many decisions remain. */
function dropNewestDecision(dir: string): number {
  const path = join(dir, "decisions.jsonl");
  const lines = readFileSync(path, "utf8").split("\n");
  let last = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i]!.trim() !== "") last = i;
  }
  assert.ok(last >= 0, "golden decision missing");
  const rec = JSON.parse(lines[last]!) as { claims?: { ref?: unknown } };
  const ref = rec.claims?.ref;
  assert.equal(typeof ref, "string");
  lines.splice(last, 1);
  writeFileSync(path, lines.join("\n"), "utf8");

  const effectsPath = join(dir, "effects.jsonl");
  const kept = readFileSync(effectsPath, "utf8")
    .split("\n")
    .filter((line) => {
      if (line.trim() === "") return false;
      const row = JSON.parse(line) as { row?: { ref?: unknown } };
      return row.row?.ref !== ref;
    });
  writeFileSync(effectsPath, `${kept.join("\n")}\n`, "utf8");
  return lines.filter((line) => line.trim() !== "").length;
}

const SKIP_DIR = new Set(["node_modules", "dist", ".git"]);

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIR.has(name)) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else out.push(path);
  }
}

describe("attack R5", () => {
  it("R5-1 verify rejects a checkpoint whose signature does not verify", async () => {
    const dir = copyGolden();
    try {
      const remaining = dropNewestDecision(dir);
      const before = await verifyLedger(dir);
      assert.equal(before.ok, true, JSON.stringify(before.problems));

      writeFileSync(
        join(dir, "checkpoints.jsonl"),
        `${JSON.stringify({ claims: { receiptCount: remaining }, coseHex: "00" })}\n`,
        "utf8",
      );
      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /checkpoint/i.test(problem) && /sign/i.test(problem)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R5-1 a witness-signed checkpoint verifies under the pinned key", async () => {
    const dir = copyGolden();
    try {
      const keys = witnessKeys();
      writeCheckpoints(dir, [signOver(readDecisions(dir), keys, null, 0)]);
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: keys.publicKeyPem });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.checkpointTrust.source, "pinned");
      assert.equal(result.checkpointTrust.publicKeyPem?.trim(), keys.publicKeyPem.trim());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R5-1 a checkpoint signed by another key fails under the pin", async () => {
    const dir = copyGolden();
    try {
      const signer = witnessKeys();
      const pin = witnessKeys();
      writeCheckpoints(dir, [signOver(readDecisions(dir), signer, null, 0)]);
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: pin.publicKeyPem });
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /checkpoint/i.test(problem) && /sign/i.test(problem)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R5-1 a checkpoint row edited after signing fails", async () => {
    const dir = copyGolden();
    try {
      const keys = witnessKeys();
      const signed = signOver(readDecisions(dir), keys, null, 0);
      const flipped = signed.coseHex.endsWith("00") ? "ff" : "00";
      signed.coseHex = signed.coseHex.slice(0, -2) + flipped;
      writeCheckpoints(dir, [signed]);
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: keys.publicKeyPem });
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /checkpoint/i.test(problem) && /sign/i.test(problem)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R5-1 a broken prevCheckpointHash chain fails", async () => {
    const dir = copyGolden();
    try {
      const keys = witnessKeys();
      const records = readDecisions(dir);
      assert.ok(records.length >= 2, "golden ledger is shorter than this test");
      const first = signOver(records.slice(0, records.length - 1), keys, null, 0);
      const real = checkpointHash(first);
      const wrong = `${real[0] === "0" ? "1" : "0"}${real.slice(1)}`;
      const second = signOver(records, keys, wrong, 1);
      writeCheckpoints(dir, [first, second]);
      const result = await verifyLedger(dir, { checkpointPublicKeyPem: keys.publicKeyPem });
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /prevCheckpointHash/i.test(problem)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R5-2 verify rejects an effect row whose class is not the signed class", async () => {
    const dir = copyGolden();
    try {
      const path = join(dir, "effects.jsonl");
      const lines = readFileSync(path, "utf8").split("\n");
      const first = lines.findIndex((line) => line.trim() !== "");
      assert.ok(first >= 0, "golden effect missing");
      const row = JSON.parse(lines[first]!) as LedgerEffect;
      assert.equal(row.row.effectClass, "memory.get");
      assert.equal(row.receipt?.body.effects[0]?.effectClass, "memory.get");
      row.row.effectClass = "spend";
      lines[first] = JSON.stringify(row);
      writeFileSync(path, lines.join("\n"), "utf8");

      const result = await verifyLedger(dir);
      assert.equal(result.ok, false, JSON.stringify(result.problems));
      assert.ok(
        result.problems.some((problem) => /class/i.test(problem)),
        JSON.stringify(result.problems),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R5-3 private keys stay under tests/fixtures and are named TEST-KEY-NOT-A-SECRET", () => {
    const files: string[] = [];
    walk(root, files);
    const privateKeys: string[] = [];
    for (const file of files) {
      let text = "";
      try {
        text = readFileSync(file, "utf8");
      } catch {
        continue;
      }
      // A real PEM block (any private key type) with a base64 body, not a sentence that names one.
      if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}/.test(text)) continue;
      const rel = relative(root, file).replaceAll("\\", "/");
      assert.ok(rel.includes("tests/fixtures/"), `${rel} is a private key outside tests/fixtures`);
      assert.ok(
        basename(file).includes("TEST-KEY-NOT-A-SECRET"),
        `${rel} is a private key whose name does not say TEST-KEY-NOT-A-SECRET`,
      );
      privateKeys.push(file);
    }
    assert.ok(privateKeys.length >= 1, "the golden fixture keys are missing");
    const names = privateKeys.map((file) => basename(file));
    for (const file of files) {
      const rel = relative(root, file).replaceAll("\\", "/");
      if (!/^packages\/[^/]+\/src\//.test(rel)) continue;
      let text = "";
      try {
        text = readFileSync(file, "utf8");
      } catch {
        continue;
      }
      for (const name of names) {
        assert.equal(text.includes(name), false, `${rel} references ${name}`);
      }
    }
  });
});
