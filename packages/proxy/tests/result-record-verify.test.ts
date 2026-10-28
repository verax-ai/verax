import { strict as assert } from "node:assert";
import { appendFileSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { decisionRecordHash, signDecisionRecord, type SignedDecisionRecord } from "@cedulon/core";

import { sha256Canonical } from "../src/hash.ts";
import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const TCKN = "10000000146";
const P = { brain: "brain-1", scopes: new Set(["verax:read"]) };
const CALL = { name: "media.read", arguments: { path: "notes.txt" } };

function policy() {
  return loadPolicy(
    JSON.stringify({
      version: 2,
      default: "deny",
      resultClasses: { tckn: "mask" },
      rules: [
        {
          id: "media-read",
          tool: "media.read",
          requires: ["verax:read"],
          text: "Reading needs the read scope.",
        },
      ],
    }),
  );
}

async function ledgerWithResultRecord(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-rrv-"));
  const ledger = new FileLedger(dir);
  try {
    const proxy = createProxy({
      policy: policy(),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["r-1", "r-2"]),
      inner: async () => ({
        content: [{ type: "text", text: `TC ${TCKN}` }],
        isError: false,
      }),
    });
    await proxy.call(CALL, P);
  } finally {
    ledger.close();
  }
  return dir;
}

function jsonlFiles(dir: string, name: string): string[] {
  const out: string[] = [];
  const stack = [dir];
  while (stack.length > 0) {
    const here = stack.pop()!;
    for (const entry of readdirSync(here)) {
      const path = join(here, entry);
      if (entry === "evidence-copy") continue;
      if (statSync(path).isDirectory()) stack.push(path);
      else if (entry === name) out.push(path);
    }
  }
  return out;
}

function rewriteLastDecision(dir: string, edit: (rec: SignedDecisionRecord) => SignedDecisionRecord): void {
  const path = jsonlFiles(dir, "decisions.jsonl")[0];
  assert.ok(path, "no decisions.jsonl");
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
  assert.ok(lines.length >= 2, "expected a call record and a result record");
  const last = JSON.parse(lines[lines.length - 1]!) as SignedDecisionRecord;
  const next = edit(last);
  lines[lines.length - 1] = JSON.stringify(next);
  writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
}

function rewriteInputsResultOf(dir: string, from: string, to: string): void {
  const path = jsonlFiles(dir, "inputs.jsonl")[0];
  assert.ok(path, "no inputs.jsonl");
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
  const edited = lines.map((line) => {
    const row = JSON.parse(line) as { ref?: string; inputs?: { resultOf?: string } };
    if (row.inputs?.resultOf === from) row.inputs.resultOf = to;
    return JSON.stringify(row);
  });
  writeFileSync(path, `${edited.join("\n")}\n`, "utf8");
}

describe("verifyLedger — result records", () => {
  it("a ledger with a result-classes record verifies", async () => {
    const dir = await ledgerWithResultRecord();
    const verified = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
    assert.equal(verified.ok, true, JSON.stringify(verified.problems));
  });

  it("refuses when that record's requestHash or resultOf points elsewhere", async () => {
    const hashDir = await ledgerWithResultRecord();
    rewriteLastDecision(hashDir, (rec) =>
      signDecisionRecord(
        { ...rec.claims, requestHash: "0".repeat(64) },
        RECORD_SIGNER.privateKeyPem,
        RECORD_SIGNER.publicKeyPem,
      ),
    );
    const hash = await verifyLedger(hashDir, { boundaryAllowanceMs: 0 });
    assert.equal(hash.ok, false);
    assert.ok(
      hash.problems.some((p) => p.startsWith("result-record-mismatch ")),
      JSON.stringify(hash.problems),
    );

    const ofDir = await ledgerWithResultRecord();
    rewriteInputsResultOf(ofDir, "r-1", "no-such-call");
    rewriteLastDecision(ofDir, (rec) =>
      signDecisionRecord(
        { ...rec.claims, inputsHash: hashInputs(ofDir, rec.claims.ref as string) },
        RECORD_SIGNER.privateKeyPem,
        RECORD_SIGNER.publicKeyPem,
      ),
    );
    const pointed = await verifyLedger(ofDir, { boundaryAllowanceMs: 0 });
    assert.equal(pointed.ok, false);
    assert.ok(
      pointed.problems.some((p) => p.startsWith("result-record-mismatch ")),
      JSON.stringify(pointed.problems),
    );
  });

  it("a ledger whose result record is a gated tool throw verifies", async () => {
    const dir = await ledgerWithThrownRecord();
    const verified = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
    assert.equal(verified.ok, true, JSON.stringify(verified.problems));
  });

  it("refuses an allow whose effectHash is not its requestHash", async () => {
    const dir = await ledgerWithResultRecord();
    rewriteLastDecision(dir, (rec) =>
      signDecisionRecord(
        { ...rec.claims, effectHash: "a".repeat(64) },
        RECORD_SIGNER.privateKeyPem,
        RECORD_SIGNER.publicKeyPem,
      ),
    );
    await assertResultMismatch(dir);
  });

  it("a withheld (deny) result record verifies", async () => {
    const dir = await ledgerWithBlockRecord();
    const verified = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
    assert.equal(verified.ok, true, JSON.stringify(verified.problems));
  });

  it("refuses a returnedHash that is not 64 lowercase hex, and non-positive counts", async () => {
    const hashDir = await ledgerWithResultRecord();
    rewriteLastResultClasses(hashDir, (rc) => {
      rc.returnedHash = "ABCDEF" + "0".repeat(58);
    });
    await assertResultMismatch(hashDir);

    const countDir = await ledgerWithResultRecord();
    rewriteLastResultClasses(countDir, (rc) => {
      rc.masked = { tckn: 0 };
      rc.withheld = { audio: -1 };
      rc.transcribed = -1;
    });
    await assertResultMismatch(countDir);
  });

  it("refuses when the record's subject is not the named call's effect class", async () => {
    const dir = await ledgerWithResultRecord();
    rewriteLastDecision(dir, (rec) =>
      signDecisionRecord(
        { ...rec.claims, subject: "other.tool" },
        RECORD_SIGNER.privateKeyPem,
        RECORD_SIGNER.publicKeyPem,
      ),
    );
    await assertResultMismatch(dir);
  });

  it("refuses when two result records name the same call", async () => {
    const dir = await ledgerWithResultRecord();
    appendSecondResultRecord(dir);
    await assertResultMismatch(dir);
  });

  it("refuses a result record whose decision is not allow or deny", async () => {
    const dir = await ledgerWithResultRecord();
    rewriteLastDecision(dir, (rec) =>
      signDecisionRecord(
        { ...rec.claims, decision: "defer", effectHash: null },
        RECORD_SIGNER.privateKeyPem,
        RECORD_SIGNER.publicKeyPem,
      ),
    );
    await assertResultMismatch(dir);
  });
});

async function assertResultMismatch(dir: string): Promise<void> {
  const verified = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
  assert.equal(verified.ok, false);
  assert.ok(
    verified.problems.some((p) => p.startsWith("result-record-mismatch ")),
    JSON.stringify(verified.problems),
  );
}

async function ledgerWithBlockRecord(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-rrv-block-"));
  const ledger = new FileLedger(dir);
  try {
    const proxy = createProxy({
      policy: policyDoc({ tckn: "block" }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["r-1", "r-2"]),
      inner: async () => ({
        content: [{ type: "text", text: `TC ${TCKN}` }],
        isError: false,
      }),
    });
    await proxy.call(CALL, P);
  } finally {
    ledger.close();
  }
  return dir;
}

async function ledgerWithThrownRecord(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-rrv-threw-"));
  const ledger = new FileLedger(dir);
  try {
    const proxy = createProxy({
      policy: policy(),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["e-1", "e-2"]),
      inner: async () => {
        throw new Error(`lookup failed for TC ${TCKN}`);
      },
    });
    try {
      await proxy.call(CALL, P);
    } catch {
      // Gated throw; the ledger holds the :threw row and the result record.
    }
  } finally {
    ledger.close();
  }
  return dir;
}

function policyDoc(resultClasses: Record<string, string>) {
  return loadPolicy(
    JSON.stringify({
      version: 2,
      default: "deny",
      resultClasses,
      rules: [
        {
          id: "media-read",
          tool: "media.read",
          requires: ["verax:read"],
          text: "Reading needs the read scope.",
        },
      ],
    }),
  );
}

function rewriteLastResultClasses(
  dir: string,
  edit: (rc: { masked: Record<string, number>; transcribed: number; withheld: Record<string, number>; returnedHash: string }) => void,
): void {
  const path = jsonlFiles(dir, "inputs.jsonl")[0];
  assert.ok(path, "no inputs.jsonl");
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line !== "");
  let resultRef: string | undefined;
  const edited = lines.map((line) => {
    const row = JSON.parse(line) as {
      ref?: string;
      inputs?: { resultOf?: string; resultClasses?: { masked: Record<string, number>; transcribed: number; withheld: Record<string, number>; returnedHash: string } };
    };
    if (row.inputs?.resultOf && row.inputs.resultClasses) {
      resultRef = row.ref;
      edit(row.inputs.resultClasses);
    }
    return JSON.stringify(row);
  });
  writeFileSync(path, `${edited.join("\n")}\n`, "utf8");
  assert.ok(resultRef, "no result-classes inputs row");
  rewriteLastDecision(dir, (rec) =>
    signDecisionRecord(
      { ...rec.claims, inputsHash: hashInputs(dir, resultRef!) },
      RECORD_SIGNER.privateKeyPem,
      RECORD_SIGNER.publicKeyPem,
    ),
  );
}

function appendSecondResultRecord(dir: string): void {
  const decPath = jsonlFiles(dir, "decisions.jsonl")[0];
  const inpPath = jsonlFiles(dir, "inputs.jsonl")[0];
  assert.ok(decPath && inpPath, "no ledger files");
  const decLines = readFileSync(decPath, "utf8").split("\n").filter((line) => line !== "");
  const last = JSON.parse(decLines[decLines.length - 1]!) as SignedDecisionRecord;
  let copied: unknown;
  for (const line of readFileSync(inpPath, "utf8").split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { inputs?: { resultOf?: string } };
    if (row.inputs?.resultOf) copied = row.inputs;
  }
  assert.ok(copied, "no result inputs to duplicate");
  const newRef = "r-dup";
  appendFileSync(inpPath, `${JSON.stringify({ ref: newRef, inputs: copied })}\n`);
  const next = signDecisionRecord(
    {
      ...last.claims,
      ref: newRef,
      nonce: newRef,
      inputsHash: sha256Canonical(copied),
      prevRecordHash: decisionRecordHash(last),
      timestampMs: (last.claims.timestampMs as number) + 1,
    },
    RECORD_SIGNER.privateKeyPem,
    RECORD_SIGNER.publicKeyPem,
  );
  appendFileSync(decPath, `${JSON.stringify(next)}\n`);
}

function hashInputs(dir: string, ref: string): string {
  const path = jsonlFiles(dir, "inputs.jsonl")[0]!;
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: unknown };
    if (row.ref === ref && row.inputs !== undefined) {
      return sha256Canonical(row.inputs);
    }
  }
  throw new Error(`inputs for ${ref} missing`);
}
