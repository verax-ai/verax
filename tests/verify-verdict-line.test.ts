import { strict as assert } from "node:assert";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger, type VerifyResult } from "@verax-ai/proxy";
import type { ApprovalSignatureReport } from "../packages/body/src/approval-signature.ts";
import type { ControlSignatureReport } from "../packages/body/src/control-signature.ts";
import { renderVerify, runVerify } from "../packages/body/src/verify-cli.ts";

const golden = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "packages",
  "proxy",
  "tests",
  "fixtures",
  "ledger-golden",
);

const pinned = { source: "pinned", publicKeyPem: null, note: "pinned in this test" };
const inLedger = { source: "in-ledger", publicKeyPem: null, note: "carried in this test" };
const anchored = { line: "anchors: 1 receipt", receipts: 1, verified: 1, checked: true };

function withFields(r: VerifyResult, fields: Record<string, unknown>): VerifyResult {
  return { ...r, ...fields } as VerifyResult;
}

function lastLine(
  r: VerifyResult,
  approval?: ApprovalSignatureReport,
  control?: ControlSignatureReport,
): string {
  return renderVerify(r, approval, control).split("\n").at(-1) ?? "";
}

/** Every key pinned, a checkpoint that reaches the newest record, a receipt that verified. */
function complete(r: VerifyResult, fields: Record<string, unknown> = {}): VerifyResult {
  return withFields(r, {
    trust: pinned,
    effectTrust: pinned,
    checkpointTrust: pinned,
    anchors: anchored,
    tail: {
      ...r.tail,
      checkpoint: { receiptCount: r.decisions, chainHeadHash: "head", ledgerHoldsRecord: true },
    },
    ...fields,
  });
}

function checkpointOf(r: VerifyResult, receiptCount: number | null, holds: boolean | null): unknown {
  return { ...r.tail, checkpoint: { receiptCount, chainHeadHash: "head", ledgerHoldsRecord: holds } };
}

describe("the last line of verify says what the run could show", () => {
  it("keys taken from the files: internal consistency only", async () => {
    const lines: string[] = [];
    const code = await runVerify([golden], (s) => lines.push(s));
    assert.equal(code, 0, lines.join("\n"));
    assert.equal(lines.join("\n").split("\n").at(-1), "VERIFIED (internal consistency only)");
  });

  it("record key pinned, effect key still from the files: internal consistency only", async () => {
    const r = await verifyLedger(golden);
    assert.equal(lastLine(withFields(r, { trust: pinned })), "VERIFIED (internal consistency only)");
  });

  it("keys pinned, no checkpoint: the tail is named", async () => {
    const r = await verifyLedger(golden);
    assert.equal(
      lastLine(withFields(r, { trust: pinned, effectTrust: pinned })),
      "VERIFIED (tail not covered: no checkpoint)",
    );
  });

  it("keys pinned, checkpoint under a key from the file: internal consistency only", async () => {
    const r = await verifyLedger(golden);
    assert.equal(lastLine(complete(r, { checkpointTrust: inLedger })), "VERIFIED (internal consistency only)");
  });

  it("operator credentials read from the state directory: internal consistency only", async () => {
    const r = await verifyLedger(golden);
    const fromFile = { line: "signatures", trustNote: "note", trustSource: "in-ledger" };
    assert.equal(
      lastLine(complete(r), fromFile as ApprovalSignatureReport),
      "VERIFIED (internal consistency only)",
    );
    assert.equal(
      lastLine(complete(r), undefined, fromFile as ControlSignatureReport),
      "VERIFIED (internal consistency only)",
    );
  });

  it("records after the newest checkpoint are counted", async () => {
    const r = await verifyLedger(golden);
    assert.equal(
      lastLine(complete(r, { tail: checkpointOf(r, r.decisions - 2, true) })),
      "VERIFIED (tail not covered: 2 record(s) after the newest checkpoint)",
    );
  });

  it("a checkpoint with no record count, or no head in the ledger, does not cover the tail", async () => {
    const r = await verifyLedger(golden);
    const unknown = "VERIFIED (tail not covered: the newest checkpoint does not reach a known record)";
    assert.equal(lastLine(complete(r, { tail: checkpointOf(r, null, true) })), unknown);
    assert.equal(lastLine(complete(r, { tail: checkpointOf(r, r.decisions, null) })), unknown);
  });

  it("no receipt that verified: rollback is not checked", async () => {
    const r = await verifyLedger(golden);
    const expected = "VERIFIED (rollback not checked: no anchored checkpoint)";
    assert.equal(
      lastLine(complete(r, { anchors: { line: "anchors: none", receipts: 0, verified: 0, checked: false } })),
      expected,
    );
    assert.equal(
      lastLine(complete(r, { anchors: { line: "anchors: unchecked", receipts: 3, verified: 0, checked: false } })),
      expected,
    );
  });

  it("every key pinned, the tail covered and a receipt verified: plain VERIFIED", async () => {
    const r = await verifyLedger(golden);
    assert.equal(lastLine(complete(r)), "VERIFIED");
  });

  it("a ledger that fails stays NOT VERIFIED", async () => {
    const r = await verifyLedger(golden);
    assert.equal(lastLine(complete(r, { ok: false })), "NOT VERIFIED");
  });
});
