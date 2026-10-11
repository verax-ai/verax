import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { buildCheckpointClaims, signCheckpoint, totalsFromDecisionRecords } from "@cedulon/checkpoint";
import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { checkpointsPath, listPieceFiles, verifyLedger } from "@verax-ai/proxy";

import { createBodyServices } from "../packages/body/src/wiring.ts";

/**
 * R26 (E-5). `verify --require-anchored` ages a checkpoint by the `endMs` the
 * checkpoint itself carries: it is exempt while `endMs + grace >= now`. The
 * reader is told this names "every checkpoint older than the grace that has
 * no receipt". Whoever rewrites the directory holds the witness key in it
 * (`keys/witness.private.pem`), which is the reader the receipts exist for.
 * They sign the rewritten history into a checkpoint whose window ends in
 * 2100. It covers every record, verifies under the witness key the reader
 * pinned, has no receipt at any service, and is never due.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const serviceKey = readFileSync(join(root, "tests", "fixtures", "anchor-capsule", "service-key.pem"), "utf8");

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** A ledger with one allowed call at t=5000, and one checkpoint over it ending at `endMs`. */
async function ledgerWithCheckpoint(endMs: number): Promise<{ dir: string; record: string; effect: string; witness: string }> {
  const dir = mkdtempSync(join(tmpdir(), "verax-r26-future-window-"));
  const record = keys();
  const effect = keys();
  const witness = keys();
  const services = createBodyServices({
    stateDir: dir,
    policyFile,
    recordSigner: record,
    effectSigner: effect,
    now: () => 5_000,
    nonce: () => "r25-e-5",
  });
  try {
    const allowed = await services.proxy.call(
      {
        name: "memory.put",
        arguments: { id: "note-1", body: { t: 1 }, source: { uri: "file://t", retrievedAtMs: 1 }, validUntilMs: 9_999 },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    assert.equal(allowed.isError, false);
  } finally {
    services.ledger.close();
  }
  const decisions: SignedDecisionRecord[] = [];
  for (const piece of listPieceFiles(dir)) {
    for (const line of readFileSync(piece.decisions, "utf8").split("\n")) {
      if (line !== "") decisions.push(JSON.parse(line) as SignedDecisionRecord);
    }
  }
  // The same calls `verax witness` makes for a window (witness.ts signWindowCheckpoint).
  const claims = buildCheckpointClaims(0, decisions, 0, endMs, null, totalsFromDecisionRecords, (row) =>
    decisionRecordHash(row),
  );
  const signed = signCheckpoint(claims, witness.privateKeyPem, witness.publicKeyPem);
  appendFileSync(checkpointsPath(dir), `${JSON.stringify(signed)}\n`, { encoding: "utf8" });
  return { dir, record: record.publicKeyPem, effect: effect.publicKeyPem, witness: witness.publicKeyPem };
}

function verifyRequiring(l: { dir: string; record: string; effect: string; witness: string }) {
  return verifyLedger(l.dir, {
    publicKeyPem: l.record,
    effectPublicKeyPem: l.effect,
    checkpointPublicKeyPem: l.witness,
    anchorPublicKeyPem: serviceKey,
    requireAnchored: true,
  });
}

describe("R26 --require-anchored and a checkpoint whose window ends in the future", () => {
  it("control: the same unanchored checkpoint with a past window is named", async () => {
    const l = await ledgerWithCheckpoint(6_000);
    try {
      const result = await verifyRequiring(l);
      assert.equal(result.ok, false);
      assert.deepEqual(
        result.problems.filter((p) => !p.startsWith("checkpoint-not-anchored ")),
        [],
        "the control ledger has a problem of its own",
      );
      assert.equal(result.problems.filter((p) => p.startsWith("checkpoint-not-anchored ")).length, 1);
    } finally {
      rmSync(l.dir, { recursive: true, force: true });
    }
  });

  it("a window that ends in 2100 does not put the checkpoint beyond the rule", async () => {
    const l = await ledgerWithCheckpoint(Date.UTC(2100, 0, 1));
    try {
      const result = await verifyRequiring(l);
      assert.equal(
        result.ok,
        false,
        `require-anchored verified a ledger whose only checkpoint has no receipt (${result.tail.line}; ${result.anchors.line}; problems ${JSON.stringify(result.problems)})`,
      );
      assert.equal(result.problems.filter((p) => p.startsWith("checkpoint-window-in-future ")).length, 1);
    } finally {
      rmSync(l.dir, { recursive: true, force: true });
    }
  });
});
