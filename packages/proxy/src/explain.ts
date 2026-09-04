import { audit, DECISION_PROFILE } from "@cedulon/audit";
import { buildCheckpointClaims, signCheckpoint, totalsFromDecisionRecords } from "@cedulon/checkpoint";
import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import type { ExplainOpts, ExplainResult, Ledger, RecordSigner } from "./types.ts";

/**
 * Re-runs the Cedulon decision profile on the ledger window that contains
 * `ref`. Finding codes are Cedulon's; this wrapper does not invent names.
 * A self witness makes a clean ("balanced") report conditional.
 */
export async function explain(ledger: Ledger, ref: string, opts?: ExplainOpts): Promise<ExplainResult> {
  const decisions = await ledger.decisions();
  const effects = await ledger.effects();
  const record = decisions.find((d) => d.claims.ref === ref);
  if (!record) {
    throw new Error(`explain-unknown-ref:${ref}`);
  }
  const effect = effects.find((e) => e.row.ref === ref && e.row.effectClass !== "duplicate-effect") ?? null;
  const windowRecords = [record];
  const windowRows = effect ? [effect.row] : [];
  const produced = produceCheckpoint(windowRecords, opts?.checkpointSigner);
  const report = audit({
    receipts: windowRecords,
    checkpoints: produced.checkpoint ? [produced.checkpoint] : [],
    settlements: windowRows,
    profile: DECISION_PROFILE,
    issuerTrust: opts?.checkpointSigner ? { publicKeyPem: opts.checkpointSigner.publicKeyPem } : undefined,
  });
  const hit =
    report.findings.find((f) => f.id === ref) ??
    report.warnings.find((f) => f.id === ref) ??
    null;
  const witnessClass = effect?.witnessClass ?? null;
  const self = witnessClass === "self";
  const balanced = report.summary === "audit: balanced";
  return {
    record,
    effect,
    witnessClass,
    balanced,
    finding: {
      code: hit?.code ?? null,
      label: self ? "conditional" : null,
      detail: hit?.detail ?? null,
      summary: report.summary,
      ...(produced.notApplicable.length > 0 ? { notApplicable: produced.notApplicable } : {}),
    },
  };
}

function produceCheckpoint(records: SignedDecisionRecord[], signer: RecordSigner | undefined) {
  if (!signer) {
    return { checkpoint: null, notApplicable: ["window-coverage"] };
  }
  try {
    const times = records.map((r) => r.claims.timestampMs);
    const startMs = Math.min(...times);
    const endMs = Math.max(...times) + 1;
    const claims = buildCheckpointClaims(
      1,
      records,
      startMs,
      endMs,
      null,
      totalsFromDecisionRecords,
      decisionRecordHash,
    );
    return { checkpoint: signCheckpoint(claims, signer.privateKeyPem, signer.publicKeyPem), notApplicable: [] };
  } catch {
    return { checkpoint: null, notApplicable: ["window-coverage"] };
  }
}
