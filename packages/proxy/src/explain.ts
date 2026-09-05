import { audit, DECISION_PROFILE } from "@cedulon/audit";
import { findDecisionRecordChainBreak } from "@cedulon/core";
import type { ExplainResult, Ledger } from "./types.ts";

const WINDOW_COVERAGE = "window-coverage";

/**
 * Re-runs the Cedulon decision profile on the whole ledger. Finding codes
 * are Cedulon's; this wrapper does not invent names. Phase 1 has no
 * durable checkpoint, so window-coverage is listed as notApplicable and
 * dropped from the finding set before balanced is computed. A self
 * witness makes a clean ("balanced") report conditional.
 */
export async function explain(ledger: Ledger, ref: string): Promise<ExplainResult> {
  const decisions = await ledger.decisions();
  const effects = await ledger.effects();
  const record = decisions.find((d) => d.claims.ref === ref);
  if (!record) {
    throw new Error(`explain-unknown-ref:${ref}`);
  }
  const effect = effects.find((e) => e.row.ref === ref && e.row.effectClass !== "duplicate-effect") ?? null;
  const report = audit({
    receipts: decisions,
    checkpoints: [],
    settlements: effects.map((e) => e.row),
    profile: DECISION_PROFILE,
  });
  const dropped = [...new Set(
    [...report.findings, ...report.warnings]
      .filter((f) => f.code === WINDOW_COVERAGE)
      .map((f) => f.code),
  )];
  const applicable = report.findings.filter((f) => f.code !== WINDOW_COVERAGE);
  const applicableWarnings = report.warnings.filter((f) => f.code !== WINDOW_COVERAGE);
  const refFindings = applicable.filter((f) => f.id === ref);
  const hit =
    refFindings[0] ??
    applicableWarnings.find((f) => f.id === ref) ??
    null;
  const prefix = decisions.slice(0, decisions.indexOf(record) + 1);
  const brk = findDecisionRecordChainBreak(prefix);
  const breakAt = brk ? (prefix[brk.index]?.claims.ref ?? null) : null;
  const chain = { intact: brk === null, breakAt };
  const witnessClass = effect?.witnessClass ?? null;
  const self = witnessClass === "self";
  const chainBreak = !chain.intact;
  const balanced = refFindings.length === 0 && !chainBreak;
  const code = chainBreak ? "receipt-chain-break" : (hit?.code ?? null);
  const detail = chainBreak
    ? `receipt-chain-break at ${breakAt ?? "unknown"} (${brk?.reason ?? "broken"})`
    : (hit?.detail ?? null);
  const findingCount = chainBreak ? Math.max(refFindings.length, 1) : refFindings.length;
  const summary = balanced ? "audit: balanced" : `audit: ${findingCount} finding(s) → FAIL`;
  return {
    record,
    effect,
    witnessClass,
    balanced,
    chain,
    finding: {
      code,
      label: self ? "conditional" : null,
      detail,
      summary,
      ...(dropped.length > 0 ? { notApplicable: dropped } : {}),
    },
  };
}
