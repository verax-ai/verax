import { audit, DECISION_PROFILE } from "@cedulon/audit";
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
  const witnessClass = effect?.witnessClass ?? null;
  const self = witnessClass === "self";
  const balanced = refFindings.length === 0;
  const summary = balanced ? "audit: balanced" : `audit: ${refFindings.length} finding(s) → FAIL`;
  return {
    record,
    effect,
    witnessClass,
    balanced,
    finding: {
      code: hit?.code ?? null,
      label: self ? "conditional" : null,
      detail: hit?.detail ?? null,
      summary,
      ...(dropped.length > 0 ? { notApplicable: dropped } : {}),
    },
  };
}
