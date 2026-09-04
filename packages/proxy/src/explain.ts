import { audit, DECISION_PROFILE } from "@cedulon/audit";
import type { ExplainResult, Ledger } from "./types.ts";

/**
 * Re-runs the Cedulon decision profile on the ledger window that contains
 * `ref`. Finding codes are Cedulon's; this wrapper does not invent names.
 * A self witness makes a clean ("balanced") report conditional.
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
  const hit =
    report.findings.find((f) => f.id === ref) ??
    report.warnings.find((f) => f.id === ref) ??
    null;
  const witnessClass = effect?.witnessClass ?? null;
  const balanced = report.summary === "audit: balanced" && hit === null;
  const self = witnessClass === "self";
  return {
    record,
    effect,
    witnessClass,
    finding: {
      code: hit?.code ?? (balanced ? null : null),
      label: self ? "conditional" : null,
      detail: hit?.detail ?? null,
      summary: report.summary,
    },
  };
}
