import { audit, DECISION_PROFILE, type Finding, type IssuerTrustPin, type PresentedExtract } from "@cedulon/audit";
import { findDecisionRecordChainBreak } from "@cedulon/core";
import { sha256Canonical } from "./hash.ts";
import { inputsLogFor } from "./inputs.ts";
import type { ExplainOpts, ExplainResult, ExplainWarning, Ledger } from "./types.ts";

const WINDOW_COVERAGE = "window-coverage";

function resolveIssuerTrust(opts?: ExplainOpts): IssuerTrustPin | undefined {
  if (opts?.issuerTrust) return opts.issuerTrust;
  const env = process.env.VERAX_RECORD_PUBKEY_PIN;
  if (typeof env === "string" && env.trim() !== "") {
    return { publicKeyPem: env };
  }
  return undefined;
}

function asWarning(f: Finding): ExplainWarning {
  return { id: f.id, code: f.code, detail: f.detail };
}

function conditionName(f: Finding): string | null {
  if (f.code === "unauthenticated-issuer") return "issuer unpinned";
  if (f.code === "unauthenticated-extract") {
    return f.detail.includes("unsigned") ? "extract unsigned" : "extract unpinned";
  }
  return null;
}

function balancedSummary(
  guarantee: "unconditional" | "conditional",
  conditions: readonly string[],
  cedulonSummary: string,
): string {
  if (conditions.length > 0) {
    return `audit: balanced (${guarantee}: ${conditions.join("; ")})`;
  }
  if (guarantee === "unconditional") {
    return "audit: balanced (unconditional)";
  }
  const why = cedulonSummary.replace(/^audit:\s*/i, "").trim();
  if (why !== "" && why !== "balanced" && why !== "conditional") {
    return `audit: balanced (${guarantee}: ${why})`;
  }
  return `audit: balanced (${guarantee})`;
}

/**
 * Re-runs the Cedulon decision profile on the whole ledger. Finding codes
 * are Cedulon's; this wrapper does not invent names. Phase 1 has no
 * durable checkpoint, so window-coverage is listed as notApplicable and
 * dropped from the finding set before balanced is computed. General
 * issuer/extract warnings and the audit guarantee are kept. A self
 * witness and each general Cedulon warning are named in the condition
 * list; "balanced" is never written alone, and "conditional" is never
 * written twice.
 */
export async function explain(ledger: Ledger, ref: string, opts?: ExplainOpts): Promise<ExplainResult> {
  const decisions = await ledger.decisions();
  const effects = await ledger.effects();
  const record = decisions.find((d) => d.claims.ref === ref);
  if (!record) {
    throw new Error(`explain-unknown-ref:${ref}`);
  }
  const effect = effects.find((e) => e.row.ref === ref && e.row.effectClass !== "duplicate-effect") ?? null;
  const issuerTrust = resolveIssuerTrust(opts);
  const pinned = issuerTrust !== undefined;
  const report = audit({
    receipts: decisions,
    checkpoints: [],
    settlements: effects.map((e) => e.row),
    profile: DECISION_PROFILE,
    ...(issuerTrust ? { issuerTrust } : {}),
    ...(opts?.extract ?? effect?.receipt ? { extract: opts?.extract ?? effect?.receipt } : {}),
  });
  const dropped = [
    ...new Set(
      [...report.findings, ...report.warnings]
        .filter((f) => f.code === WINDOW_COVERAGE)
        .map((f) => f.code),
    ),
  ];
  const applicable = report.findings.filter((f) => f.code !== WINDOW_COVERAGE);
  const applicableWarnings = report.warnings.filter((f) => f.code !== WINDOW_COVERAGE);
  const refFindings = applicable.filter((f) => f.id === ref);
  const issuerFinding =
    applicable.find((f) => f.code === "issuer-key-mismatch" || f.id === "issuer") ??
    applicableWarnings.find((f) => f.code === "issuer-key-mismatch") ??
    null;
  const hit =
    refFindings[0] ??
    (pinned ? issuerFinding : null) ??
    applicableWarnings.find((f) => f.id === ref) ??
    null;
  const prefix = decisions.slice(0, decisions.indexOf(record) + 1);
  const brk = findDecisionRecordChainBreak(prefix);
  const breakAt = brk ? (prefix[brk.index]?.claims.ref ?? null) : null;
  const chain = { intact: brk === null, breakAt };
  const witnessClass = effect?.witnessClass ?? null;
  const self = witnessClass === "self";
  const chainBreak = !chain.intact;
  const conditions: string[] = [];
  if (self) conditions.push("self witness");
  for (const w of applicableWarnings) {
    const name = conditionName(w);
    if (name && !conditions.includes(name)) conditions.push(name);
  }
  const issuerMismatch = applicable.concat(applicableWarnings).some(
    (f) => f.code === "issuer-key-mismatch" || (pinned && f.code === "unauthenticated-issuer"),
  );
  const inputsLog = opts?.inputsLog ?? inputsLogFor(ledger);
  const inputsDoc = record.claims.ref ? await inputsLog.get(record.claims.ref) : null;
  const inputsMismatch = Boolean(
    inputsDoc &&
      typeof record.claims.inputsHash === "string" &&
      sha256Canonical(inputsDoc) !== record.claims.inputsHash,
  );
  const balanced = refFindings.length === 0 && !chainBreak && !issuerMismatch && !inputsMismatch;
  const code = chainBreak
    ? "receipt-chain-break"
    : inputsMismatch
      ? "inputs-hash-mismatch"
      : (hit?.code ?? null);
  const detail = chainBreak
    ? `receipt-chain-break at ${breakAt ?? "unknown"} (${brk?.reason ?? "broken"})`
    : inputsMismatch
      ? "inputs document hash does not match claims.inputsHash"
      : (hit?.detail ?? null);
  const findingCount = chainBreak
    ? Math.max(refFindings.length, 1)
    : refFindings.length + (issuerMismatch && pinned ? 1 : 0) + (inputsMismatch ? 1 : 0);
  const guarantee = report.guarantee;
  const summary = balanced
    ? balancedSummary(guarantee, conditions, report.summary)
    : `audit: ${Math.max(findingCount, 1)} finding(s) → FAIL`;
  const warnings = applicableWarnings.filter((f) => f.id === "issuer" || f.id === "extract").map(asWarning);
  return {
    record,
    effect,
    witnessClass,
    balanced,
    chain,
    guarantee,
    warnings,
    trustRoot: {
      pinned,
      issuerMatches: pinned ? !issuerMismatch && !warnings.some((w) => w.id === "issuer") : null,
    },
    ...(report.scope ? { scope: report.scope } : {}),
    finding: {
      code,
      label: guarantee === "conditional" || conditions.length > 0 ? "conditional" : null,
      detail,
      summary,
      ...(dropped.length > 0 ? { notApplicable: dropped } : {}),
    },
  };
}
