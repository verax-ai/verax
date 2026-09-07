import { audit, DECISION_PROFILE, type Finding, type IssuerTrustPin, type PresentedExtract } from "@cedulon/audit";
import { findDecisionRecordChainBreak } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";
import { approvalsLogFor, type ApprovalsLog } from "./approvals.ts";
import { sha256Canonical } from "./hash.ts";
import { inputsLogFor } from "./inputs.ts";
import { lookupResolvedBy } from "./ledger.ts";
import { loadCheckpoints } from "./checkpoints.ts";
import type { ExplainOpts, ExplainPair, ExplainResult, ExplainWarning, InputsLog, Ledger } from "./types.ts";

async function pairFor(
  ledger: Ledger,
  decisions: SignedDecisionRecord[],
  record: SignedDecisionRecord,
  inputsLog: InputsLog,
  approvals: ApprovalsLog,
): Promise<ExplainPair> {
  const ref = record.claims.ref;
  if (!ref) return { defer: null, resolution: null };
  if (record.claims.decision === "defer") {
    const snap = await approvals.get(ref);
    if (snap?.allowRef) {
      const resolution = decisions.find((d) => d.claims.ref === snap.allowRef) ?? null;
      return { defer: record, resolution };
    }
    const hit = lookupResolvedBy(ledger, ref);
    if (hit) {
      const resolution = decisions.find((d) => d.claims.ref === hit.ref) ?? null;
      return { defer: record, resolution };
    }
    return { defer: null, resolution: null };
  }
  const own = await inputsLog.get(ref);
  if (own?.approver?.resolves) {
    const defer = decisions.find((d) => d.claims.ref === own.approver?.resolves) ?? null;
    return { defer, resolution: record };
  }
  return { defer: null, resolution: null };
}

const WINDOW_COVERAGE = "window-coverage";

function resolveIssuerTrust(opts?: ExplainOpts): {
  pin: IssuerTrustPin | undefined;
  source: "env" | "own-key" | null;
} {
  if (opts?.issuerTrust) {
    return {
      pin: { publicKeyPem: opts.issuerTrust.publicKeyPem },
      source: opts.issuerTrust.source ?? null,
    };
  }
  const env = process.env.VERAX_RECORD_PUBKEY_PIN;
  if (typeof env === "string" && env.trim() !== "") {
    return { pin: { publicKeyPem: env }, source: "env" };
  }
  return { pin: undefined, source: null };
}

function asWarning(f: Finding): ExplainWarning {
  return { id: f.id, code: f.code, detail: f.detail };
}

function conditionName(f: Finding, extractPresented: boolean): string | null {
  if (f.code === "unauthenticated-issuer") return "issuer unpinned";
  if (f.code === "unauthenticated-extract") {
    // Name from whether an extract was handed to audit, not Cedulon detail text.
    return extractPresented ? "extract unpinned" : "extract unsigned";
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
 * are Cedulon's; this wrapper does not invent names. With no durable
 * checkpoint on disk, window-coverage is listed as notApplicable and
 * dropped from the finding set before balanced is computed. When
 * `checkpoints.jsonl` has at least one signed row, that finding is kept.
 * General issuer/extract warnings and the audit guarantee are kept. A
 * self witness and each general Cedulon warning are named in the
 * condition list; "balanced" is never written alone, and "conditional"
 * is never written twice.
 */
export async function explain(ledger: Ledger, ref: string, opts?: ExplainOpts): Promise<ExplainResult> {
  const decisions = await ledger.decisions();
  const effects = await ledger.effects();
  const record = decisions.find((d) => d.claims.ref === ref);
  if (!record) {
    throw new Error(`explain-unknown-ref:${ref}`);
  }
  const effect = effects.find((e) => e.row.ref === ref && e.row.effectClass !== "duplicate-effect") ?? null;
  const presentedExtract = opts?.extract ?? effect?.receipt;
  const extractPresented = Boolean(presentedExtract);
  const resolvedTrust = resolveIssuerTrust(opts);
  const issuerTrust = resolvedTrust.pin;
  const pinSource = resolvedTrust.source;
  const pinned = issuerTrust !== undefined;
  const dir = (ledger as { dir?: unknown }).dir;
  const checkpoints = typeof dir === "string" ? loadCheckpoints(dir) : [];
  const report = audit({
    receipts: decisions,
    checkpoints,
    settlements: effects.map((e) => e.row),
    profile: DECISION_PROFILE,
    ...(issuerTrust ? { issuerTrust } : {}),
    ...(presentedExtract ? { extract: presentedExtract } : {}),
  });
  const dropWindow = checkpoints.length === 0;
  const dropped = dropWindow
    ? [
        ...new Set(
          [...report.findings, ...report.warnings]
            .filter((f) => f.code === WINDOW_COVERAGE)
            .map((f) => f.code),
        ),
      ]
    : [];
  const applicable = dropWindow
    ? report.findings.filter((f) => f.code !== WINDOW_COVERAGE)
    : report.findings;
  const applicableWarnings = dropWindow
    ? report.warnings.filter((f) => f.code !== WINDOW_COVERAGE)
    : report.warnings;
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
  if (pinSource === "own-key") conditions.push("issuer pinned to own key");
  for (const w of applicableWarnings) {
    const name = conditionName(w, extractPresented);
    if (name && !conditions.includes(name)) conditions.push(name);
  }
  const issuerMismatch = applicable.concat(applicableWarnings).some(
    (f) => f.code === "issuer-key-mismatch" || (pinned && f.code === "unauthenticated-issuer"),
  );
  const inputsLog = opts?.inputsLog ?? inputsLogFor(ledger);
  const approvals = approvalsLogFor(ledger);
  const inputsDoc = record.claims.ref ? await inputsLog.get(record.claims.ref) : null;
  const inputsMismatch = Boolean(
    inputsDoc &&
      typeof record.claims.inputsHash === "string" &&
      sha256Canonical(inputsDoc) !== record.claims.inputsHash,
  );
  const inputsMissing =
    typeof record.claims.inputsHash === "string" && inputsDoc === null;
  if (inputsMissing) conditions.push("inputs document missing");
  const balanced = refFindings.length === 0 && !chainBreak && !issuerMismatch && !inputsMismatch && !inputsMissing;
  const code = chainBreak
    ? "receipt-chain-break"
    : inputsMismatch
      ? "inputs-hash-mismatch"
      : inputsMissing
        ? "inputs-document-missing"
        : (hit?.code ?? null);
  const detail = chainBreak
    ? `receipt-chain-break at ${breakAt ?? "unknown"} (${brk?.reason ?? "broken"})`
    : inputsMismatch
      ? "inputs document hash does not match claims.inputsHash"
      : inputsMissing
        ? "claims.inputsHash is on the record; the inputs document is not on disk"
        : (hit?.detail ?? null);
  const findingCount = chainBreak
    ? Math.max(refFindings.length, 1)
    : refFindings.length +
      (issuerMismatch && pinned ? 1 : 0) +
      (inputsMismatch ? 1 : 0) +
      (inputsMissing ? 1 : 0);
  const guarantee = report.guarantee;
  const summary = balanced
    ? balancedSummary(guarantee, conditions, report.summary)
    : `audit: ${Math.max(findingCount, 1)} finding(s) → FAIL`;
  const warnings = applicableWarnings.filter((f) => f.id === "issuer" || f.id === "extract").map(asWarning);
  if (inputsMissing) {
    warnings.push({
      id: "inputs",
      code: "inputs-document-missing",
      detail: "claims.inputsHash is on the record; the inputs document is not on disk",
    });
  }
  return {
    record,
    effect,
    pair: await pairFor(ledger, decisions, record, inputsLog, approvals),
    witnessClass,
    balanced,
    chain,
    guarantee,
    warnings,
    trustRoot: {
      pinned,
      issuerMatches: pinned ? !issuerMismatch && !warnings.some((w) => w.id === "issuer") : null,
      source: pinSource,
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
