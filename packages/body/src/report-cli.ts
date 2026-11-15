/**
 * `verax report <stateDir> --from <YYYY-MM-DD> --to <YYYY-MM-DD>` — a period
 * evidence summary read offline from the ledger, the same way `verax verify`
 * reads: no body running, nothing on the network.
 *
 * It counts decisions, held-call approvals and checkpoints inside the window,
 * and carries the verification verdict `verax verify` would give for the whole
 * ledger. It does not judge whether a decision was right.
 */
import { createHash } from "node:crypto";
import {
  copyFileSync,
  constants as fsConstants,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

import { checkpointHash, type SignedCheckpoint } from "@cedulon/checkpoint";
import { canonical, decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import {
  listPieceFiles,
  loadApprovalsFromDir,
  readAnchors,
  readCheckpointFile,
  terminalText,
  terminalLines,
  verifyLedger,
  type VerifyResult,
} from "@verax-ai/proxy";

import { verifyApprovalSignatures, type ApprovalSignatureReport } from "./approval-signature.ts";
import { verifyControlSignatures, type ControlSignatureReport } from "./control-signature.ts";
import { readStartSummary } from "./heartbeat.ts";
import { directoryAccess, unreadableSentence } from "./install.ts";
import { EX_VERIFY_FAILED, verdictLine } from "./verify-cli.ts";

export const EX_USAGE = 64;

const DAY_MS = 86_400_000;

const WHAT_NOT_SHOWN =
  "It counts what is in the ledger. A call that never passed through the gate is not in it. A count is not a judgement that a decision was right. A held call is a signed defer counted by the time it was held; it is approved when a signed allow answers it, and still held when none does. approvals.jsonl is not the source of a count. A checkpoint is counted when its coverage overlaps the window under the same [startMs, endMs) rule the ledger uses. The report does not name the ledger directory. Verification problems are named by class only; run verax verify on the machine for the detail. A ledger that cannot be read still yields a report that says it does not verify.";

type DecisionCounts = { allow: number; deny: number; defer: number };

export type PeriodReport = {
  from: string;
  to: string;
  headHash: string | null;
  recordCount: number;
  firstRecordMs: number | null;
  lastRecordMs: number | null;
  verification: {
    ok: boolean;
    verdict: string;
    problems: string[];
  };
  decisions: {
    total: DecisionCounts;
    byTool: { [tool: string]: DecisionCounts };
  };
  approvals: {
    approved: number;
    withOperatorSignature: number;
    withoutOperatorSignature: number;
    stillHeld: number;
  };
  checkpoints: {
    count: number;
    withAnchor: number;
  };
  whatThisReportDoesNotShow: string;
};

function usage(): string {
  return [
    "usage: verax report <stateDir> --from <YYYY-MM-DD> --to <YYYY-MM-DD> [--out <file.html>] [--json]",
    "",
    "  <stateDir>     the directory holding decisions.jsonl and related ledger files",
    "  --from <date>  inclusive start of the window, UTC midnight (YYYY-MM-DD)",
    "  --to <date>    inclusive calendar end; the window is [from, to+1 day) UTC",
    "  --out <file>   write one self-contained HTML file (refuses to overwrite)",
    "  --json         one JSON object on stdout; no generation timestamp",
    "",
    "Exit code is 0 when the ledger verifies and the same non-zero code",
    "`verax verify` uses when it does not. Usage errors exit 64.",
  ].join("\n");
}

/** UTC midnight for a calendar date, or null when the string is not YYYY-MM-DD. */
export function parseReportDate(raw: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  const ms = Date.UTC(year, month - 1, day);
  const d = new Date(ms);
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) return null;
  return ms;
}

function emptyCounts(): DecisionCounts {
  return { allow: 0, deny: 0, defer: 0 };
}

function bump(counts: DecisionCounts, decision: string): void {
  if (decision === "allow") counts.allow += 1;
  else if (decision === "deny") counts.deny += 1;
  else if (decision === "defer") counts.defer += 1;
}

function readLines(path: string): string[] {
  try {
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line !== "");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

/**
 * Stable leading code or kind from a verify problem line: the text before the
 * first colon, or the leading kebab-case token when there is no colon.
 */
export function problemClass(problem: string): string {
  const colon = problem.indexOf(":");
  if (colon > 0) return problem.slice(0, colon).trim();
  const m = /^([a-z][a-z0-9-]*)\b/.exec(problem);
  if (m) return m[1]!;
  return problem;
}

function classOfThrown(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message) {
    const cls = problemClass(err.message);
    if (cls !== err.message || /^[a-z][a-z0-9-]*$/.test(cls)) return cls;
  }
  return fallback;
}

/** Decision records in chain order, using the same piece listing verify's helpers use. */
export function readDecisionRecords(dir: string): SignedDecisionRecord[] {
  const out: SignedDecisionRecord[] = [];
  for (const piece of listPieceFiles(dir)) {
    for (const line of readLines(piece.decisions)) {
      try {
        const row = JSON.parse(line) as SignedDecisionRecord;
        if (row && typeof row === "object" && row.claims && typeof row.claims === "object") out.push(row);
      } catch {
        // A torn line is the ledger statement's problem; verify names it.
      }
    }
  }
  return out;
}

function inputsForRecord(
  dir: string,
  row: SignedDecisionRecord,
): { approver?: { signature?: unknown; resolves?: unknown } } | null {
  const ref = row.claims.ref;
  const inputsHash = row.claims.inputsHash;
  if (typeof ref !== "string" || typeof inputsHash !== "string") return null;
  for (const piece of listPieceFiles(dir)) {
    for (const line of readLines(piece.inputs)) {
      try {
        const doc = JSON.parse(line) as {
          ref?: unknown;
          inputs?: { approver?: { signature?: unknown; resolves?: unknown } };
        };
        if (doc.ref !== ref || doc.inputs === undefined) continue;
        const hash = createHash("sha256").update(canonical(doc.inputs), "utf8").digest("hex");
        if (hash !== inputsHash) continue;
        return doc.inputs;
      } catch {
        // skip a torn line
      }
    }
  }
  return null;
}

function allowCarriesOperatorSignature(dir: string, allow: SignedDecisionRecord): boolean {
  const inputs = inputsForRecord(dir, allow);
  return inputs?.approver?.signature !== undefined;
}

/**
 * Cedulon/verify coverage is half-open `[startMs, endMs)` (see verify-ledger:
 * `r.claims.timestampMs >= startMs && r.claims.timestampMs < endMs`). Overlap
 * with the report window `[fromMs, toExclusive)` is therefore
 * `start < toExclusive && fromMs < end`.
 */
export function checkpointInWindow(row: SignedCheckpoint, fromMs: number, toExclusive: number): boolean {
  const start = row.claims.startMs;
  const end = row.claims.endMs;
  if (typeof start !== "number" || typeof end !== "number") return false;
  return start < toExclusive && fromMs < end;
}

const APPROVAL_NOT_CHECKED: ApprovalSignatureReport = {
  ok: true,
  signedVerified: 0,
  signedFailed: 0,
  signedAfterRemoval: 0,
  unsignedHttp: 0,
  cli: 0,
  line: "approval signatures  not checked",
  trustSource: "none",
  trustNote: "approval signatures were not checked",
};

const CONTROL_NOT_CHECKED: ControlSignatureReport = {
  ok: true,
  signedVerified: 0,
  signedFailed: 0,
  signedAfterRemoval: 0,
  unsignedHttp: 0,
  cli: 0,
  file: 0,
  integrity: 0,
  line: "control signatures   not checked",
  trustSource: "none",
  trustNote: "control signatures were not checked",
};

function failedVerifyShell(dir: string, problem: string): {
  result: VerifyResult;
  approval: ApprovalSignatureReport;
  control: ControlSignatureReport;
  verdict: string;
} {
  const result: VerifyResult = {
    ok: false,
    directory: dir,
    decisions: 0,
    effects: 0,
    signaturesValid: 0,
    signaturesInvalid: 0,
    chainBreakAt: null,
    effectsBound: 0,
    effectsOrphaned: 0,
    effectsDeferred: [],
    trust: { source: "none", publicKeyPem: null, note: problem },
    effectTrust: { source: "none", publicKeyPem: null, note: problem },
    witnessTrust: { source: "none", publicKeyPem: null, note: problem },
    checkpointTrust: { source: "none", publicKeyPem: null, note: problem },
    index: { present: false, missing: 0, line: "index: none (cannot check for removed records)" },
    effectCompleteness: "effect completeness was not checked",
    tail: {
      line: "tail: no checkpoint; removing the newest records with their effects is not detectable from these files",
      checkpoint: null,
    },
    control: { line: "control: not checked", windows: 0, warnings: [] },
    inputs: { line: "inputs: not checked", matched: 0, missing: 0, mismatched: 0 },
    anchors: { line: "anchors: not checked", receipts: 0, verified: 0, checked: false },
    problems: [problem],
  };
  return {
    result,
    approval: APPROVAL_NOT_CHECKED,
    control: CONTROL_NOT_CHECKED,
    verdict: verdictLine(result, APPROVAL_NOT_CHECKED, CONTROL_NOT_CHECKED),
  };
}

async function verifyLikeVerifyCli(dir: string): Promise<{
  result: VerifyResult;
  approval: ApprovalSignatureReport;
  control: ControlSignatureReport;
  verdict: string;
}> {
  let result: VerifyResult;
  try {
    result = await verifyLedger(dir);
  } catch (err) {
    const problem = err instanceof Error ? err.message : "ledger could not be read";
    return failedVerifyShell(dir, problem);
  }

  let approval: ApprovalSignatureReport;
  try {
    approval = await verifyApprovalSignatures(dir);
  } catch (err) {
    const problem = err instanceof Error ? err.message : "approval signatures could not be read";
    approval = { ...APPROVAL_NOT_CHECKED, ok: false, trustNote: problem };
    result = { ...result, ok: false, problems: [...result.problems, problem] };
  }
  if (approval.signedFailed > 0) {
    result = {
      ...result,
      ok: false,
      problems: [...result.problems, `approval signatures: ${approval.signedFailed} did not verify`],
    };
  }
  if (approval.signedAfterRemoval > 0) {
    result = {
      ...result,
      ok: false,
      problems: [...result.problems, `approval signatures: ${approval.signedAfterRemoval} signed after removal`],
    };
  }

  let control: ControlSignatureReport;
  try {
    control = await verifyControlSignatures(dir);
  } catch (err) {
    const problem = err instanceof Error ? err.message : "control signatures could not be read";
    control = { ...CONTROL_NOT_CHECKED, ok: false, trustNote: problem };
    result = { ...result, ok: false, problems: [...result.problems, problem] };
  }
  if (control.signedFailed > 0) {
    result = {
      ...result,
      ok: false,
      problems: [...result.problems, `control signatures: ${control.signedFailed} did not verify`],
    };
  }
  if (control.signedAfterRemoval > 0) {
    result = {
      ...result,
      ok: false,
      problems: [...result.problems, `control signatures: ${control.signedAfterRemoval} signed after removal`],
    };
  }

  const startKeyPem = result.trust.publicKeyPem ?? null;
  const starts = readStartSummary(dir, startKeyPem, "in-ledger", { requireSigned: false });
  if (starts.problems.length > 0) {
    result = { ...result, ok: false, problems: [...result.problems, ...starts.problems] };
  }

  return {
    result,
    approval,
    control,
    verdict: verdictLine(result, approval, control),
  };
}

/** Map defer ref -> signed allow that answers it via inputs.approver.resolves. */
function allowsAnsweringDefers(dir: string, all: SignedDecisionRecord[]): Map<string, SignedDecisionRecord> {
  const out = new Map<string, SignedDecisionRecord>();
  for (const row of all) {
    if (row.claims.decision !== "allow") continue;
    const inputs = inputsForRecord(dir, row);
    const resolves = inputs?.approver?.resolves;
    if (typeof resolves === "string" && resolves !== "") out.set(resolves, row);
  }
  return out;
}

function countApprovalsFromSigned(
  dir: string,
  all: SignedDecisionRecord[],
  fromMs: number,
  toExclusive: number,
): {
  approved: number;
  withOperatorSignature: number;
  withoutOperatorSignature: number;
  stillHeld: number;
} {
  const answering = allowsAnsweringDefers(dir, all);
  let approved = 0;
  let withOperatorSignature = 0;
  let withoutOperatorSignature = 0;
  let stillHeld = 0;
  for (const row of all) {
    if (row.claims.decision !== "defer") continue;
    const ts = row.claims.timestampMs;
    if (typeof ts !== "number" || ts < fromMs || ts >= toExclusive) continue;
    const ref = row.claims.ref;
    if (typeof ref !== "string") continue;
    const allow = answering.get(ref);
    if (!allow) {
      stillHeld += 1;
      continue;
    }
    approved += 1;
    if (allowCarriesOperatorSignature(dir, allow)) withOperatorSignature += 1;
    else withoutOperatorSignature += 1;
  }
  return { approved, withOperatorSignature, withoutOperatorSignature, stillHeld };
}

function writeOutExclusive(outPath: string, content: string): void {
  const tmp = join(dirname(outPath), `.verax-report-${process.pid}-${Date.now()}.tmp`);
  try {
    writeFileSync(tmp, content, "utf8");
    copyFileSync(tmp, outPath, fsConstants.COPYFILE_EXCL);
    unlinkSync(tmp);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // best-effort cleanup
    }
    throw err;
  }
}

export async function buildPeriodReport(
  dir: string,
  from: string,
  to: string,
  fromMs: number,
  toExclusive: number,
): Promise<PeriodReport> {
  const earlyProblems: string[] = [];

  let all: SignedDecisionRecord[] = [];
  try {
    all = readDecisionRecords(dir);
  } catch (err) {
    earlyProblems.push(classOfThrown(err, "ledger-unreadable"));
  }

  // Candidates only: a malformed line must not abort the report, and must not
  // be the source of a count.
  try {
    loadApprovalsFromDir(dir);
  } catch {
    earlyProblems.push("approvals-malformed");
  }

  let headHash: string | null = null;
  if (all.length > 0) {
    try {
      headHash = decisionRecordHash(all[all.length - 1]!);
    } catch {
      headHash = null;
    }
  }

  const inWindow = all.filter((r) => {
    const ts = r.claims.timestampMs;
    return typeof ts === "number" && ts >= fromMs && ts < toExclusive;
  });

  const total = emptyCounts();
  const byToolMap = new Map<string, DecisionCounts>();
  let firstRecordMs: number | null = null;
  let lastRecordMs: number | null = null;
  for (const row of inWindow) {
    const ts = row.claims.timestampMs as number;
    if (firstRecordMs === null || ts < firstRecordMs) firstRecordMs = ts;
    if (lastRecordMs === null || ts > lastRecordMs) lastRecordMs = ts;
    const decision = row.claims.decision;
    if (typeof decision !== "string") continue;
    bump(total, decision);
    const tool = typeof row.claims.subject === "string" ? row.claims.subject : "";
    if (tool === "") continue;
    let counts = byToolMap.get(tool);
    if (!counts) {
      counts = emptyCounts();
      byToolMap.set(tool, counts);
    }
    bump(counts, decision);
  }

  // Own keys only: tool names such as __proto__ must not hit Object.prototype.
  const byTool: { [tool: string]: DecisionCounts } = Object.create(null);
  for (const tool of [...byToolMap.keys()].sort()) {
    byTool[tool] = byToolMap.get(tool)!;
  }

  let approvals = {
    approved: 0,
    withOperatorSignature: 0,
    withoutOperatorSignature: 0,
    stillHeld: 0,
  };
  try {
    approvals = countApprovalsFromSigned(dir, all, fromMs, toExclusive);
  } catch (err) {
    earlyProblems.push(classOfThrown(err, "approvals-unreadable"));
  }

  let withAnchor = 0;
  let checkpointCount = 0;
  try {
    const anchors = readAnchors(dir);
    const anchored = new Set(anchors.rows.map((r) => r.checkpointHash));
    const checkpoints = readCheckpointFile(dir).rows.filter((row) =>
      checkpointInWindow(row, fromMs, toExclusive),
    );
    checkpointCount = checkpoints.length;
    for (const row of checkpoints) {
      try {
        if (anchored.has(checkpointHash(row))) withAnchor += 1;
      } catch {
        // A row that cannot be hashed is not counted as anchored.
      }
    }
  } catch {
    earlyProblems.push("anchors-unreadable");
  }

  let verified = await verifyLikeVerifyCli(dir);
  if (earlyProblems.length > 0) {
    const problems = [...earlyProblems, ...verified.result.problems];
    const result = { ...verified.result, ok: false, problems };
    verified = {
      result,
      approval: verified.approval,
      control: verified.control,
      verdict: verdictLine(result, verified.approval, verified.control),
    };
  }

  const problemClasses = [...new Set(verified.result.problems.map(problemClass))];

  return {
    from,
    to,
    headHash,
    recordCount: inWindow.length,
    firstRecordMs,
    lastRecordMs,
    verification: {
      ok: verified.result.ok,
      verdict: verified.verdict,
      problems: problemClasses,
    },
    decisions: { total, byTool },
    approvals,
    checkpoints: {
      count: checkpointCount,
      withAnchor,
    },
    whatThisReportDoesNotShow: WHAT_NOT_SHOWN,
  };
}

/** Fixed key order. The same ledger and window give the same bytes. */
export function serializePeriodReport(report: PeriodReport): string {
  const byToolEntries = Object.keys(report.decisions.byTool)
    .sort()
    .map((tool) => {
      const c = report.decisions.byTool[tool]!;
      return [
        JSON.stringify(tool),
        `{"allow":${c.allow},"deny":${c.deny},"defer":${c.defer}}`,
      ].join(":");
    });
  const byToolJson = `{${byToolEntries.join(",")}}`;
  const problemsJson = `[${report.verification.problems.map((p) => JSON.stringify(p)).join(",")}]`;
  return (
    "{" +
    [
      `"from":${JSON.stringify(report.from)}`,
      `"to":${JSON.stringify(report.to)}`,
      `"headHash":${JSON.stringify(report.headHash)}`,
      `"recordCount":${report.recordCount}`,
      `"firstRecordMs":${report.firstRecordMs === null ? "null" : String(report.firstRecordMs)}`,
      `"lastRecordMs":${report.lastRecordMs === null ? "null" : String(report.lastRecordMs)}`,
      `"verification":{"ok":${report.verification.ok},"verdict":${JSON.stringify(report.verification.verdict)},"problems":${problemsJson}}`,
      `"decisions":{"total":{"allow":${report.decisions.total.allow},"deny":${report.decisions.total.deny},"defer":${report.decisions.total.defer}},"byTool":${byToolJson}}`,
      `"approvals":{"approved":${report.approvals.approved},"withOperatorSignature":${report.approvals.withOperatorSignature},"withoutOperatorSignature":${report.approvals.withoutOperatorSignature},"stillHeld":${report.approvals.stillHeld}}`,
      `"checkpoints":{"count":${report.checkpoints.count},"withAnchor":${report.checkpoints.withAnchor}}`,
      `"whatThisReportDoesNotShow":${JSON.stringify(report.whatThisReportDoesNotShow)}`,
    ].join(",") +
    "}"
  );
}

export function reportDigest(jsonBytes: string): string {
  return createHash("sha256").update(jsonBytes, "utf8").digest("hex");
}

export function htmlEscape(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderReportHtml(report: PeriodReport, digest: string): string {
  const toolRows = Object.keys(report.decisions.byTool)
    .sort()
    .map((tool) => {
      const c = report.decisions.byTool[tool]!;
      return `<tr><td>${htmlEscape(tool)}</td><td>${c.allow}</td><td>${c.deny}</td><td>${c.defer}</td></tr>`;
    })
    .join("");
  const problemItems = report.verification.problems
    .map((p) => `<li>${htmlEscape(p)}</li>`)
    .join("");
  const problemsBlock =
    report.verification.problems.length === 0
      ? "<p>No verification problems named.</p>"
      : `<p>${report.verification.problems.length} problem class(es). Run <code>verax verify</code> on the machine for the detail.</p><ul>${problemItems}</ul>`;

  return [
    "<!DOCTYPE html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    "<title>Period report</title>",
    "<style>",
    "body{font-family:ui-sans-serif,system-ui,sans-serif;margin:2rem;line-height:1.45;color:#111}",
    "h1{font-size:1.5rem;margin:0 0 0.5rem}",
    "h2{font-size:1.1rem;margin:1.5rem 0 0.5rem}",
    "table{border-collapse:collapse;margin:0.5rem 0}",
    "th,td{border:1px solid #ccc;padding:0.35rem 0.6rem;text-align:left}",
    ".verdict{font-weight:600;margin:0.75rem 0}",
    ".digest{margin-top:2rem;font-size:0.95rem}",
    "code{word-break:break-all}",
    "</style>",
    "</head>",
    "<body>",
    "<h1>Period report</h1>",
    `<p class="verdict">${htmlEscape(report.verification.verdict)}</p>`,
    `<p>Window ${htmlEscape(report.from)} to ${htmlEscape(report.to)} (UTC).</p>`,
    `<p>Records in window: ${report.recordCount}. First record time: ${report.firstRecordMs === null ? "none" : String(report.firstRecordMs)}. Last record time: ${report.lastRecordMs === null ? "none" : String(report.lastRecordMs)}. Ledger head hash: ${htmlEscape(report.headHash ?? "none")}.</p>`,
    "<h2>Decisions</h2>",
    `<p>Total: allow ${report.decisions.total.allow}, deny ${report.decisions.total.deny}, defer ${report.decisions.total.defer}.</p>`,
    "<table><thead><tr><th>Tool</th><th>Allow</th><th>Deny</th><th>Defer</th></tr></thead>",
    `<tbody>${toolRows}</tbody></table>`,
    "<h2>Approvals</h2>",
    `<p>Approved held calls: ${report.approvals.approved} (${report.approvals.withOperatorSignature} with an operator signature, ${report.approvals.withoutOperatorSignature} without). Still held: ${report.approvals.stillHeld}.</p>`,
    "<h2>Checkpoints</h2>",
    `<p>Checkpoints in the window: ${report.checkpoints.count}. With an anchor row: ${report.checkpoints.withAnchor}.</p>`,
    "<h2>Verification</h2>",
    problemsBlock,
    "<h2>What this report does not show</h2>",
    `<p>${htmlEscape(report.whatThisReportDoesNotShow)}</p>`,
    `<p class="digest">Report digest (SHA-256 of the JSON form): <code>${htmlEscape(digest)}</code></p>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

export function renderReportText(report: PeriodReport, digest: string): string {
  const lines: string[] = [];
  lines.push(report.verification.verdict);
  lines.push(`window        ${report.from} .. ${report.to} (UTC)`);
  lines.push(`records       ${report.recordCount}`);
  lines.push(`first         ${report.firstRecordMs === null ? "none" : String(report.firstRecordMs)}`);
  lines.push(`last          ${report.lastRecordMs === null ? "none" : String(report.lastRecordMs)}`);
  lines.push(`head          ${report.headHash ?? "none"}`);
  lines.push(
    `decisions     allow ${report.decisions.total.allow}, deny ${report.decisions.total.deny}, defer ${report.decisions.total.defer}`,
  );
  for (const tool of Object.keys(report.decisions.byTool).sort()) {
    const c = report.decisions.byTool[tool]!;
    lines.push(`  ${tool}  allow ${c.allow}, deny ${c.deny}, defer ${c.defer}`);
  }
  lines.push(
    `approvals     approved ${report.approvals.approved} (signed ${report.approvals.withOperatorSignature}, unsigned ${report.approvals.withoutOperatorSignature}), still held ${report.approvals.stillHeld}`,
  );
  lines.push(`checkpoints   ${report.checkpoints.count} in window, ${report.checkpoints.withAnchor} with an anchor`);
  if (report.verification.problems.length > 0) {
    lines.push(`problems      ${report.verification.problems.length} class(es); run verax verify on the machine for the detail`);
    for (const p of report.verification.problems.slice(0, 50)) lines.push(`  - ${p}`);
    if (report.verification.problems.length > 50) {
      lines.push(`  ... and ${report.verification.problems.length - 50} more`);
    }
  }
  lines.push("");
  lines.push(`What this report does not show: ${report.whatThisReportDoesNotShow}`);
  lines.push(`digest        ${digest}`);
  return lines.map((line) => terminalText(line)).join("\n");
}

type ParsedArgs =
  | {
      ok: true;
      dir: string;
      from: string;
      to: string;
      fromMs: number;
      toExclusive: number;
      json: boolean;
      outPath: string | null;
    }
  | { ok: false; message: string };

function parseArgs(argv: readonly string[]): ParsedArgs {
  const args = [...argv];
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return { ok: false, message: usage() };
  }

  let from: string | undefined;
  let to: string | undefined;
  let outPath: string | null = null;
  let json = false;
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "--json") {
      json = true;
      continue;
    }
    if (a === "--from") {
      const v = args[i + 1];
      if (!v || v.startsWith("-")) return { ok: false, message: "report: --from needs a YYYY-MM-DD date" };
      from = v;
      i += 1;
      continue;
    }
    if (a === "--to") {
      const v = args[i + 1];
      if (!v || v.startsWith("-")) return { ok: false, message: "report: --to needs a YYYY-MM-DD date" };
      to = v;
      i += 1;
      continue;
    }
    if (a === "--out") {
      const v = args[i + 1];
      if (!v || v.startsWith("-")) return { ok: false, message: "report: --out needs a file path" };
      outPath = v;
      i += 1;
      continue;
    }
    if (a.startsWith("-")) {
      return { ok: false, message: `report: unknown option ${a}` };
    }
    positionals.push(a);
  }

  if (positionals.length !== 1) {
    return { ok: false, message: "report: one ledger directory is required" };
  }
  if (from === undefined || to === undefined) {
    return { ok: false, message: "report: --from and --to are required (YYYY-MM-DD)" };
  }
  const fromMs = parseReportDate(from);
  const toStart = parseReportDate(to);
  if (fromMs === null || toStart === null) {
    return { ok: false, message: "report: --from and --to must be YYYY-MM-DD calendar dates" };
  }
  if (fromMs > toStart) {
    return { ok: false, message: "report: --from must not be after --to" };
  }
  return {
    ok: true,
    dir: positionals[0]!,
    from,
    to,
    fromMs,
    toExclusive: toStart + DAY_MS,
    json,
    outPath,
  };
}

export async function runReport(
  argv: readonly string[],
  out: (s: string) => void = (s) => process.stdout.write(`${s}\n`),
): Promise<number> {
  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    out(parsed.message.startsWith("usage:") ? parsed.message : terminalText(parsed.message));
    return argv.length === 0 || argv[0] === "--help" || argv[0] === "-h" ? (argv.length === 0 ? EX_USAGE : 0) : EX_USAGE;
  }

  if (directoryAccess(parsed.dir) === "unreadable") {
    out(terminalText(unreadableSentence(parsed.dir, "report")));
    return 77;
  }

  let report: PeriodReport;
  try {
    report = await buildPeriodReport(parsed.dir, parsed.from, parsed.to, parsed.fromMs, parsed.toExclusive);
  } catch (err) {
    const cls = classOfThrown(err, "ledger-unreadable");
    const shell = failedVerifyShell(parsed.dir, cls);
    report = {
      from: parsed.from,
      to: parsed.to,
      headHash: null,
      recordCount: 0,
      firstRecordMs: null,
      lastRecordMs: null,
      verification: {
        ok: false,
        verdict: shell.verdict,
        problems: [cls],
      },
      decisions: { total: emptyCounts(), byTool: Object.create(null) },
      approvals: {
        approved: 0,
        withOperatorSignature: 0,
        withoutOperatorSignature: 0,
        stillHeld: 0,
      },
      checkpoints: { count: 0, withAnchor: 0 },
      whatThisReportDoesNotShow: WHAT_NOT_SHOWN,
    };
  }

  const json = serializePeriodReport(report);
  const digest = reportDigest(json);

  if (parsed.outPath !== null) {
    try {
      writeOutExclusive(parsed.outPath, renderReportHtml(report, digest));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EEXIST") {
        out(terminalText(`report: refusing to overwrite ${parsed.outPath}`));
        return EX_USAGE;
      }
      out(terminalText(`report: could not write ${basename(parsed.outPath)}`));
      return EX_USAGE;
    }
  }

  if (parsed.json) {
    out(terminalLines(json));
  } else if (parsed.outPath === null) {
    out(renderReportText(report, digest));
  } else {
    out(terminalText(`wrote ${parsed.outPath}`));
    out(terminalText(`digest ${digest}`));
  }

  return report.verification.ok ? 0 : EX_VERIFY_FAILED;
}
