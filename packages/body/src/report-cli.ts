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
import { existsSync, readFileSync, writeFileSync } from "node:fs";

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
  type ApprovalRow,
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
  "It counts what is in the ledger. A call that never passed through the gate is not in it. A count is not a judgement that a decision was right.";

type DecisionCounts = { allow: number; deny: number; defer: number };

export type PeriodReport = {
  from: string;
  to: string;
  directory: string;
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

function allowCarriesOperatorSignature(dir: string, allow: SignedDecisionRecord): boolean {
  const ref = allow.claims.ref;
  const inputsHash = allow.claims.inputsHash;
  if (typeof ref !== "string" || typeof inputsHash !== "string") return false;
  for (const piece of listPieceFiles(dir)) {
    for (const line of readLines(piece.inputs)) {
      try {
        const row = JSON.parse(line) as { ref?: unknown; inputs?: { approver?: { signature?: unknown } } };
        if (row.ref !== ref || row.inputs === undefined) continue;
        const hash = createHash("sha256").update(canonical(row.inputs), "utf8").digest("hex");
        if (hash !== inputsHash) continue;
        return row.inputs.approver?.signature !== undefined;
      } catch {
        // skip a torn line
      }
    }
  }
  return false;
}

function checkpointInWindow(row: SignedCheckpoint, fromMs: number, toExclusive: number): boolean {
  const start = row.claims.startMs;
  const end = row.claims.endMs;
  if (typeof start !== "number" || typeof end !== "number") return false;
  return start < toExclusive && end >= fromMs;
}

/** When the hold entered the ledger. Approval time may fall outside the period. */
function holdTimeMs(row: ApprovalRow): number | null {
  if (typeof row.createdAtMs === "number") return row.createdAtMs;
  return null;
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
    result = {
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

export async function buildPeriodReport(
  dir: string,
  from: string,
  to: string,
  fromMs: number,
  toExclusive: number,
): Promise<PeriodReport> {
  const all = readDecisionRecords(dir);
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

  const byTool: { [tool: string]: DecisionCounts } = {};
  for (const tool of [...byToolMap.keys()].sort()) {
    byTool[tool] = byToolMap.get(tool)!;
  }

  // Approvals whose hold time falls in the window. Argument values stay out of the report.
  const allowsByRef = new Map<string, SignedDecisionRecord>();
  for (const row of all) {
    if (row.claims.decision === "allow" && typeof row.claims.ref === "string") {
      allowsByRef.set(row.claims.ref, row);
    }
  }

  let approved = 0;
  let withOperatorSignature = 0;
  let withoutOperatorSignature = 0;
  let stillHeld = 0;
  for (const row of loadApprovalsFromDir(dir)) {
    const at = holdTimeMs(row);
    if (at === null || at < fromMs || at >= toExclusive) continue;
    if (row.status === "pending") {
      stillHeld += 1;
      continue;
    }
    if (row.status !== "approved") continue;
    approved += 1;
    const allow = typeof row.allowRef === "string" ? allowsByRef.get(row.allowRef) : undefined;
    if (allow && allowCarriesOperatorSignature(dir, allow)) withOperatorSignature += 1;
    else withoutOperatorSignature += 1;
  }

  const anchors = readAnchors(dir);
  const anchored = new Set(anchors.rows.map((r) => r.checkpointHash));
  const checkpoints = readCheckpointFile(dir).rows.filter((row) => checkpointInWindow(row, fromMs, toExclusive));
  let withAnchor = 0;
  for (const row of checkpoints) {
    try {
      if (anchored.has(checkpointHash(row))) withAnchor += 1;
    } catch {
      // A row that cannot be hashed is not counted as anchored.
    }
  }

  const verified = await verifyLikeVerifyCli(dir);

  return {
    from,
    to,
    directory: dir,
    headHash,
    recordCount: inWindow.length,
    firstRecordMs,
    lastRecordMs,
    verification: {
      ok: verified.result.ok,
      verdict: verified.verdict,
      problems: [...verified.result.problems],
    },
    decisions: { total, byTool },
    approvals: {
      approved,
      withOperatorSignature,
      withoutOperatorSignature,
      stillHeld,
    },
    checkpoints: {
      count: checkpoints.length,
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
      `"directory":${JSON.stringify(report.directory)}`,
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
      : `<ul>${problemItems}</ul>`;

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
    `<p>Window ${htmlEscape(report.from)} to ${htmlEscape(report.to)} (UTC). Ledger ${htmlEscape(report.directory)}.</p>`,
    `<p>Records in window: ${report.recordCount}. First record time: ${report.firstRecordMs === null ? "none" : String(report.firstRecordMs)}. Last record time: ${report.lastRecordMs === null ? "none" : String(report.lastRecordMs)}. Ledger head hash: ${htmlEscape(report.headHash ?? "none")}.</p>`,
    "<h2>Decisions</h2>",
    `<p>Total — allow ${report.decisions.total.allow}, deny ${report.decisions.total.deny}, defer ${report.decisions.total.defer}.</p>`,
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
  lines.push(`ledger        ${report.directory}`);
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
    lines.push("problems:");
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

  if (parsed.outPath !== null && existsSync(parsed.outPath)) {
    out(terminalText(`report: refusing to overwrite ${parsed.outPath}`));
    return EX_USAGE;
  }

  const report = await buildPeriodReport(parsed.dir, parsed.from, parsed.to, parsed.fromMs, parsed.toExclusive);
  const json = serializePeriodReport(report);
  const digest = reportDigest(json);

  if (parsed.outPath !== null) {
    writeFileSync(parsed.outPath, renderReportHtml(report, digest), "utf8");
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
