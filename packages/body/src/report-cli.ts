/**
 * `verax report <stateDir> --from <YYYY-MM-DD> --to <YYYY-MM-DD>` — a period
 * evidence summary read offline from the ledger, the same way `verax verify`
 * reads: no body running, nothing on the network.
 *
 * It counts decisions, held-call approvals and checkpoints inside the window,
 * and carries the verification verdict `verax verify` would give for the whole
 * ledger. It does not judge whether a decision was right.
 *
 * Counts come only from the records and checkpoints `verifyLedger` attested,
 * and only when the ledger verifies. A ledger that does not verify yields
 * `null` for every count: unverified material is never counted.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  linkSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { checkpointHash, type SignedCheckpoint } from "@cedulon/checkpoint";
import { canonical, decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import {
  listPieceFiles,
  loadApprovalsFromDir,
  readAnchors,
  terminalLines,
  terminalText,
  verifyLedger,
  type VerifyResult,
} from "@verax-ai/proxy";

import { type ApprovalSignatureReport } from "./approval-signature.ts";
import { type ControlSignatureReport } from "./control-signature.ts";
import { directoryAccess, EX_ELEVATION } from "./install.ts";
import { completeVerify, EX_VERIFY_FAILED, verdictLine } from "./verify-cli.ts";

export const EX_USAGE = 64;
/** Same code `verax verify` uses for an unreadable state directory. */
export const EX_STATE_UNREADABLE = EX_ELEVATION;

const DAY_MS = 86_400_000;

const COUNTS_UNAVAILABLE_REASON =
  "the ledger did not verify; nothing is counted from unverified records (see the verification problem classes)";

const UNSIGNED_APPROVALS_NOTE =
  "approvals.jsonl could not be parsed cleanly. It is an unsigned candidate file: it is not a source of any count and it does not change the verdict.";

const WHAT_NOT_SHOWN =
  "It counts what is in the ledger. A call that never passed through the gate is not in it. A count is not a judgement that a decision was right. Counts are taken only from records and checkpoints that verification attested, and only when the ledger verifies; when it does not, every count is null. A held call is a signed defer counted by the time it was held. It is approved when the first signed allow or deny that follows it in chain order, names it, and agrees on request hash and tool, is an allow; it is closed without an allow when that first answer is a deny (expired or otherwise); it is still held when no signed bound answer exists and no later unbound record could have answered it; when a held defer could have been answered by an unbound record anywhere after it in chain order, stillHeld is not established and the report says how many held records an unbound inputs row could have answered; it is unmatched when the defer has no usable reference, shares its reference with another defer, or its only bound answers disagree on request hash or tool. A signature field present on an approving record is not a verified operator signature in this report; signature verification is part of the verdict. approvals.jsonl is not the source of a count. A checkpoint is counted when its coverage overlaps the window under the same [startMs, endMs) rule the ledger uses and its start is before its end. The report verifies with default options only (no key pins, operator credentials, anchor requirements or signed-start requirement), so anchor rows are only counted as present and not checked. The report does not name the ledger directory. Verification problems are named by class only; run verax verify on the machine for the detail. A ledger that cannot be read still yields a report that says it does not verify.";

type DecisionCounts = { allow: number; deny: number; defer: number };

export type ApprovalCounts = {
  approved: number;
  withOperatorSignatureFieldPresent: number;
  withoutOperatorSignatureField: number;
  closedWithoutAllow: number;
  /**
   * Defers with no hash-bound answer. Established as a fact only when no held
   * defer could be answered by an unbound record after it; otherwise null
   * (see heldWithoutBoundAnswer / heldPossiblyAnsweredByUnbound).
   */
  stillHeld: number | null;
  unmatched: number;
  /** Allow/deny records in the window whose inputs are not hash-bound. */
  terminalsWithoutBoundInputs: number;
  /** Defers with no hash-bound answer (raw open count; always computed). */
  heldWithoutBoundAnswer: number;
  /**
   * Of those held without a bound answer, how many an unbound terminal's
   * inputs row names with matching request hash and tool.
   */
  heldPossiblyAnsweredByUnbound: number;
};

export type PeriodReport = {
  from: string;
  to: string;
  /** Head of the whole verified ledger. Null when the ledger does not verify. */
  headHash: string | null;
  /** Records in the window. Null when the ledger does not verify. */
  recordCount: number | null;
  firstRecordMs: number | null;
  lastRecordMs: number | null;
  verification: {
    ok: boolean;
    verdict: string;
    problems: string[];
  };
  /** Why every count is null, or null when counts are available. */
  countsUnavailableReason: string | null;
  /** Set when approvals.jsonl is malformed. Never affects verdict or counts. */
  unsignedApprovalsNote: string | null;
  decisions: {
    total: DecisionCounts | null;
    byTool: { [tool: string]: DecisionCounts } | null;
    /**
     * Records whose subject is empty or not a string. Null when counts are
     * unavailable. Identity: for each kind, sum(byTool[*][kind]) +
     * withoutSubject[kind] === total[kind].
     */
    withoutSubject: DecisionCounts | null;
  };
  approvals: {
    approved: number | null;
    /** Approving records whose hash-bound inputs carry an approver signature field. Not a verification. */
    withOperatorSignatureFieldPresent: number | null;
    withoutOperatorSignatureField: number | null;
    closedWithoutAllow: number | null;
    stillHeld: number | null;
    unmatched: number | null;
    /** Allow/deny in the window with no hash-bound inputs. Null when counts unavailable. */
    terminalsWithoutBoundInputs: number | null;
    /** Defers with no hash-bound answer. Null when counts unavailable. */
    heldWithoutBoundAnswer: number | null;
    /** Held defers an unbound terminal's inputs row could answer. Null when counts unavailable. */
    heldPossiblyAnsweredByUnbound: number | null;
    /** Class only, when approvals could not be counted although the ledger verified. */
    unavailableReason: string | null;
  };
  checkpoints: {
    count: number | null;
    /** Anchor receipts for window checkpoints that verified. Zero when anchors were not checked. */
    withAnchorVerified: number | null;
    /** Anchor rows for window checkpoints present but not checked (no anchor key). */
    anchorRowsPresentNotChecked: number | null;
    /** Class only, when anchors could not be read although the ledger verified. */
    anchorUnavailableReason: string | null;
  };
  whatThisReportDoesNotShow: string;
};

function usage(): string {
  return [
    "usage: verax report <stateDir> --from <YYYY-MM-DD> --to <YYYY-MM-DD> [--out <file.html>] [--json]",
    "",
    "  <stateDir>     the directory holding decisions.jsonl and related ledger files",
    "  --from <date>  inclusive start of the window, UTC midnight (YYYY-MM-DD)",
    "  --to <date>    the last day, included in full; the window is [from, to + 1 day) UTC",
    "  --out <file>   write one self-contained HTML file (refuses to overwrite, and",
    "                 refuses a path inside <stateDir>)",
    "  --json         one JSON object on stdout; no generation timestamp",
    "",
    "Counts come only from ledger records that verified. When the ledger does not",
    "verify, every count is null and the report says NOT VERIFIED.",
    "The report verifies with default options only: it does not accept key pins,",
    "--operator-credentials, --require-anchored, --anchor-key, or",
    "--require-signed-starts. Run verax verify with those flags when you need them.",
    "Exit code is 0 when the ledger verifies and the same non-zero code",
    "`verax verify` uses when it does not (an unreadable directory included).",
    "Usage errors exit 64.",
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

/**
 * Usable per-tool subject, or null when empty or not a string. Null subjects
 * are counted in `withoutSubject`, not under a synthetic byTool key, so a
 * real tool named U+001F cannot collide with the empty/missing bucket.
 */
export function subjectToolKey(subject: unknown): string | null {
  if (typeof subject === "string" && subject !== "") return subject;
  return null;
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
 * Known verify / report problem-class prefixes, taken from the strings the
 * verifier and `completeVerify` push into `problems` (and the report's own
 * shell classes). Matched as a prefix of the problem line followed by a
 * space, a colon, or the end of the string; longest match wins. Anything
 * else is `unclassified`, so a ledger ref after a class cannot become the
 * class label.
 */
const KNOWN_PROBLEM_CLASSES: readonly string[] = [
  "allow-while-halted",
  "anchor entry hash is not the checkpoint's",
  "anchor line",
  "anchor names a checkpoint the ledger does not hold",
  "anchor receipt does not verify",
  "anchor route is not one this verifier reads",
  "anchor row disagrees with its receipt",
  "anchor statement is not this checkpoint's",
  "approval signatures could not be read",
  "approval signatures",
  "approval-signatures-unreadable",
  "approvals-malformed",
  "approvals-unreadable",
  "anchors-not-all-verified",
  "anchors-unreadable",
  "chain breaks at record",
  "checkpoint chain breaks at checkpoint",
  "checkpoint chain could not be checked",
  "checkpoint covers",
  "checkpoint file could not be read",
  "checkpoint has no window",
  "checkpoint line",
  "checkpoint names a head the ledger does not hold",
  "checkpoint signature does not verify",
  "checkpoint totals do not match the records in its window",
  "checkpoint-not-anchored",
  "checkpoint-window-in-future",
  "control signatures could not be read",
  "control signatures",
  "control-signatures-unreadable",
  "decision-without-effect",
  "downstream-manifest-invalid",
  "downstream-manifest-mismatch",
  "downstream-manifest-missing",
  "duplicate-effect hash is not the fixed refusal",
  "duplicate-effect row repeated",
  "duplicate-effect with no decision",
  "effect attestation does not cover the row",
  "effect class is not the signed class",
  "effect hash does not match its decision",
  "effect is not an effect row",
  "effect with no decision",
  "halted effect does not match an allowed decision",
  "index could not be read",
  "index line",
  "index names",
  "index says ref",
  "inputs row does not match",
  "inputs row missing",
  "ledger could not be read",
  "ledger-manifest-corrupt",
  "ledger-manifest-invalid",
  "ledger-manifest-unreadable",
  "ledger-unreadable",
  "manifest piece path leaves the ledger directory",
  "missing piece",
  "newest checkpoint names a record the ledger no longer holds",
  "no decisions found",
  "public key is not ed25519",
  "record is not a decision",
  "record shape is not a decision",
  "ref",
  "require-anchored needs the service key",
  "result-record-mismatch",
  "same-org rows need --witness-key when --effect-key is pinned",
  "self rows need --effect-key when --witness-key is pinned",
  "signature does not verify",
  "signed start row is malformed",
  "signed start row is not written as the body writes it",
  "start chain breaks at starts.jsonl line",
  "start row at starts.jsonl line",
  "start signature does not verify",
  "start signature is not canonical base64",
  "start-row-unreadable",
  "start-row-unsigned",
  "start-rows-missing",
  "start-rows-not-checked",
  "start-summary-unreadable",
  "starts.jsonl could not be read",
  "starts.jsonl line",
  "state-unreadable",
  "symbolic link",
  "third-party key equals",
  "third-party key rejected",
  "third-party row",
  "thrown effect does not match an allowed decision",
  "unreadable file",
  "unreadable row",
  "unsigned start row after a signed one",
].slice().sort((a, b) => b.length - a.length || a.localeCompare(b));

/**
 * Stable class for a verify problem line: the longest known class prefix
 * followed by a space, a colon, or the end. Ledger detail after that prefix
 * is dropped. Anything that is not a known class is `unclassified`.
 */
export function problemClass(problem: string): string {
  for (const known of KNOWN_PROBLEM_CLASSES) {
    if (problem === known) return known;
    if (!problem.startsWith(known)) continue;
    const next = problem[known.length];
    if (next === " " || next === ":") return known;
  }
  return "unclassified";
}

function classOfThrown(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message) {
    const cls = problemClass(err.message);
    if (cls !== "unclassified") return cls;
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

type ApproverInputs = { approver?: { signature?: unknown; resolves?: unknown } };

/** Inputs rows by ref, each with the hash a signed record's `inputsHash` must equal. */
type InputsIndex = Map<string, { hash: string; inputs: ApproverInputs }[]>;

function buildInputsIndex(dir: string): InputsIndex {
  const index: InputsIndex = new Map();
  for (const piece of listPieceFiles(dir)) {
    for (const line of readLines(piece.inputs)) {
      try {
        const doc = JSON.parse(line) as { ref?: unknown; inputs?: unknown };
        if (typeof doc.ref !== "string" || doc.inputs === undefined || doc.inputs === null) continue;
        if (typeof doc.inputs !== "object") continue;
        const hash = createHash("sha256").update(canonical(doc.inputs), "utf8").digest("hex");
        let list = index.get(doc.ref);
        if (!list) {
          list = [];
          index.set(doc.ref, list);
        }
        list.push({ hash, inputs: doc.inputs as ApproverInputs });
      } catch {
        // skip a torn line
      }
    }
  }
  return index;
}

/** The inputs row that hashes to the record's signed `inputsHash`, or null. */
function inputsForRecord(index: InputsIndex, row: SignedDecisionRecord): ApproverInputs | null {
  const ref = row.claims.ref;
  const inputsHash = row.claims.inputsHash;
  if (typeof ref !== "string" || typeof inputsHash !== "string") return null;
  const list = index.get(ref);
  if (!list) return null;
  for (const entry of list) {
    if (entry.hash === inputsHash) return entry.inputs;
  }
  return null;
}

/**
 * Cedulon/verify coverage is half-open `[startMs, endMs)` (see verify-ledger:
 * `r.claims.timestampMs >= startMs && r.claims.timestampMs < endMs`). Overlap
 * with the report window `[fromMs, toExclusive)` is therefore
 * `start < toExclusive && fromMs < end`. A checkpoint with `start >= end`
 * covers nothing and is never counted.
 */
export function checkpointInWindow(row: SignedCheckpoint, fromMs: number, toExclusive: number): boolean {
  const start = row.claims.startMs;
  const end = row.claims.endMs;
  if (typeof start !== "number" || typeof end !== "number") return false;
  if (!(start < end)) return false;
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
    attestedDecisions: [],
    attestedCheckpoints: [],
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
    return failedVerifyShell(dir, classOfThrown(err, "ledger-unreadable"));
  }

  const completed = await completeVerify(dir, result, {
    requireSignedStarts: false,
    catchStartErrors: true,
    problemFromThrown: (err, fallback) => {
      const reportFallback =
        fallback === "approval signatures could not be read"
          ? "approval-signatures-unreadable"
          : fallback === "control signatures could not be read"
            ? "control-signatures-unreadable"
            : fallback;
      return classOfThrown(err, reportFallback);
    },
  });
  return {
    result: completed.result,
    approval: completed.approval,
    control: completed.control,
    verdict: completed.verdict,
  };
}

function refOf(row: SignedDecisionRecord): string | null {
  const ref = row.claims.ref;
  return typeof ref === "string" && ref !== "" ? ref : null;
}

function nonEmptyString(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

/**
 * Held-call counts from attested records only, in chain order.
 *
 * A defer is answered by the first terminal (allow or deny) record that
 * follows it in chain order, whose hash-bound inputs name the defer's ref in
 * `approver.resolves`, and that agrees with the defer on request hash and
 * tool. A record whose decision is defer is never an answer. One answer
 * answers one defer: each answer names at most one resolves ref, and a ref
 * shared by two defers is unmatched, so no shared-consumption set is needed.
 * A defer with no usable ref, a ref shared with another defer, or only
 * disagreeing answers is unmatched.
 *
 * Identity (when counts are available):
 *   approved + closedWithoutAllow + unmatched + heldWithoutBoundAnswer
 *     === windowDeferCount
 * Bound answers and unbound possibility both scan every later terminal in
 * chain order, inside the window or not. stillHeld is heldWithoutBoundAnswer
 * when no held defer could be answered by an unbound record after it
 * (heldPossiblyAnsweredByUnbound === 0); otherwise null. terminalsWithoutBoundInputs
 * still counts only unbound terminals whose time falls in the window.
 * heldPossiblyAnsweredByUnbound never exceeds heldWithoutBoundAnswer.
 */
export function countApprovalsFromSigned(
  dir: string,
  all: readonly SignedDecisionRecord[],
  fromMs: number,
  toExclusive: number,
): ApprovalCounts {
  const index = buildInputsIndex(dir);

  const deferRefCount = new Map<string, number>();
  for (const row of all) {
    if (row.claims.decision !== "defer") continue;
    const ref = refOf(row);
    if (ref !== null) deferRefCount.set(ref, (deferRefCount.get(ref) ?? 0) + 1);
  }

  // resolves ref -> terminal records naming it, in chain order (bound only).
  const answersByRef = new Map<string, { pos: number; row: SignedDecisionRecord; inputs: ApproverInputs }[]>();
  // Unbound terminals: no string inputsHash or no row hashing to it. Every
  // inputs row for the terminal (not only the first with resolves) is
  // consulted for heldPossiblyAnsweredByUnbound.
  const unboundTerminals: { pos: number; row: SignedDecisionRecord; resolves: Set<string> }[] = [];
  let terminalsWithoutBoundInputs = 0;
  for (let pos = 0; pos < all.length; pos += 1) {
    const row = all[pos]!;
    const decision = row.claims.decision;
    if (decision !== "allow" && decision !== "deny") continue;
    const ts = row.claims.timestampMs;
    const inWindow = typeof ts === "number" && ts >= fromMs && ts < toExclusive;
    const inputs = inputsForRecord(index, row);
    if (inputs === null) {
      if (inWindow) terminalsWithoutBoundInputs += 1;
      const ref = typeof row.claims.ref === "string" ? row.claims.ref : null;
      const resolves = new Set<string>();
      if (ref !== null) {
        const rows = index.get(ref);
        if (rows) {
          for (const entry of rows) {
            const r = entry.inputs.approver?.resolves;
            if (typeof r === "string" && r !== "") resolves.add(r);
          }
        }
      }
      unboundTerminals.push({ pos, row, resolves });
      continue;
    }
    const resolves = inputs.approver?.resolves;
    if (typeof resolves !== "string" || resolves === "") continue;
    let list = answersByRef.get(resolves);
    if (!list) {
      list = [];
      answersByRef.set(resolves, list);
    }
    list.push({ pos, row, inputs });
  }

  const counts: ApprovalCounts = {
    approved: 0,
    withOperatorSignatureFieldPresent: 0,
    withoutOperatorSignatureField: 0,
    closedWithoutAllow: 0,
    stillHeld: 0,
    unmatched: 0,
    terminalsWithoutBoundInputs,
    heldWithoutBoundAnswer: 0,
    heldPossiblyAnsweredByUnbound: 0,
  };

  const heldPositions: { pos: number; defer: SignedDecisionRecord; ref: string }[] = [];

  for (let pos = 0; pos < all.length; pos += 1) {
    const defer = all[pos]!;
    if (defer.claims.decision !== "defer") continue;
    const ts = defer.claims.timestampMs;
    const inWindow = typeof ts === "number" && ts >= fromMs && ts < toExclusive;

    const ref = refOf(defer);
    let outcome: "approved" | "closed" | "held" | "unmatched";
    let decided: { row: SignedDecisionRecord; inputs: ApproverInputs } | null = null;

    if (ref === null || (deferRefCount.get(ref) ?? 0) !== 1) {
      outcome = "unmatched";
    } else {
      const candidates = (answersByRef.get(ref) ?? []).filter((c) => c.pos > pos);
      if (candidates.length === 0) {
        outcome = "held";
      } else {
        const reqHash = nonEmptyString(defer.claims.requestHash);
        const subject = nonEmptyString(defer.claims.subject);
        const valid = candidates.find((c) => {
          const aReq = nonEmptyString(c.row.claims.requestHash);
          const aSubject = nonEmptyString(c.row.claims.subject);
          return reqHash !== null && subject !== null && aReq === reqHash && aSubject === subject;
        });
        if (!valid) {
          outcome = "unmatched";
        } else {
          decided = valid;
          outcome = valid.row.claims.decision === "allow" ? "approved" : "closed";
        }
      }
    }

    if (!inWindow) continue;
    if (outcome === "approved") {
      counts.approved += 1;
      if (decided?.inputs.approver?.signature !== undefined) counts.withOperatorSignatureFieldPresent += 1;
      else counts.withoutOperatorSignatureField += 1;
    } else if (outcome === "closed") {
      counts.closedWithoutAllow += 1;
    } else if (outcome === "held") {
      counts.heldWithoutBoundAnswer += 1;
      heldPositions.push({ pos, defer, ref: ref! });
    } else {
      counts.unmatched += 1;
    }
  }

  for (const held of heldPositions) {
    const reqHash = nonEmptyString(held.defer.claims.requestHash);
    const subject = nonEmptyString(held.defer.claims.subject);
    const maybe = unboundTerminals.some((u) => {
      if (u.pos <= held.pos) return false;
      if (!u.resolves.has(held.ref)) return false;
      const aReq = nonEmptyString(u.row.claims.requestHash);
      const aSubject = nonEmptyString(u.row.claims.subject);
      return reqHash !== null && subject !== null && aReq === reqHash && aSubject === subject;
    });
    if (maybe) counts.heldPossiblyAnsweredByUnbound += 1;
  }

  counts.stillHeld =
    counts.heldPossiblyAnsweredByUnbound === 0 ? counts.heldWithoutBoundAnswer : null;

  return counts;
}

/**
 * Temp file with a random name, exclusive create, then a hard link to the
 * final name: the link fails with EEXIST if the target exists, so an existing
 * file is never replaced. The temp name is removed on every path.
 * `tempPath` is for tests that plant a collision at a known name; the CLI
 * never passes it.
 */
export function writeOutExclusive(outPath: string, content: string, tempPath?: string): void {
  const tmp = tempPath ?? join(dirname(outPath), `.verax-report-${randomBytes(12).toString("hex")}.tmp`);
  let created = false;
  try {
    writeFileSync(tmp, content, { encoding: "utf8", flag: "wx" });
    created = true;
    linkSync(tmp, outPath);
  } finally {
    if (created) {
      try {
        unlinkSync(tmp);
      } catch {
        // best-effort cleanup
      }
    }
  }
}

/**
 * Real path when the file exists. When it does not, walk up to the nearest
 * existing ancestor, realpath that, and append the missing segments. One
 * parent is not enough: a state directory reached through a symlink (macOS
 * /var, or a junction) resolves, while `--out dir/sub/nested` may not, and
 * comparing the unresolved path then misses "inside the state directory".
 */
function realOrResolved(path: string): string {
  const abs = resolve(path);
  const missing: string[] = [];
  let cur = abs;
  for (;;) {
    try {
      const real = realpathSync(cur);
      return missing.length === 0 ? real : join(real, ...missing);
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return abs;
      missing.unshift(basename(cur));
      cur = parent;
    }
  }
}

function pathInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  if (rel === "") return true;
  if (isAbsolute(rel)) return false;
  return rel !== ".." && !rel.startsWith(`..${sep}`);
}

function outInsideStateDir(dir: string, outPath: string): boolean {
  return pathInside(realOrResolved(outPath), realOrResolved(dir));
}

function unverifiedReport(from: string, to: string, problem: string): PeriodReport {
  const shell = failedVerifyShell("", problem);
  return {
    from,
    to,
    headHash: null,
    recordCount: null,
    firstRecordMs: null,
    lastRecordMs: null,
    verification: {
      ok: false,
      verdict: shell.verdict,
      problems: [problem],
    },
    countsUnavailableReason: COUNTS_UNAVAILABLE_REASON,
    unsignedApprovalsNote: null,
    decisions: { total: null, byTool: null, withoutSubject: null },
    approvals: {
      approved: null,
      withOperatorSignatureFieldPresent: null,
      withoutOperatorSignatureField: null,
      closedWithoutAllow: null,
      stillHeld: null,
      unmatched: null,
      terminalsWithoutBoundInputs: null,
      heldWithoutBoundAnswer: null,
      heldPossiblyAnsweredByUnbound: null,
      unavailableReason: null,
    },
    checkpoints: {
      count: null,
      withAnchorVerified: null,
      anchorRowsPresentNotChecked: null,
      anchorUnavailableReason: null,
    },
    whatThisReportDoesNotShow: WHAT_NOT_SHOWN,
  };
}

export async function buildPeriodReport(
  dir: string,
  from: string,
  to: string,
  fromMs: number,
  toExclusive: number,
): Promise<PeriodReport> {
  if (directoryAccess(dir) === "unreadable") {
    return unverifiedReport(from, to, "state-unreadable");
  }

  let verified: Awaited<ReturnType<typeof verifyLikeVerifyCli>>;
  try {
    verified = await verifyLikeVerifyCli(dir);
  } catch (err) {
    return unverifiedReport(from, to, classOfThrown(err, "ledger-unreadable"));
  }
  const result = verified.result;
  const problemClasses = [...new Set(result.problems.map(problemClass))];

  // Candidate file only: a malformed line is noted, never counted, and never
  // changes the verdict.
  let unsignedApprovalsNote: string | null = null;
  try {
    loadApprovalsFromDir(dir);
  } catch {
    unsignedApprovalsNote = UNSIGNED_APPROVALS_NOTE;
  }

  const verification = {
    ok: result.ok,
    verdict: verified.verdict,
    problems: problemClasses,
  };

  if (!result.ok) {
    const report = unverifiedReport(from, to, "unused");
    return {
      ...report,
      verification,
      unsignedApprovalsNote,
    };
  }

  const attested = result.attestedDecisions;

  let headHash: string | null = null;
  if (attested.length > 0) {
    try {
      headHash = decisionRecordHash(attested[attested.length - 1]!);
    } catch {
      headHash = null;
    }
  }

  const inWindow = attested.filter((r) => {
    const ts = r.claims.timestampMs;
    return typeof ts === "number" && ts >= fromMs && ts < toExclusive;
  });

  const total = emptyCounts();
  const withoutSubject = emptyCounts();
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
    const tool = subjectToolKey(row.claims.subject);
    if (tool === null) {
      bump(withoutSubject, decision);
      continue;
    }
    let counts = byToolMap.get(tool);
    if (!counts) {
      counts = emptyCounts();
      byToolMap.set(tool, counts);
    }
    bump(counts, decision);
  }

  // Own keys only: tool names such as __proto__ must not hit Object.prototype.
  // byTool holds only real subjects; empty/missing are in withoutSubject.
  // Identity: per-tool numbers plus withoutSubject equal the totals.
  const byTool: { [tool: string]: DecisionCounts } = Object.create(null);
  for (const tool of [...byToolMap.keys()].sort()) {
    byTool[tool] = byToolMap.get(tool)!;
  }

  let approvals: PeriodReport["approvals"] = {
    approved: null,
    withOperatorSignatureFieldPresent: null,
    withoutOperatorSignatureField: null,
    closedWithoutAllow: null,
    stillHeld: null,
    unmatched: null,
    terminalsWithoutBoundInputs: null,
    heldWithoutBoundAnswer: null,
    heldPossiblyAnsweredByUnbound: null,
    unavailableReason: null,
  };
  try {
    approvals = { ...countApprovalsFromSigned(dir, attested, fromMs, toExclusive), unavailableReason: null };
  } catch (err) {
    approvals.unavailableReason = classOfThrown(err, "approvals-unreadable");
  }

  // Checkpoints come from verify's attested set; anchors are read on their own
  // so that an unreadable anchor file cannot hide the checkpoint count.
  const windowCheckpoints = result.attestedCheckpoints.filter((row) =>
    checkpointInWindow(row, fromMs, toExclusive),
  );
  const windowHashes = new Set<string>();
  for (const row of windowCheckpoints) {
    try {
      windowHashes.add(checkpointHash(row));
    } catch {
      // A row that cannot be hashed cannot be matched to an anchor row.
    }
  }

  const checkpoints: PeriodReport["checkpoints"] = {
    count: windowCheckpoints.length,
    withAnchorVerified: null,
    anchorRowsPresentNotChecked: null,
    anchorUnavailableReason: null,
  };
  try {
    const anchorRows = readAnchors(dir).rows;
    const inWindowRows = anchorRows.filter((r) => windowHashes.has(r.checkpointHash)).length;
    if (result.anchors.checked) {
      // An ok ledger has no failed receipt: every row verified.
      if (result.anchors.verified === result.anchors.receipts) {
        checkpoints.withAnchorVerified = inWindowRows;
        checkpoints.anchorRowsPresentNotChecked = 0;
      } else {
        checkpoints.anchorUnavailableReason = "anchors-not-all-verified";
      }
    } else {
      checkpoints.withAnchorVerified = 0;
      checkpoints.anchorRowsPresentNotChecked = inWindowRows;
    }
  } catch (err) {
    checkpoints.anchorUnavailableReason = classOfThrown(err, "anchors-unreadable");
  }

  return {
    from,
    to,
    headHash,
    recordCount: inWindow.length,
    firstRecordMs,
    lastRecordMs,
    verification,
    countsUnavailableReason: null,
    unsignedApprovalsNote,
    decisions: { total, byTool, withoutSubject },
    approvals,
    checkpoints,
    whatThisReportDoesNotShow: WHAT_NOT_SHOWN,
  };
}

function jsonNum(n: number | null): string {
  return n === null ? "null" : String(n);
}

function jsonCounts(c: DecisionCounts | null): string {
  return c === null ? "null" : `{"allow":${c.allow},"deny":${c.deny},"defer":${c.defer}}`;
}

/**
 * Fixed key order. The same ledger and window give the same bytes. These are
 * the one canonical display-safe bytes: terminal-control and bidi characters
 * are escaped here, before any digest, so stdout, the digest and the digest
 * shown in HTML are all of this exact sequence.
 */
export function serializePeriodReport(report: PeriodReport): string {
  const byToolJson =
    report.decisions.byTool === null
      ? "null"
      : `{${Object.keys(report.decisions.byTool)
          .sort()
          .map((tool) => `${JSON.stringify(tool)}:${jsonCounts(report.decisions.byTool![tool]!)}`)
          .join(",")}}`;
  const withoutSubjectJson = jsonCounts(report.decisions.withoutSubject);
  const problemsJson = `[${report.verification.problems.map((p) => JSON.stringify(p)).join(",")}]`;
  const a = report.approvals;
  const c = report.checkpoints;
  const json =
    "{" +
    [
      `"from":${JSON.stringify(report.from)}`,
      `"to":${JSON.stringify(report.to)}`,
      `"headHash":${JSON.stringify(report.headHash)}`,
      `"recordCount":${jsonNum(report.recordCount)}`,
      `"firstRecordMs":${jsonNum(report.firstRecordMs)}`,
      `"lastRecordMs":${jsonNum(report.lastRecordMs)}`,
      `"verification":{"ok":${report.verification.ok},"verdict":${JSON.stringify(report.verification.verdict)},"problems":${problemsJson}}`,
      `"countsUnavailableReason":${JSON.stringify(report.countsUnavailableReason)}`,
      `"unsignedApprovalsNote":${JSON.stringify(report.unsignedApprovalsNote)}`,
      `"decisions":{"total":${jsonCounts(report.decisions.total)},"byTool":${byToolJson},"withoutSubject":${withoutSubjectJson}}`,
      `"approvals":{"approved":${jsonNum(a.approved)},"withOperatorSignatureFieldPresent":${jsonNum(a.withOperatorSignatureFieldPresent)},"withoutOperatorSignatureField":${jsonNum(a.withoutOperatorSignatureField)},"closedWithoutAllow":${jsonNum(a.closedWithoutAllow)},"stillHeld":${jsonNum(a.stillHeld)},"unmatched":${jsonNum(a.unmatched)},"terminalsWithoutBoundInputs":${jsonNum(a.terminalsWithoutBoundInputs)},"heldWithoutBoundAnswer":${jsonNum(a.heldWithoutBoundAnswer)},"heldPossiblyAnsweredByUnbound":${jsonNum(a.heldPossiblyAnsweredByUnbound)},"unavailableReason":${JSON.stringify(a.unavailableReason)}}`,
      `"checkpoints":{"count":${jsonNum(c.count)},"withAnchorVerified":${jsonNum(c.withAnchorVerified)},"anchorRowsPresentNotChecked":${jsonNum(c.anchorRowsPresentNotChecked)},"anchorUnavailableReason":${JSON.stringify(c.anchorUnavailableReason)}}`,
      `"whatThisReportDoesNotShow":${JSON.stringify(report.whatThisReportDoesNotShow)}`,
    ].join(",") +
    "}";
  return terminalLines(json);
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

function shown(n: number | null): string {
  return n === null ? "not available" : String(n);
}

function shownCounts(c: DecisionCounts | null): string {
  return c === null ? "not available" : `allow ${c.allow}, deny ${c.deny}, defer ${c.defer}`;
}

function unavailableSentence(report: PeriodReport): string {
  const classes = report.verification.problems.join(", ");
  return `Counts not available (null): ${report.countsUnavailableReason ?? ""}${classes === "" ? "" : ` Problem classes: ${classes}.`}`;
}

const WINDOW_SENTENCE =
  "The to day is included in full: the window is half-open, from 00:00:00 UTC on the from day up to, not including, 00:00:00 UTC on the day after the to day.";

export function renderReportHtml(report: PeriodReport, digest: string): string {
  const esc = (s: string): string => htmlEscape(terminalText(s));
  const toolRows =
    report.decisions.byTool === null
      ? ""
      : Object.keys(report.decisions.byTool)
          .sort()
          .map((tool) => {
            const c = report.decisions.byTool![tool]!;
            return `<tr><td>${esc(tool)}</td><td>${c.allow}</td><td>${c.deny}</td><td>${c.defer}</td></tr>`;
          })
          .join("");
  const problemItems = report.verification.problems.map((p) => `<li>${esc(p)}</li>`).join("");
  const problemsBlock =
    report.verification.problems.length === 0
      ? "<p>No verification problems named.</p>"
      : `<p>${report.verification.problems.length} problem class(es). Run <code>verax verify</code> on the machine for the detail.</p><ul>${problemItems}</ul>`;
  const countsNotice =
    report.countsUnavailableReason === null ? [] : [`<p class="verdict">${esc(unavailableSentence(report))}</p>`];
  const approvalsNote =
    report.unsignedApprovalsNote === null ? [] : [`<p>Note: ${esc(report.unsignedApprovalsNote)}</p>`];
  const a = report.approvals;
  const c = report.checkpoints;
  const approvalsReason =
    a.unavailableReason === null ? "" : ` Approvals not available: ${esc(a.unavailableReason)}.`;
  const anchorReason =
    c.anchorUnavailableReason === null ? "" : ` Anchor counts not available: ${esc(c.anchorUnavailableReason)}.`;

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
    `<p class="verdict">${esc(report.verification.verdict)}</p>`,
    ...countsNotice,
    `<p>Window ${esc(report.from)} to ${esc(report.to)} (UTC). ${esc(WINDOW_SENTENCE)}</p>`,
    `<p>Records in window: ${shown(report.recordCount)}. First record time: ${report.firstRecordMs === null ? "none" : String(report.firstRecordMs)}. Last record time: ${report.lastRecordMs === null ? "none" : String(report.lastRecordMs)}. Ledger head hash: ${esc(report.headHash ?? "none")}.</p>`,
    "<h2>Decisions</h2>",
    `<p>Total: ${shownCounts(report.decisions.total)}.</p>`,
    "<table><thead><tr><th>Tool</th><th>Allow</th><th>Deny</th><th>Defer</th></tr></thead>",
    `<tbody>${toolRows}</tbody></table>`,
    `<p>No usable subject: ${shownCounts(report.decisions.withoutSubject)}.</p>`,
    "<h2>Approvals</h2>",
    `<p>Approved held calls: ${shown(a.approved)} (${shown(a.withOperatorSignatureFieldPresent)} with an operator signature field present, ${shown(a.withoutOperatorSignatureField)} without; signature field present is not a verified signature here). Closed without an allow: ${shown(a.closedWithoutAllow)}. Still held: ${shown(a.stillHeld)}. Unmatched: ${shown(a.unmatched)}. Held, and no bound answer found: ${shown(a.heldWithoutBoundAnswer)}. Terminals without bound inputs: ${shown(a.terminalsWithoutBoundInputs)}. Held record(s) that could have been answered by an unbound record: ${shown(a.heldPossiblyAnsweredByUnbound)}.${approvalsReason}</p>`,
    "<p>Approved means the first signed bound answer after the defer, naming it and agreeing on request hash and tool, is an allow. Closed without an allow means that first answer is a deny (expired or otherwise). Still held means no signed bound answer exists and no later unbound record could have answered the defer; when a held defer could have been answered by an unbound record anywhere after it, still held is not established. Unmatched means the defer has no usable reference, shares it with another defer, or its bound answers disagree on request hash or tool.</p>",
    ...approvalsNote,
    "<h2>Checkpoints</h2>",
    `<p>Checkpoints in the window: ${shown(c.count)}. Anchor receipts verified: ${shown(c.withAnchorVerified)}. Anchor rows present, not checked (no anchor key): ${shown(c.anchorRowsPresentNotChecked)}.${anchorReason}</p>`,
    "<h2>Verification</h2>",
    problemsBlock,
    "<h2>What this report does not show</h2>",
    `<p>${esc(report.whatThisReportDoesNotShow)}</p>`,
    `<p class="digest">Report digest (SHA-256 of the JSON form, the same bytes as --json): <code>${htmlEscape(digest)}</code></p>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

export function renderReportText(report: PeriodReport, digest: string): string {
  const lines: string[] = [];
  const a = report.approvals;
  const c = report.checkpoints;
  lines.push(report.verification.verdict);
  if (report.countsUnavailableReason !== null) lines.push(unavailableSentence(report));
  lines.push(`window        ${report.from} .. ${report.to} (UTC)`);
  lines.push(`window note   ${WINDOW_SENTENCE}`);
  lines.push(`records       ${shown(report.recordCount)}`);
  lines.push(`first         ${report.firstRecordMs === null ? "none" : String(report.firstRecordMs)}`);
  lines.push(`last          ${report.lastRecordMs === null ? "none" : String(report.lastRecordMs)}`);
  lines.push(`head          ${report.headHash ?? "none"}`);
  lines.push(`decisions     ${shownCounts(report.decisions.total)}`);
  if (report.decisions.byTool !== null) {
    for (const tool of Object.keys(report.decisions.byTool).sort()) {
      const t = report.decisions.byTool[tool]!;
      lines.push(`  ${tool}  allow ${t.allow}, deny ${t.deny}, defer ${t.defer}`);
    }
  }
  lines.push(`no usable subject  ${shownCounts(report.decisions.withoutSubject)}`);
  lines.push(
    `approvals     approved ${shown(a.approved)} (signature field present ${shown(a.withOperatorSignatureFieldPresent)}, absent ${shown(a.withoutOperatorSignatureField)}), closed without an allow ${shown(a.closedWithoutAllow)}, still held ${shown(a.stillHeld)}, unmatched ${shown(a.unmatched)}`,
  );
  lines.push(
    `approvals     held, and no bound answer found ${shown(a.heldWithoutBoundAnswer)}, terminals without bound inputs ${shown(a.terminalsWithoutBoundInputs)}, held record(s) that could have been answered by an unbound record ${shown(a.heldPossiblyAnsweredByUnbound)}`,
  );
  if (a.unavailableReason !== null) lines.push(`approvals     not available: ${a.unavailableReason}`);
  lines.push(
    "approvals mean: approved = first signed bound answer after the defer (naming it, same request hash and tool) is an allow; closed without an allow = that answer is a deny; still held = no signed bound answer and no later unbound record could have answered it (otherwise not available); unmatched = no usable ref, shared ref, or disagreeing bound answers; signature field present is not a verified signature",
  );
  if (report.unsignedApprovalsNote !== null) lines.push(`note          ${report.unsignedApprovalsNote}`);
  lines.push(
    `checkpoints   ${shown(c.count)} in window, anchor receipts verified ${shown(c.withAnchorVerified)}, anchor rows present not checked ${shown(c.anchorRowsPresentNotChecked)}`,
  );
  if (c.anchorUnavailableReason !== null) lines.push(`anchors       not available: ${c.anchorUnavailableReason}`);
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
  /** Test-only: force the exclusive-create temp path. Not a CLI flag. */
  opts?: { writeTempPath?: string },
): Promise<number> {
  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    out(parsed.message.startsWith("usage:") ? parsed.message : terminalText(parsed.message));
    return argv.length === 0 || argv[0] === "--help" || argv[0] === "-h" ? (argv.length === 0 ? EX_USAGE : 0) : EX_USAGE;
  }

  // Before any compute or write: the report must not land inside the ledger.
  if (parsed.outPath !== null && outInsideStateDir(parsed.dir, parsed.outPath)) {
    out("report: --out must not be inside the state directory");
    return EX_USAGE;
  }

  let report: PeriodReport;
  try {
    report = await buildPeriodReport(parsed.dir, parsed.from, parsed.to, parsed.fromMs, parsed.toExclusive);
  } catch (err) {
    report = unverifiedReport(parsed.from, parsed.to, classOfThrown(err, "ledger-unreadable"));
  }

  const json = serializePeriodReport(report);
  const digest = reportDigest(json);

  if (parsed.outPath !== null) {
    try {
      writeOutExclusive(parsed.outPath, renderReportHtml(report, digest), opts?.writeTempPath);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EEXIST") {
        out(terminalText(`report: refusing to overwrite ${basename(parsed.outPath)}`));
        return EX_USAGE;
      }
      out(terminalText(`report: could not write ${basename(parsed.outPath)}`));
      return EX_USAGE;
    }
  }

  if (parsed.json) {
    out(json);
  } else if (parsed.outPath === null) {
    out(renderReportText(report, digest));
  } else {
    out(terminalText(`wrote ${basename(parsed.outPath)}`));
    out(terminalText(`digest ${digest}`));
  }

  if (report.verification.ok) return 0;
  // Match verax verify: an unreadable directory is 77, not the generic verify-failed 1.
  if (report.verification.problems.includes("state-unreadable")) return EX_STATE_UNREADABLE;
  return EX_VERIFY_FAILED;
}
