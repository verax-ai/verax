/**
 * Reads a ledger directory and says whether it still holds together, with no
 * body running and nothing on the network.
 *
 * This is the answer to a question a customer is right to ask: if we stopped
 * using Verax tomorrow, would these files still mean anything? Evidence that
 * can only be read by the vendor who sold it is a weak kind of evidence.
 *
 * Three things fail separately, so three things are stated separately:
 *
 *   signatures  each record verifies against a public key
 *   chain       each record names the hash of the one before it
 *   effects     an effect is bound only when a decision with that ref exists and
 *               its recorded `effectHash` equals the row's `effectHash`, and
 *               the row carries an attestation and a witness receipt that both
 *               verify under one effect key. The signed COSE payload is
 *               `{ ref, effectHash, witnessClass, resultHash }`, compared after
 *               decode, and the receipt's effect (`body.effects[0]`, every
 *               field the writer put there) must be that same row. A
 *               `third-party` row instead needs a one-row receipt verified
 *               under `thirdPartyPublicKeyPems` supplied by the reader, equal
 *               to the stored row and bound by ref and effectHash. No body
 *               attestation is required; its resultHash is unattested. Keys
 *               shared with record/effect/witness signers are refused. Without
 *               a third-party pin the row is named unchecked and is not bound.
 *               For self/same-org rows, a
 *               thrown call relaxes only the hash, and only for the tool that
 *               was allowed: some decision on that ref has `decision: "allow"`
 *               and this row's class is exactly that decision's `effectClass`
 *               plus `:threw`. A deny, or an allow of a different tool, does
 *               not bind. The signature is still required. A
 *               `duplicate-effect` row is bound to the decision by ref and to
 *               the fixed refusal hash the writer stores, not to the
 *               decision's effectHash; the signature is still required.
 *               Anything else that claims that class is named. A ref has at
 *               most one primary effect row (a row that is not
 *               `duplicate-effect`). A further primary row for that ref is
 *               named `ref X has more than one effect row` and is not bound.
 *               A `self` row is checked under the effect key:
 *               `effectPublicKeyPem` when the reader pins one, otherwise the
 *               first receipt key on a `self` row. A `same-org` row is checked
 *               under the witness key: `witnessPublicKeyPem` when the reader
 *               pins one, otherwise the first receipt key on a `same-org` row.
 *               Pinning one of those keys and leaving the other to the file
 *               does not verify: a pinned effect key with any `same-org` row
 *               requires a pinned witness key, and a pinned witness key with
 *               any `self` row requires a pinned effect key. Agreement of a
 *               key with the files is not trust.
 *
 * Checkpoints are a fifth statement. Each row in `checkpoints.jsonl` must
 * verify under one witness key: `checkpointPublicKeyPem` when the reader
 * pins one, otherwise the first key the file carries. A line that does not
 * parse, or that parses but is not a checkpoint, is named and `ok` is false.
 * A missing file is not that: the tail line says there is no checkpoint.
 * A row that does not
 * verify is named and `ok` is false. The `prevCheckpointHash` chain is
 * checked with `findCheckpointChainBreak`. The tail uses only the prefix
 * that verified. A key taken from the file shows the checkpoints agree
 * with each other, not that the key was ever trusted.
 *
 * Inputs are a further statement. The writer appends a call's inputs row
 * before the record whose `inputsHash` commits to it, so a crash leaves at
 * most an inputs row with no record, never the reverse. Each record that
 * carries an `inputsHash` must find an inputs row under its ref whose
 * canonical SHA-256 is that hash. A missing row is `inputs row missing`, a
 * row under that ref with another hash is `inputs row does not match`, and
 * either makes `ok` false: the approver block of an approval lives in that
 * row, and an unbound row could be rewritten from a signed approval into an
 * unsigned one. A row with no record is the crash case and is not named.
 *
 * Checkpoint counts are checked too. For every checkpoint that verified, its
 * head must be a record the ledger holds, the verified records in its window
 * up to that head must be its `receiptCount` ending at the head, and their
 * allow, deny and defer counts must be its totals; a record appended later
 * with a time in the window is not counted. Null totals (redacted) are not
 * compared; the count still is.
 *
 * Anchors are the last statement. `checkpoint-anchors.jsonl` holds COSE
 * Receipts from a Transparency Service for checkpoints `verax anchor`
 * registered. A receipt names no key, so it is checked only under a key the
 * reader supplies (`anchorPublicKeyPem`): each row must name a checkpoint that
 * verified, its leaf entry must be the one the route defines, and the receipt
 * must verify over the root its inclusion proof rebuilds. Without that key the
 * receipts are counted and said to be unchecked; that is not a failure.
 *
 * Control records are a further statement. An allow whose subject is
 * `verax.halt` opens a halt window; an allow whose subject is `verax.resume`
 * closes it. An allow whose subject does not start with `verax.` while a
 * window is open is `allow-while-halted <ref>` and `ok` is false. A deny
 * whose reason is `halted` and which sits outside every window is the
 * warning `halted-deny-without-halt-record <ref>` and does not change `ok`.
 * A ledger with no control record says so, and that sentence is not a violation.
 *
 * And a fourth, which matters most and is the easiest to fudge: **which key**.
 * A ledger checked against the key sitting next to it is internally
 * consistent and nothing more — whatever could write the file could write
 * that key too (the downstream audit showed exactly this: a stdio child runs
 * as the same user and can read `keys/*.pem`). So the trust source is part of
 * the answer rather than a footnote, and `publicKeyPem` lets a reader pin a
 * copy they hold themselves.
 */
import { createPublicKey } from "node:crypto";
import { samePublicKey, thirdPartyReceiptCoversRow } from "./third-party.ts";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  checkpointHash,
  findCheckpointChainBreak,
  totalsFromDecisionRecords,
  verifyCheckpoint,
  verifyCheckpointUnderPin,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { canonical, decisionRecordHash, findDecisionRecordChainBreak, verifyDecisionRecord } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";
import { coseFromHex, decodeCoseSign1, verifyCoseSign1 } from "@cedulon/cose";
import { verifyEffectExtract, type SignedEffectExtract } from "@cedulon/effect-extract";

import { anchorEntryHash, readAnchors } from "./anchors.ts";
import { checkpointsPath, readCheckpointFile } from "./checkpoints.ts";
import { sha256Canonical } from "./hash.ts";
import { verifyReceipt } from "./transparency-receipt.ts";
import {
  ledgerPiecePathProblem,
  readLedgerManifest,
  requireLedgerPiecePath,
  indexPath,
  manifestPath,
  parseIndexText,
} from "./ledger-manifest.ts";

export type VerifyTrust = {
  /** `pinned`: the caller supplied the key. `in-ledger`: read from the records. */
  source: "pinned" | "in-ledger" | "none";
  publicKeyPem: string | null;
  note: string;
};

export type VerifyResult = {
  ok: boolean;
  directory: string;
  decisions: number;
  effects: number;
  signaturesValid: number;
  signaturesInvalid: number;
  /** Index of the first record whose `prevRecordHash` does not match, else null. */
  chainBreakAt: number | null;
  effectsBound: number;
  effectsOrphaned: number;
  /**
   * Refs of attested allows with no effect row that sit within the boundary
   * allowance of the newest record: `boundary-deferred`, a warning. An older
   * allow with no row is the problem `decision-without-effect <ref>`.
   */
  effectsDeferred: string[];
  trust: VerifyTrust;
  /** Which key answered for `self` effect rows. Same honesty rules as `trust`. */
  effectTrust: VerifyTrust;
  /** Which key answered for `same-org` effect rows. Agreement is not trust. */
  witnessTrust: VerifyTrust;
  /** Which key answered for checkpoint rows. Same honesty rules as `trust`. */
  checkpointTrust: VerifyTrust;
  /** What `index.jsonl` still names. Missing file is not a failure. */
  index: VerifyIndex;
  /**
   * Absent index: effect completeness was not checked, and that absence is
   * not itself a failure. Present index: every ref it marks was compared to
   * a bound effect row.
   */
  effectCompleteness: string;
  /** What the newest checkpoint covers, and the records after it. */
  tail: VerifyTail;
  /** Halt windows. A ledger with none says so; that sentence is not a violation. */
  control: VerifyControl;
  /** Inputs rows checked against each record's signed `inputsHash`. */
  inputs: VerifyInputs;
  /** Transparency Service receipts for checkpoints, when the ledger holds any. */
  anchors: VerifyAnchors;
  problems: string[];
};

export type VerifyAnchors = {
  line: string;
  /** Receipts in `checkpoint-anchors.jsonl`. */
  receipts: number;
  /** Receipts that verified under the reader's key. Zero when no key was given. */
  verified: number;
  checked: boolean;
};

export type VerifyInputs = {
  line: string;
  /** Records whose inputs row was found and hashes to their `inputsHash`. */
  matched: number;
  missing: number;
  mismatched: number;
};

export type VerifyIndex = {
  present: boolean;
  /** Index refs that are not decisions in the ledger. */
  missing: number;
  line: string;
};

export type VerifyTail = {
  line: string;
  /** Newest signed checkpoint, or null when the file has none. */
  checkpoint: {
    receiptCount: number | null;
    chainHeadHash: string | null;
    /** True when some decision's hash is the checkpoint head. Null when the checkpoint carries no head. */
    ledgerHoldsRecord: boolean | null;
  } | null;
};

/** Halt windows taken from control records. Warnings do not change `ok`. */
export type VerifyControl = {
  line: string;
  windows: number;
  warnings: string[];
};

export type VerifyOptions = {
  /** Verify decision records against this key instead of the one they carry. */
  publicKeyPem?: string;
  /** Verify `self` effect rows against this key instead of the one those rows carry. */
  effectPublicKeyPem?: string;
  /** Out-of-band pins only. Third-party resultHash is never attested by the extract. */
  thirdPartyPublicKeyPems?: string[];
  /** Verify `same-org` effect rows against this key instead of the one those rows carry. */
  witnessPublicKeyPem?: string;
  /** Verify every checkpoint row against this key instead of one key taken from the file. */
  checkpointPublicKeyPem?: string;
  /** The Transparency Service key that receipts in `checkpoint-anchors.jsonl` are checked under. */
  anchorPublicKeyPem?: string;
  /** How close to the newest record an allow with no effect row is deferred rather than named. */
  boundaryAllowanceMs?: number;
};

/**
 * A symbolic link is a named problem and is not read. Missing files are not
 * this case. `lstatSync` does not follow the link.
 */
function symbolicLinkProblem(path: string): string | null {
  try {
    if (lstatSync(path).isSymbolicLink()) return `symbolic link: ${path}`;
  } catch {
    return null;
  }
  return null;
}

/**
 * A piece path that leaves the directory is a problem and is not opened.
 * A piece that is a symbolic link is named and is not opened. A decisions or
 * effects file the manifest names and the disk lacks is `missing piece`.
 * `existsSync` runs only after the path and link checks.
 */
function takePieceFile(dir: string, rel: string, problems: string[], read: boolean): string | null {
  const problem = ledgerPiecePathProblem(dir, rel);
  if (problem !== null) {
    problems.push(problem);
    return null;
  }
  const path = requireLedgerPiecePath(dir, rel);
  const link = symbolicLinkProblem(path);
  if (link !== null) {
    problems.push(link);
    return null;
  }
  if (!read) return null;
  // The writer creates the effects file for every piece, including a piece
  // that has no effects yet (an empty file). A name in the manifest with no
  // file on disk is not that empty piece.
  if (!existsSync(path)) {
    problems.push(`missing piece: ${rel}`);
    return null;
  }
  return path;
}

type LedgerFiles = { decisions: string[]; effects: string[]; inputs: string[] };

/**
 * Decision, effect and inputs files this directory holds, oldest piece first.
 * An inputs file the disk lacks is not named here: a record that needed a row
 * from it is named when inputs are checked.
 */
function ledgerFiles(dir: string, problems: string[]): LedgerFiles {
  const manifestFile = manifestPath(dir);
  const manifestLink = symbolicLinkProblem(manifestFile);
  if (manifestLink !== null) {
    problems.push(manifestLink);
    return { decisions: [], effects: [], inputs: [] };
  }
  if (existsSync(manifestFile)) {
    try {
      const manifest = readLedgerManifest(dir);
      if (manifest && Array.isArray(manifest.pieces) && manifest.pieces.length > 0) {
        return pieceFiles(dir, manifest.pieces, problems);
      }
    } catch (err) {
      problems.push(err instanceof Error ? err.message : "ledger-manifest-unreadable");
      return { decisions: [], effects: [], inputs: [] };
    }
  }
  return legacyFiles(dir);
}

function legacyFiles(dir: string): LedgerFiles {
  const decisionsPath = join(dir, "decisions.jsonl");
  const effectsPath = join(dir, "effects.jsonl");
  const inputsPath = join(dir, "inputs.jsonl");
  return {
    decisions: existsSync(decisionsPath) ? [decisionsPath] : [],
    effects: existsSync(effectsPath) ? [effectsPath] : [],
    inputs: existsSync(inputsPath) ? [inputsPath] : [],
  };
}

function pieceFiles(
  dir: string,
  pieces: { decisions: string; effects: string; inputs: string }[],
  problems: string[],
): LedgerFiles {
  const decisions: string[] = [];
  const effects: string[] = [];
  const inputs: string[] = [];
  for (const p of pieces) {
    const decision = takePieceFile(dir, p.decisions, problems, true);
    if (decision) decisions.push(decision);
    const effect = takePieceFile(dir, p.effects, problems, true);
    if (effect) effects.push(effect);
    const before = problems.length;
    takePieceFile(dir, p.inputs, problems, false);
    if (problems.length === before) {
      const path = requireLedgerPiecePath(dir, p.inputs);
      if (existsSync(path)) inputs.push(path);
    }
  }
  return { decisions, effects, inputs };
}

/** Parses JSONL, reporting the line a bad row sits on rather than throwing. */
function readJsonl(path: string, problems: string[]): unknown[] {
  const out: unknown[] = [];
  const link = symbolicLinkProblem(path);
  if (link !== null) {
    problems.push(link);
    return out;
  }
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    problems.push(`unreadable file: ${path}`);
    return out;
  }
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!.trim();
    if (line === "") continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      problems.push(`unreadable row: ${path}:${i + 1} is not JSON`);
    }
  }
  return out;
}

type EffectOnDisk = {
  row?: { ref?: unknown; effectHash?: unknown; effectClass?: unknown };
  witnessClass?: unknown;
  resultHash?: unknown;
  attestation?: { coseHex?: unknown };
  receipt?: SignedEffectExtract;
};

function isPublicKeyPem(pem: unknown): pem is string {
  return typeof pem === "string" && pem.includes("BEGIN PUBLIC KEY");
}

/**
 * RFC 9864 assigns alg -19 to Ed25519 only. A key that parses as something
 * else is refused here. The same check belongs in `verifyCoseSign1`; this
 * package does not patch that dependency.
 * A PEM that does not parse is left to the verifier, which already fails it.
 */
function ed25519Refusal(pem: string | null | undefined): string | null {
  if (typeof pem !== "string" || pem.trim() === "") return null;
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType === "ed25519") return null;
    return "public key is not ed25519";
  } catch {
    return null;
  }
}

function noteEd25519(pem: string | null | undefined, problems: string[]): void {
  const refusal = ed25519Refusal(pem);
  if (refusal) problems.push(refusal);
}

/**
 * The writer signs `{ ref, effectHash, witnessClass, resultHash }` as COSE
 * Sign1 and a one-row extract. A row with either missing is not bound. Both
 * must verify under the key the caller settled on for this row's witness
 * class — never a key this row brought by itself.
 */
function effectSignatureCoversRow(effect: EffectOnDisk, effectKey: string | null): boolean {
  const coseHex = effect.attestation?.coseHex;
  const hasAtt = typeof coseHex === "string" && coseHex !== "";
  const hasReceipt = effect.receipt !== undefined;
  if (!hasAtt || !hasReceipt || !effect.receipt || !isPublicKeyPem(effectKey)) return false;
  if (ed25519Refusal(effectKey)) return false;
  const ref = effect.row?.ref;
  const effectHash = effect.row?.effectHash;
  const witnessClass = effect.witnessClass;
  if (typeof ref !== "string" || typeof effectHash !== "string" || typeof witnessClass !== "string") {
    return false;
  }
  const expected = canonical({
    ref,
    effectHash,
    witnessClass,
    resultHash: typeof effect.resultHash === "string" ? effect.resultHash : null,
  });
  let decodedPayload: unknown;
  try {
    const decoded = decodeCoseSign1(coseFromHex(coseHex));
    decodedPayload = JSON.parse(Buffer.from(decoded.payload).toString("utf8"));
  } catch {
    return false;
  }
  try {
    if (canonical(decodedPayload) !== expected) return false;
  } catch {
    return false;
  }
  try {
    if (!verifyCoseSign1(coseFromHex(coseHex), effectKey, "application/json")) return false;
  } catch {
    return false;
  }
  try {
    if (!verifyEffectExtract(effect.receipt, effectKey)) return false;
  } catch {
    return false;
  }
  let signedRow: unknown;
  try {
    signedRow = effect.receipt.body.effects[0];
  } catch {
    return false;
  }
  if (signedRow == null || !effect.row) return false;
  try {
    if (canonical(signedRow) !== canonical(effect.row)) return false;
  } catch {
    return false;
  }
  return true;
}

function effectProblem(effect: EffectOnDisk, ref: string | null): string {
  const signedClass = effect.receipt?.body?.effects?.[0]?.effectClass;
  const diskClass = effect.row?.effectClass;
  if (typeof signedClass === "string" && signedClass !== diskClass) {
    return `effect class is not the signed class: ref ${ref ?? "(missing)"}`;
  }
  return `effect attestation does not cover the row: ref ${ref ?? "(missing)"}`;
}

function firstReceiptKey(rows: readonly EffectOnDisk[], sameOrg: boolean): string | null {
  for (const row of rows) {
    if (row.witnessClass !== (sameOrg ? "same-org" : "self")) continue;
    const pem = row.receipt?.publicKeyPem;
    if (isPublicKeyPem(pem)) return pem;
  }
  return null;
}

const AGREE =
  "this shows the files are internally consistent, not that the key was ever trusted. Pin a key you hold to check that.";

function witnessTrustOf(pinned: string, taken: string | null, sameOrgCount: number): VerifyTrust {
  if (sameOrgCount === 0) {
    return {
      source: "none",
      publicKeyPem: null,
      note: "no same-org effects, so no witness key was used",
    };
  }
  if (pinned !== "") {
    return {
      source: "pinned",
      publicKeyPem: pinned,
      note: "verified against a key the reader supplied, not one taken from these files",
    };
  }
  if (taken) {
    return {
      source: "in-ledger",
      publicKeyPem: taken,
      note: `verified against the key carried in the same-org effects themselves: ${AGREE}`,
    };
  }
  return {
    source: "none",
    publicKeyPem: null,
    note: "no witness key was found in these files",
  };
}

function firstCheckpointKey(rows: readonly SignedCheckpoint[]): string | null {
  for (const row of rows) {
    if (isPublicKeyPem(row.publicKeyPem)) return row.publicKeyPem;
  }
  return null;
}

function checkpointTrustOf(pinned: string, taken: string | null, checkpointCount: number): VerifyTrust {
  if (checkpointCount === 0) {
    return {
      source: "none",
      publicKeyPem: null,
      note: "no checkpoints, so no checkpoint key was used",
    };
  }
  if (pinned !== "") {
    return {
      source: "pinned",
      publicKeyPem: pinned,
      note: "verified against a key the reader supplied, not one taken from these files",
    };
  }
  if (taken) {
    return {
      source: "in-ledger",
      publicKeyPem: taken,
      note:
        "verified against the key carried in the checkpoints themselves: this shows the files are " +
        "internally consistent, not that the key was ever trusted. Pin a key you hold to check that.",
    };
  }
  return {
    source: "none",
    publicKeyPem: null,
    note: "no checkpoint key was found in these files",
  };
}

/** One key for every row. A pin ignores the key a row carries. */
function checkpointRowVerifies(row: SignedCheckpoint, key: string | null): boolean {
  try {
    if (key && ed25519Refusal(key)) return false;
    if (key) return verifyCheckpointUnderPin(row, key) && verifyCheckpoint(row, key);
    return verifyCheckpoint(row);
  } catch {
    return false;
  }
}

function effectTrustOf(pinned: string, taken: string | null, effectCount: number): VerifyTrust {
  if (effectCount === 0) {
    return {
      source: "none",
      publicKeyPem: null,
      note: "no effects, so no effect key was used",
    };
  }
  if (pinned !== "") {
    return {
      source: "pinned",
      publicKeyPem: pinned,
      note: "verified against a key the reader supplied, not one taken from these files",
    };
  }
  if (taken) {
    return {
      source: "in-ledger",
      publicKeyPem: taken,
      note:
        `verified against the key carried in the self effects themselves: ${AGREE}`,
    };
  }
  return {
    source: "none",
    publicKeyPem: null,
    note: "no effect key was found in these files",
  };
}

const INDEX_NONE = "index: none (cannot check for removed records)";
const EFFECT_COMPLETENESS_UNCHECKED = "effect completeness was not checked";
const EFFECT_COMPLETENESS_CHECKED = "effect completeness checked";
const TAIL_NONE =
  "tail: no checkpoint; removing the newest records with their effects is not detectable from these files";
const CONTROL_NONE: VerifyControl = {
  line: "control: no control records",
  windows: 0,
  warnings: [],
};
const CONTROL_UNCHECKED: VerifyControl = {
  line: "control: not checked",
  windows: 0,
  warnings: [],
};

/**
 * A torn last line is the crash the writer already documents: earlier lines
 * parsed, so that tail is skipped. Any other line that is not JSON, and a
 * file whose every line fails to parse, is a problem.
 */
function indexLineProblems(text: string): string[] {
  const lines = text.split("\n");
  const filled: { n: number; line: string }[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i] !== "") filled.push({ n: i + 1, line: lines[i]! });
  }
  const problems: string[] = [];
  let parsedOk = 0;
  for (let i = 0; i < filled.length; i += 1) {
    const last = i === filled.length - 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(filled[i]!.line);
    } catch {
      if (!last || parsedOk === 0) problems.push(`index line ${filled[i]!.n} is not JSON`);
      continue;
    }
    parsedOk += 1;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      problems.push(`index line ${filled[i]!.n} is not a JSON object`);
    }
  }
  return problems;
}

function effectRefsInIndex(text: string): Set<string> {
  const refs = new Set<string>();
  for (const line of parseIndexText(text)) {
    if (line.hasEffect || line.kind === "effect") refs.add(line.ref);
  }
  return refs;
}

/**
 * `null` means the index is not there or could not be read, so effect
 * completeness was not checked. An empty set means it was checked and it
 * marks no effect.
 */
function indexStatement(
  dir: string,
  decisionRefs: ReadonlySet<string>,
): { index: VerifyIndex; problems: string[]; effectRefs: Set<string> | null } {
  const indexFile = indexPath(dir);
  const indexLink = symbolicLinkProblem(indexFile);
  if (indexLink !== null) {
    return { index: { present: true, missing: 0, line: indexLink }, problems: [indexLink], effectRefs: null };
  }
  if (!existsSync(indexFile)) {
    return { index: { present: false, missing: 0, line: INDEX_NONE }, problems: [], effectRefs: null };
  }
  let text = "";
  try {
    text = readFileSync(indexFile, "utf8");
  } catch {
    const line = "index could not be read";
    return { index: { present: true, missing: 0, line }, problems: [line], effectRefs: null };
  }
  const parseProblems = indexLineProblems(text);
  const lines = parseIndexText(text);
  const named = new Set<string>();
  for (const line of lines) named.add(line.ref);
  const effectRefs = effectRefsInIndex(text);
  let missing = 0;
  for (const ref of named) {
    if (!decisionRefs.has(ref)) missing += 1;
  }
  if (missing > 0) {
    const line = `index names ${missing} record(s) the ledger no longer holds`;
    return { index: { present: true, missing, line }, problems: [...parseProblems, line], effectRefs };
  }
  return {
    index: { present: true, missing: 0, line: `index: ${named.size} ref(s), each still a decision` },
    problems: parseProblems,
    effectRefs,
  };
}

function noteEffectCompleteness(
  effectRefs: Set<string> | null,
  bound: ReadonlySet<string>,
  problems: string[],
): string {
  if (effectRefs === null) return EFFECT_COMPLETENESS_UNCHECKED;
  for (const ref of effectRefs) {
    if (!bound.has(ref)) {
      problems.push(`index says ref ${ref} has an effect but no bound effect row`);
    }
  }
  return EFFECT_COMPLETENESS_CHECKED;
}

/** The core's default clock-skew allowance, which decision profile 6.1 applies unchanged. */
export const DEFAULT_BOUNDARY_ALLOWANCE_MS = 300_000;

/**
 * Every attested allow expects an effect row under its ref (decision profile
 * 6.1). This reads the signed records and the rows, never `index.jsonl`,
 * which is unsigned. A ref with a primary row, bound or not, is not this
 * finding: a row that fails to bind is already named for what is wrong with
 * it. The writer appends the row after the call returns, so an allow within
 * the allowance of the newest attested record may still be in flight; that
 * one is `boundary-deferred` and does not change `ok`. An older allow with no
 * row is `decision-without-effect`.
 */
function allowsWithoutEffect(
  attested: readonly SignedDecisionRecord[],
  rowRefs: ReadonlySet<string>,
  allowanceMs: number,
): { findings: string[]; deferred: string[] } {
  let newest = -Infinity;
  for (const r of attested) {
    if (typeof r.claims.timestampMs === "number" && r.claims.timestampMs > newest) newest = r.claims.timestampMs;
  }
  const findings: string[] = [];
  const deferred: string[] = [];
  const seen = new Set<string>();
  for (const r of attested) {
    const ref = r.claims.ref;
    if (r.claims.decision !== "allow" || typeof ref !== "string" || seen.has(ref)) continue;
    seen.add(ref);
    if (rowRefs.has(ref)) continue;
    const t = r.claims.timestampMs;
    if (typeof t === "number" && newest - t <= allowanceMs) deferred.push(ref);
    else findings.push(ref);
  }
  return { findings, deferred };
}

function tailStatement(
  dir: string,
  records: readonly SignedDecisionRecord[],
  checkpointPublicKeyPem: string,
  attested: readonly SignedDecisionRecord[] = records,
): { tail: VerifyTail; checkpointTrust: VerifyTrust; problems: string[]; verified: VerifiedCheckpoint[] } {
  const checkpointFile = checkpointsPath(dir);
  const checkpointLink = symbolicLinkProblem(checkpointFile);
  if (checkpointLink !== null) {
    const pinned = checkpointPublicKeyPem.trim();
    return {
      tail: { line: TAIL_NONE, checkpoint: null },
      checkpointTrust: checkpointTrustOf(pinned, null, 0),
      problems: [checkpointLink],
      verified: [],
    };
  }
  const loaded = readCheckpointFile(dir);
  const rows = loaded.rows;
  const pinned = checkpointPublicKeyPem.trim();
  const taken = firstCheckpointKey(rows);
  const key = pinned !== "" ? pinned : taken;
  const checkpointTrust = checkpointTrustOf(pinned, taken, rows.length);
  const problems: string[] = [...loaded.problems];
  const verified: VerifiedCheckpoint[] = [];
  noteEd25519(key, problems);
  for (let i = 0; i < rows.length; i += 1) {
    if (!checkpointRowVerifies(rows[i]!, key)) {
      problems.push(`checkpoint signature does not verify: checkpoint ${i}`);
      continue;
    }
    try {
      const count = rows[i]!.claims.receiptCount;
      verified.push({ hash: checkpointHash(rows[i]!), receiptCount: typeof count === "number" ? count : null });
    } catch {
      // A row that verified but cannot be hashed cannot be anchored either.
    }
    for (const problem of checkpointCountProblems(rows[i]!, records, attested)) {
      problems.push(`${problem}: checkpoint ${i}`);
    }
  }
  let brk: { index: number; reason: string } | null = null;
  try {
    brk = findCheckpointChainBreak(rows, key ?? undefined);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    problems.push(`checkpoint chain could not be checked: ${message}`);
    brk = rows.length > 0 ? { index: 0, reason: "bad-signature" } : null;
  }
  if (brk && brk.reason !== "bad-signature") {
    problems.push(
      `checkpoint chain breaks at checkpoint ${brk.index} (${brk.reason}): prevCheckpointHash does not match`,
    );
  }
  const covered = brk ? rows.slice(0, brk.index) : rows;
  const newest = covered.length > 0 ? covered[covered.length - 1]! : null;
  if (!newest) {
    return { tail: { line: TAIL_NONE, checkpoint: null }, checkpointTrust, problems, verified };
  }
  const claims = newest.claims;
  const receiptCount = typeof claims.receiptCount === "number" ? claims.receiptCount : null;
  const chainHeadHash = typeof claims.chainHeadHash === "string" ? claims.chainHeadHash : null;
  let ledgerHoldsRecord: boolean | null = null;
  if (chainHeadHash) {
    ledgerHoldsRecord = records.some((rec) => {
      try {
        return decisionRecordHash(rec) === chainHeadHash;
      } catch {
        return false;
      }
    });
  }
  if (receiptCount !== null && records.length < receiptCount) {
    problems.push(
      `checkpoint covers ${receiptCount} record(s); the ledger holds ${records.length}`,
    );
  }
  if (ledgerHoldsRecord === false) {
    problems.push("newest checkpoint names a record the ledger no longer holds");
  }
  const after = receiptCount === null ? null : records.length - receiptCount;
  const line =
    after === null
      ? "tail: newest checkpoint carries no record count to compare"
      : `tail: ${after < 0 ? 0 : after} record(s) after the newest checkpoint are not covered`;
  return {
    tail: { line, checkpoint: { receiptCount, chainHeadHash, ledgerHoldsRecord } },
    checkpointTrust,
    problems,
    verified,
  };
}

type VerifiedCheckpoint = { hash: string; receiptCount: number | null };

const ANCHORS_NONE: VerifyAnchors = {
  line: "anchors: none (no checkpoint is registered with a transparency service)",
  receipts: 0,
  verified: 0,
  checked: false,
};

function anchorStatement(
  dir: string,
  checkpoints: readonly VerifiedCheckpoint[],
  keyPem: string,
  problems: string[],
): VerifyAnchors {
  const read = readAnchors(dir);
  if (!read.present) return ANCHORS_NONE;
  problems.push(...read.problems);
  const receipts = read.rows.length;
  const services = [...new Set(read.rows.map((r) => r.service))].join(", ");
  if (keyPem === "") {
    return {
      line: `anchors: ${receipts} receipt(s) from ${services || "no service"}, not checked: pin the service key with --anchor-key`,
      receipts,
      verified: 0,
      checked: false,
    };
  }
  const byHash = new Map(checkpoints.map((c) => [c.hash, c]));
  let verified = 0;
  let newestCount: number | null = null;
  for (const row of read.rows) {
    const short = row.checkpointHash.slice(0, 12);
    const checkpoint = byHash.get(row.checkpointHash);
    if (!checkpoint) {
      problems.push(`anchor names a checkpoint the ledger does not hold: ${short}`);
      continue;
    }
    let entry: string;
    try {
      entry = anchorEntryHash(row.checkpointHash, row.route);
    } catch {
      problems.push(`anchor route is not one this verifier reads: ${short}`);
      continue;
    }
    if (entry !== row.entryHash) {
      problems.push(`anchor entry hash is not the checkpoint's: ${short}`);
      continue;
    }
    const check = verifyReceipt(Buffer.from(row.receiptB64, "base64"), Buffer.from(entry, "hex"), keyPem);
    if (!check.ok) {
      problems.push(`anchor receipt does not verify: ${short} (${check.stage}: ${check.reason})`);
      continue;
    }
    if (check.treeSize !== row.treeSize || check.leafIndex !== row.leafIndex) {
      problems.push(`anchor row disagrees with its receipt: ${short}`);
      continue;
    }
    verified += 1;
    if (checkpoint.receiptCount !== null && (newestCount === null || checkpoint.receiptCount > newestCount)) {
      newestCount = checkpoint.receiptCount;
    }
  }
  const covers = newestCount === null ? "" : `; the newest anchored checkpoint covers ${newestCount} record(s)`;
  return {
    line:
      verified === receipts
        ? `anchors: ${receipts} receipt(s) from ${services} verify under the key you supplied${covers}`
        : `anchors: ${verified} of ${receipts} receipt(s) verify under the key you supplied`,
    receipts,
    verified,
    checked: true,
  };
}

const INPUTS_UNCHECKED: VerifyInputs = { line: "inputs: not checked", matched: 0, missing: 0, mismatched: 0 };

/**
 * Pairs each record that carries an `inputsHash` with an inputs row under its
 * ref that hashes to it. Rows are used once. A ref can hold more rows than
 * records (a crash after the row, a retry), so a record is matched against
 * any unused row under its ref, not the k-th.
 */
function inputsStatement(
  paths: readonly string[],
  records: readonly SignedDecisionRecord[],
  problems: string[],
): VerifyInputs {
  const rowsByRef = new Map<string, string[]>();
  for (const path of paths) {
    for (const row of readJsonl(path, problems)) {
      if (!row || typeof row !== "object" || Array.isArray(row)) continue;
      const { ref, inputs } = row as { ref?: unknown; inputs?: unknown };
      if (typeof ref !== "string" || inputs === undefined) continue;
      let hash: string;
      try {
        hash = sha256Canonical(inputs);
      } catch {
        continue;
      }
      const list = rowsByRef.get(ref) ?? [];
      list.push(hash);
      rowsByRef.set(ref, list);
    }
  }
  let matched = 0;
  let missing = 0;
  let mismatched = 0;
  for (let i = 0; i < records.length; i += 1) {
    const claims = records[i]!.claims;
    const expected = claims?.inputsHash;
    if (typeof expected !== "string") continue;
    const ref = typeof claims.ref === "string" ? claims.ref : null;
    const rows = ref === null ? undefined : rowsByRef.get(ref);
    if (!rows || rows.length === 0) {
      missing += 1;
      problems.push(`inputs row missing: record ${i} (ref ${ref ?? "?"})`);
      continue;
    }
    const at = rows.indexOf(expected);
    if (at < 0) {
      mismatched += 1;
      problems.push(`inputs row does not match its record's inputsHash: record ${i} (ref ${ref})`);
      continue;
    }
    rows.splice(at, 1);
    matched += 1;
  }
  const line =
    missing === 0 && mismatched === 0
      ? `inputs: ${matched} record(s), each with its inputs row`
      : `inputs: ${matched} match, ${missing} missing, ${mismatched} do not match their record`;
  return { line, matched, missing, mismatched };
}

/**
 * What a checkpoint counted is fixed by its head. The witness counts the
 * records whose time falls in `[startMs, endMs)` and names the last of them
 * as the head, so the attested records in that window up to and including
 * the head must be `receiptCount` records ending at the head, and their
 * allow, deny and defer counts must be the signed totals (decision profile
 * 4.4). A record appended later with a time inside the window was never seen
 * by the witness and is not counted. A head the ledger does not hold is named
 * for every checkpoint, not only the newest. A null head means the witness
 * counted nothing. Null totals were redacted; the count is still checked.
 */
function checkpointCountProblems(
  row: SignedCheckpoint,
  records: readonly SignedDecisionRecord[],
  attested: readonly SignedDecisionRecord[],
): string[] {
  const claims = row.claims;
  const { startMs, endMs, receiptCount } = claims;
  if (typeof startMs !== "number" || typeof endMs !== "number") return ["checkpoint has no window"];
  const inWindow = (r: SignedDecisionRecord) => r.claims.timestampMs >= startMs && r.claims.timestampMs < endMs;
  let counted: SignedDecisionRecord[] = [];
  let headRecord: SignedDecisionRecord | null = null;
  if (typeof claims.chainHeadHash === "string") {
    const at = records.findIndex((r) => {
      try {
        return decisionRecordHash(r) === claims.chainHeadHash;
      } catch {
        return false;
      }
    });
    if (at < 0) return ["checkpoint names a head the ledger does not hold"];
    headRecord = records[at]!;
    const upTo = new Set(records.slice(0, at + 1));
    counted = attested.filter((r) => upTo.has(r) && inWindow(r));
  }
  const problems: string[] = [];
  const endsAtHead = headRecord === null ? counted.length === 0 : counted[counted.length - 1] === headRecord;
  if (typeof receiptCount !== "number" || receiptCount !== counted.length || !endsAtHead) {
    problems.push(
      `checkpoint covers ${String(receiptCount)} record(s) in its window; the ledger holds ${counted.length} there up to its head`,
    );
  }
  if (claims.totals !== null && claims.totals !== undefined) {
    let same = false;
    try {
      same = canonical(totalsFromDecisionRecords(counted)) === canonical(claims.totals);
    } catch {
      // A totals value that does not canonicalise is not the map the profile defines.
    }
    if (!same) problems.push("checkpoint totals do not match the records in its window");
  }
  return problems;
}

function controlStatement(records: readonly SignedDecisionRecord[]): {
  control: VerifyControl;
  violations: string[];
} {
  let open = false;
  let windows = 0;
  let controlRecords = 0;
  const warnings: string[] = [];
  const violations: string[] = [];
  for (const record of records) {
    const subject = typeof record.claims?.subject === "string" ? record.claims.subject : "";
    const decision = record.claims?.decision;
    const reason = record.claims?.reasonCode;
    const ref = typeof record.claims?.ref === "string" ? record.claims.ref : "?";
    // Only the two control subjects, with the control effect class, open or
    // close a window. Any other allow inside one is a violation, including a
    // downstream tool whose prefix happens to be "verax".
    const control = record.claims?.effectClass === "verax.control";
    const halt = control && decision === "allow" && subject === "verax.halt";
    const resume = control && decision === "allow" && subject === "verax.resume";
    if (halt || resume) controlRecords += 1;
    if (halt) {
      if (!open) windows += 1;
      open = true;
      continue;
    }
    if (resume) {
      open = false;
      continue;
    }
    if (decision === "allow") {
      if (open) violations.push(`allow-while-halted ${ref}`);
      continue;
    }
    if (decision === "deny" && reason === "halted" && !open) {
      warnings.push(`halted-deny-without-halt-record ${ref}`);
    }
  }
  if (controlRecords === 0) return { control: { ...CONTROL_NONE, warnings }, violations };
  return {
    control: { line: `control: ${windows} halt window(s)`, windows, warnings },
    violations,
  };
}

function unreadableResult(dir: string, problem: string): VerifyResult {
  const trust = { source: "none" as const, publicKeyPem: null, note: problem };
  return {
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
    trust,
    effectTrust: trust,
    witnessTrust: trust,
    checkpointTrust: trust,
    index: { present: false, missing: 0, line: INDEX_NONE },
    effectCompleteness: EFFECT_COMPLETENESS_UNCHECKED,
    tail: { line: TAIL_NONE, checkpoint: null },
    control: CONTROL_UNCHECKED,
    inputs: INPUTS_UNCHECKED,
    anchors: ANCHORS_NONE,
    problems: [problem],
  };
}

function isDecisionRow(row: unknown): row is SignedDecisionRecord {
  if (!row || typeof row !== "object" || Array.isArray(row)) return false;
  const claims = (row as { claims?: unknown }).claims;
  return claims !== null && typeof claims === "object";
}

export async function verifyLedger(dir: string, opts: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    return await verifyLedgerUnchecked(dir, opts);
  } catch (err) {
    const problem = err instanceof Error ? err.message : "ledger could not be read";
    return unreadableResult(dir, problem);
  }
}

async function verifyLedgerUnchecked(dir: string, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const problems: string[] = [];
  const files = ledgerFiles(dir, problems);
  const kararDosyalari = files.decisions;
  const records: SignedDecisionRecord[] = [];
  for (const path of kararDosyalari) {
    for (const row of readJsonl(path, problems)) {
      if (!isDecisionRow(row)) {
        problems.push("record is not a decision");
        continue;
      }
      records.push(row);
    }
  }

  // An empty directory is not a clean ledger. Saying "valid" over no records
  // would let a deleted ledger pass as a verified one.
  if (records.length === 0) {
    problems.push("no decisions found: this directory holds no ledger to verify");
    noteEd25519(opts.publicKeyPem, problems);
    noteEd25519(opts.effectPublicKeyPem, problems);
    const emptyIndex = indexStatement(dir, new Set());
    const emptyTail = tailStatement(dir, records, opts.checkpointPublicKeyPem ?? "");
    const effectCompleteness = noteEffectCompleteness(emptyIndex.effectRefs, new Set(), problems);
    problems.push(...emptyIndex.problems, ...emptyTail.problems);
    const emptyControl = controlStatement(records);
    return {
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
      trust: { source: "none", publicKeyPem: null, note: "no records, so no key was used" },
      effectTrust: effectTrustOf(opts.effectPublicKeyPem?.trim() ?? "", null, 0),
      witnessTrust: witnessTrustOf(opts.witnessPublicKeyPem?.trim() ?? "", null, 0),
      checkpointTrust: emptyTail.checkpointTrust,
      index: emptyIndex.index,
      effectCompleteness,
      tail: emptyTail.tail,
      control: emptyControl.control,
      inputs: INPUTS_UNCHECKED,
      anchors: ANCHORS_NONE,
      problems,
    };
  }

  const pinned = opts.publicKeyPem?.trim();
  const icerden = typeof records[0]?.publicKeyPem === "string" ? records[0].publicKeyPem : null;
  const anahtar = pinned && pinned !== "" ? pinned : icerden;
  const trust: VerifyTrust =
    pinned && pinned !== ""
      ? {
          source: "pinned",
          publicKeyPem: pinned,
          note: "verified against a key the reader supplied, not one taken from these files",
        }
      : {
          source: "in-ledger",
          publicKeyPem: icerden,
          note:
            "verified against the key carried in the records themselves: this shows the files are " +
            "internally consistent, not that the key was ever trusted. Pin a key you hold to check that.",
        };

  let signaturesValid = 0;
  let signaturesInvalid = 0;
  const attested: SignedDecisionRecord[] = [];
  const recordRefused = ed25519Refusal(anahtar);
  if (recordRefused) problems.push(recordRefused);
  for (let i = 0; i < records.length; i += 1) {
    const rec = records[i]!;
    let gecerli = false;
    try {
      gecerli = !recordRefused && verifyDecisionRecord(rec, anahtar ?? undefined);
    } catch {
      gecerli = false;
    }
    if (gecerli) {
      signaturesValid += 1;
      attested.push(rec);
    } else {
      signaturesInvalid += 1;
      const ref = typeof rec.claims?.ref === "string" ? rec.claims.ref : "?";
      problems.push(`signature does not verify: record ${i} (ref ${ref})`);
    }
  }

  // Returns `{ index, reason }` or null. The reason is carried through: a
  // broken link and a bad signature are different accidents, and a reader
  // chasing one should not be told the other.
  let brk: ReturnType<typeof findDecisionRecordChainBreak> = null;
  try {
    brk = findDecisionRecordChainBreak(records, anahtar ? [anahtar] : undefined);
  } catch (err) {
    problems.push(err instanceof Error ? err.message : "record shape is not a decision");
  }
  const chainBreakAt = brk ? brk.index : null;
  if (brk) {
    problems.push(`chain breaks at record ${brk.index} (${brk.reason}): a row was changed, removed or inserted`);
  }

  // An effect is bound only when a decision with that ref records the same
  // effectHash. A `:threw` row relaxes the hash and nothing else: it binds
  // only when some decision on that ref is an allow and the row's class is
  // exactly that decision's effectClass plus `:threw`. A deny did not throw,
  // and an allow of a different tool is not this class. A `duplicate-effect`
  // row must carry the writer's fixed refusal hash. The attestation plus
  // receipt still verify under one effect key. A mismatch is named and counts
  // as orphaned. A second primary row for a ref that already has one is named
  // and is not bound, even when the first row itself did not bind.
  const refler = new Set<string>();
  const hashesByRef = new Map<string, Set<string>>();
  const allowedClassesByRef = new Map<string, Set<string>>();
  for (const r of records) {
    if (typeof r.claims?.ref !== "string") continue;
    refler.add(r.claims.ref);
    const recorded = r.claims?.effectHash;
    if (typeof recorded === "string") {
      const bag = hashesByRef.get(r.claims.ref) ?? new Set<string>();
      bag.add(recorded);
      hashesByRef.set(r.claims.ref, bag);
    }
    if (r.claims.decision === "allow" && typeof r.claims.effectClass === "string" && r.claims.effectClass !== "") {
      const allowed = allowedClassesByRef.get(r.claims.ref) ?? new Set<string>();
      allowed.add(r.claims.effectClass);
      allowedClassesByRef.set(r.claims.ref, allowed);
    }
  }
  const effectRows: EffectOnDisk[] = [];
  for (const path of files.effects) {
    for (const row of readJsonl(path, problems)) {
      if (!row || typeof row !== "object" || Array.isArray(row)) {
        problems.push("effect is not an effect row");
        continue;
      }
      effectRows.push(row as EffectOnDisk);
    }
  }
  const pinnedEffect = opts.effectPublicKeyPem?.trim() ?? "";
  const pinnedWitness = opts.witnessPublicKeyPem?.trim() ?? "";
  const selfKeyTaken = firstReceiptKey(effectRows, false);
  const sameKeyTaken = firstReceiptKey(effectRows, true);
  const effectKey = pinnedEffect !== "" ? pinnedEffect : selfKeyTaken;
  const witnessKey = pinnedWitness !== "" ? pinnedWitness : sameKeyTaken;
  const selfCount = effectRows.filter((row) => row.witnessClass === "self").length;
  const sameCount = effectRows.filter((row) => row.witnessClass === "same-org").length;
  const thirdPartyKeys = (opts.thirdPartyPublicKeyPems ?? []).filter((key) => {
    const roles = [
      ["record", [anahtar, ...records.map(r => r.publicKeyPem)]],
      ["effect", [effectKey, ...effectRows.filter(e => e.witnessClass === "self").map(e => e.receipt?.publicKeyPem)]],
      ["witness", [witnessKey, ...effectRows.filter(e => e.witnessClass === "same-org").map(e => e.receipt?.publicKeyPem)]],
    ] as const;
    for (const [role, known] of roles) {
      if (known.some(pem => samePublicKey(key, pem))) {
        problems.push(`third-party key equals ${role} key; not accepted for third-party rows`);
        return false;
      }
    }
    const refusal = ed25519Refusal(key);
    if (refusal) { problems.push(`third-party key rejected: ${refusal}`); return false; }
    return true;
  });
  const effectTrust = effectTrustOf(pinnedEffect, selfKeyTaken, selfCount);
  const witnessTrust = witnessTrustOf(pinnedWitness, sameKeyTaken, sameCount);
  if (pinnedEffect !== "" && pinnedWitness === "" && sameCount > 0) {
    problems.push("same-org rows need --witness-key when --effect-key is pinned");
  }
  if (pinnedWitness !== "" && pinnedEffect === "" && selfCount > 0) {
    problems.push("self rows need --effect-key when --witness-key is pinned");
  }
  noteEd25519(effectKey, problems);
  noteEd25519(witnessKey, problems);
  let effects = effectRows.length;
  let effectsBound = 0;
  let effectsOrphaned = 0;
  const boundPrimaryRefs = new Set<string>();
  const primarySeen = new Set<string>();
  const duplicateSeen = new Set<string>();
  for (const e of effectRows) {
    const ref = typeof e.row?.ref === "string" ? e.row.ref : null;
    const effectHash = typeof e.row?.effectHash === "string" ? e.row.effectHash : null;
    const effectClass = typeof e.row?.effectClass === "string" ? e.row.effectClass : "";
    if (effectClass === "duplicate-effect") {
      // Duplicate refusals are body observations, never downstream receipts.
      if (e.witnessClass === "third-party") {
        effectsOrphaned += 1;
        problems.push(`third-party row ${ref ?? "(missing)"} cannot be a duplicate-effect refusal`);
        continue;
      }
      const sig = typeof e.attestation?.coseHex === "string" ? e.attestation.coseHex : "";
      const dupKey = `${ref ?? ""}\0${sig}`;
      if (sig !== "" && duplicateSeen.has(dupKey)) {
        problems.push(`duplicate-effect row repeated: ref ${ref ?? "(missing)"}`);
        continue;
      }
      if (sig !== "") duplicateSeen.add(dupKey);
      const fixed =
        ref === null ? null : sha256Canonical({ refused: "duplicate-effect", ref });
      const boundRefusal = ref !== null && refler.has(ref) && effectHash !== null && effectHash === fixed;
      if (!boundRefusal) {
        effectsOrphaned += 1;
        problems.push(
          ref === null || !refler.has(ref)
            ? `duplicate-effect with no decision: ref ${ref ?? "(missing)"}`
            : `duplicate-effect hash is not the fixed refusal: ref ${ref}`,
        );
        continue;
      }
      if (!effectSignatureCoversRow(e, e.witnessClass === "same-org" ? witnessKey : effectKey)) {
        effectsOrphaned += 1;
        problems.push(effectProblem(e, ref));
        continue;
      }
      effectsBound += 1;
      continue;
    }
    if (ref !== null && primarySeen.has(ref)) {
      problems.push(`ref ${ref} has more than one effect row`);
      continue;
    }
    if (ref !== null) primarySeen.add(ref);
    const hashes = ref === null ? undefined : hashesByRef.get(ref);
    const hashMatch = effectHash !== null && hashes?.has(effectHash) === true;
    if (e.witnessClass !== "third-party" && effectClass.endsWith(":threw")) {
      const allowed = ref === null ? undefined : allowedClassesByRef.get(ref);
      let thrownOk = false;
      if (allowed) {
        for (const cls of allowed) {
          if (`${cls}:threw` === effectClass) {
            thrownOk = true;
            break;
          }
        }
      }
      if (!thrownOk) {
        effectsOrphaned += 1;
        problems.push(`thrown effect does not match an allowed decision: ref ${ref ?? "(missing)"}`);
        continue;
      }
    } else if (!hashMatch) {
      effectsOrphaned += 1;
      problems.push(
        ref === null || !refler.has(ref)
          ? `effect with no decision: ref ${ref ?? "(missing)"}`
          : `effect hash does not match its decision: ref ${ref}`,
      );
      continue;
    }
    if (e.witnessClass === "third-party") {
      if (!thirdPartyKeys.some(key => thirdPartyReceiptCoversRow(e.receipt, e.row, key))) {
        effectsOrphaned += 1;
        problems.push((opts.thirdPartyPublicKeyPems?.length ?? 0) === 0
          ? `third-party row ${ref ?? "(missing)"} unchecked: no pinned third-party key`
          : `third-party row ${ref ?? "(missing)"} receipt does not cover the row under an accepted pinned third-party key`);
        continue;
      }
      // Only the effect row is signed; resultHash has no third-party attestation.
    } else if (!effectSignatureCoversRow(e, e.witnessClass === "same-org" ? witnessKey : effectKey)) {
      effectsOrphaned += 1;
      problems.push(effectProblem(e, ref));
      continue;
    }
    effectsBound += 1;
    if (ref !== null) boundPrimaryRefs.add(ref);
  }

  const unbound = allowsWithoutEffect(
    attested,
    primarySeen,
    opts.boundaryAllowanceMs ?? DEFAULT_BOUNDARY_ALLOWANCE_MS,
  );
  problems.push(...unbound.findings.map((ref) => `decision-without-effect ${ref}`));

  const indexed = indexStatement(dir, refler);
  const effectCompleteness = noteEffectCompleteness(indexed.effectRefs, boundPrimaryRefs, problems);
  const inputs = inputsStatement(files.inputs, records, problems);
  const tailed = tailStatement(dir, records, opts.checkpointPublicKeyPem ?? "", attested);
  problems.push(...indexed.problems, ...tailed.problems);
  const stated = controlStatement(records);
  problems.push(...stated.violations);
  const anchors = anchorStatement(dir, tailed.verified, opts.anchorPublicKeyPem?.trim() ?? "", problems);

  const ok =
    problems.length === 0 && signaturesInvalid === 0 && chainBreakAt === null && effectsOrphaned === 0;

  return {
    ok,
    directory: dir,
    decisions: records.length,
    effects,
    signaturesValid,
    signaturesInvalid,
    chainBreakAt,
    effectsBound,
    effectsOrphaned,
    effectsDeferred: unbound.deferred,
    trust,
    effectTrust,
    witnessTrust,
    checkpointTrust: tailed.checkpointTrust,
    index: indexed.index,
    effectCompleteness,
    tail: tailed.tail,
    control: stated.control,
    inputs,
    anchors,
    problems,
  };
}
