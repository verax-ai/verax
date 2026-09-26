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
 *               The effect key is
 *               `effectPublicKeyPem` when the reader pins one; otherwise the
 *               first receipt key in the ledger, and every effect row is
 *               checked against that same key.
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
 * And a fourth, which matters most and is the easiest to fudge: **which key**.
 * A ledger checked against the key sitting next to it is internally
 * consistent and nothing more — whatever could write the file could write
 * that key too (the downstream audit showed exactly this: a stdio child runs
 * as the same user and can read `keys/*.pem`). So the trust source is part of
 * the answer rather than a footnote, and `publicKeyPem` lets a reader pin a
 * copy they hold themselves.
 */
import { createPublicKey } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  findCheckpointChainBreak,
  verifyCheckpoint,
  verifyCheckpointUnderPin,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { canonical, decisionRecordHash, findDecisionRecordChainBreak, verifyDecisionRecord } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";
import { coseFromHex, decodeCoseSign1, verifyCoseSign1 } from "@cedulon/cose";
import { verifyEffectExtract, type SignedEffectExtract } from "@cedulon/effect-extract";

import { checkpointsPath, readCheckpointFile } from "./checkpoints.ts";
import { sha256Canonical } from "./hash.ts";
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
  trust: VerifyTrust;
  /** Which key answered for effect rows. Same honesty rules as `trust`. */
  effectTrust: VerifyTrust;
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
  problems: string[];
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

export type VerifyOptions = {
  /** Verify decision records against this key instead of the one they carry. */
  publicKeyPem?: string;
  /** Verify every effect row against this key instead of the one the effects carry. */
  effectPublicKeyPem?: string;
  /** Verify every checkpoint row against this key instead of one key taken from the file. */
  checkpointPublicKeyPem?: string;
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
 * A piece that is a symbolic link is named and is not opened. `existsSync`
 * runs only after both checks.
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
  return existsSync(path) ? path : null;
}

/** Decision and effect files this directory holds, oldest piece first. Inputs are confined and not read. */
function ledgerFiles(dir: string, problems: string[]): { decisions: string[]; effects: string[] } {
  const manifestFile = manifestPath(dir);
  const manifestLink = symbolicLinkProblem(manifestFile);
  if (manifestLink !== null) {
    problems.push(manifestLink);
    return { decisions: [], effects: [] };
  }
  if (existsSync(manifestFile)) {
    try {
      const manifest = readLedgerManifest(dir);
      if (manifest && Array.isArray(manifest.pieces) && manifest.pieces.length > 0) {
        return pieceFiles(dir, manifest.pieces, problems);
      }
    } catch (err) {
      problems.push(err instanceof Error ? err.message : "ledger-manifest-unreadable");
      return { decisions: [], effects: [] };
    }
  }
  return legacyFiles(dir);
}

function legacyFiles(dir: string): { decisions: string[]; effects: string[] } {
  const decisionsPath = join(dir, "decisions.jsonl");
  const effectsPath = join(dir, "effects.jsonl");
  return {
    decisions: existsSync(decisionsPath) ? [decisionsPath] : [],
    effects: existsSync(effectsPath) ? [effectsPath] : [],
  };
}

function pieceFiles(
  dir: string,
  pieces: { decisions: string; effects: string; inputs: string }[],
  problems: string[],
): { decisions: string[]; effects: string[] } {
  const decisions: string[] = [];
  const effects: string[] = [];
  for (const p of pieces) {
    const decision = takePieceFile(dir, p.decisions, problems, true);
    if (decision) decisions.push(decision);
    const effect = takePieceFile(dir, p.effects, problems, true);
    if (effect) effects.push(effect);
    takePieceFile(dir, p.inputs, problems, false);
  }
  return { decisions, effects };
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
 * Sign1 and a one-row extract with the same effect key. A row with either
 * missing is not bound. Both must verify under the one key the caller
 * settled on — never a key this row brought by itself.
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

function firstEffectKey(rows: readonly EffectOnDisk[]): string | null {
  for (const row of rows) {
    const pem = row.receipt?.publicKeyPem;
    if (isPublicKeyPem(pem)) return pem;
  }
  return null;
}

function firstCheckpointKey(rows: readonly SignedCheckpoint[]): string | null {
  for (const row of rows) {
    if (isPublicKeyPem(row.publicKeyPem)) return row.publicKeyPem;
  }
  return null;
}

function checkpointTrustOf(pinned: string, taken: string | null, checkpointCount: number): VerifyTrust {
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
    note:
      checkpointCount === 0
        ? "no checkpoints, so no checkpoint key was used"
        : "no checkpoint key was found in these files",
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
        "verified against the key carried in the effects themselves: this shows the files are " +
        "internally consistent, not that the key was ever trusted. Pin a key you hold to check that.",
    };
  }
  return {
    source: "none",
    publicKeyPem: null,
    note: effectCount === 0 ? "no effects, so no effect key was used" : "no effect key was found in these files",
  };
}

const INDEX_NONE = "index: none (cannot check for removed records)";
const EFFECT_COMPLETENESS_UNCHECKED = "effect completeness was not checked";
const EFFECT_COMPLETENESS_CHECKED = "effect completeness checked";
const TAIL_NONE =
  "tail: no checkpoint; removing the newest records with their effects is not detectable from these files";

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
    try {
      JSON.parse(filled[i]!.line);
      parsedOk += 1;
    } catch {
      if (!last || parsedOk === 0) problems.push(`index line ${filled[i]!.n} is not JSON`);
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

function tailStatement(
  dir: string,
  records: readonly SignedDecisionRecord[],
  checkpointPublicKeyPem: string,
): { tail: VerifyTail; checkpointTrust: VerifyTrust; problems: string[] } {
  const checkpointFile = checkpointsPath(dir);
  const checkpointLink = symbolicLinkProblem(checkpointFile);
  if (checkpointLink !== null) {
    const pinned = checkpointPublicKeyPem.trim();
    return {
      tail: { line: TAIL_NONE, checkpoint: null },
      checkpointTrust: checkpointTrustOf(pinned, null, 0),
      problems: [checkpointLink],
    };
  }
  const loaded = readCheckpointFile(dir);
  const rows = loaded.rows;
  const pinned = checkpointPublicKeyPem.trim();
  const taken = firstCheckpointKey(rows);
  const key = pinned !== "" ? pinned : taken;
  const checkpointTrust = checkpointTrustOf(pinned, taken, rows.length);
  const problems: string[] = [...loaded.problems];
  noteEd25519(key, problems);
  for (let i = 0; i < rows.length; i += 1) {
    if (!checkpointRowVerifies(rows[i]!, key)) {
      problems.push(`checkpoint signature does not verify: checkpoint ${i}`);
    }
  }
  let brk: { index: number; reason: string } | null = null;
  try {
    brk = findCheckpointChainBreak(rows, key ?? undefined);
  } catch {
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
    return { tail: { line: TAIL_NONE, checkpoint: null }, checkpointTrust, problems };
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
    trust,
    effectTrust: trust,
    checkpointTrust: trust,
    index: { present: false, missing: 0, line: INDEX_NONE },
    effectCompleteness: EFFECT_COMPLETENESS_UNCHECKED,
    tail: { line: TAIL_NONE, checkpoint: null },
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
      trust: { source: "none", publicKeyPem: null, note: "no records, so no key was used" },
      effectTrust: effectTrustOf(opts.effectPublicKeyPem?.trim() ?? "", null, 0),
      checkpointTrust: emptyTail.checkpointTrust,
      index: emptyIndex.index,
      effectCompleteness,
      tail: emptyTail.tail,
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
  const effectKey = pinnedEffect !== "" ? pinnedEffect : firstEffectKey(effectRows);
  const effectTrust = effectTrustOf(pinnedEffect, effectKey, effectRows.length);
  noteEd25519(effectKey, problems);
  let effects = effectRows.length;
  let effectsBound = 0;
  let effectsOrphaned = 0;
  const boundPrimaryRefs = new Set<string>();
  const primarySeen = new Set<string>();
  for (const e of effectRows) {
    const ref = typeof e.row?.ref === "string" ? e.row.ref : null;
    const effectHash = typeof e.row?.effectHash === "string" ? e.row.effectHash : null;
    const effectClass = typeof e.row?.effectClass === "string" ? e.row.effectClass : "";
    if (effectClass === "duplicate-effect") {
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
      if (!effectSignatureCoversRow(e, effectKey)) {
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
    if (effectClass.endsWith(":threw")) {
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
    if (!effectSignatureCoversRow(e, effectKey)) {
      effectsOrphaned += 1;
      problems.push(effectProblem(e, ref));
      continue;
    }
    effectsBound += 1;
    if (ref !== null) boundPrimaryRefs.add(ref);
  }

  const indexed = indexStatement(dir, refler);
  const effectCompleteness = noteEffectCompleteness(indexed.effectRefs, boundPrimaryRefs, problems);
  const tailed = tailStatement(dir, records, opts.checkpointPublicKeyPem ?? "");
  problems.push(...indexed.problems, ...tailed.problems);

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
    trust,
    effectTrust,
    checkpointTrust: tailed.checkpointTrust,
    index: indexed.index,
    effectCompleteness,
    tail: tailed.tail,
    problems,
  };
}
