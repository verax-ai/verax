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
 *   effects     each effect row is bound to a decision by `effectHash`
 *
 * And a fourth, which matters most and is the easiest to fudge: **which key**.
 * A ledger checked against the key sitting next to it is internally
 * consistent and nothing more — whatever could write the file could write
 * that key too (the downstream audit showed exactly this: a stdio child runs
 * as the same user and can read `keys/*.pem`). So the trust source is part of
 * the answer rather than a footnote, and `publicKeyPem` lets a reader pin a
 * copy they hold themselves.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { findDecisionRecordChainBreak, verifyDecisionRecord } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";

import { readLedgerManifest } from "./ledger-manifest.ts";

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
  problems: string[];
};

export type VerifyOptions = {
  /** Verify against this key instead of the one the records carry. */
  publicKeyPem?: string;
};

/** Every decisions file this directory holds, oldest piece first. */
function decisionFiles(dir: string): string[] {
  const manifest = readLedgerManifest(dir);
  if (manifest && Array.isArray(manifest.pieces) && manifest.pieces.length > 0) {
    return manifest.pieces.map((p) => join(dir, p.decisions)).filter((p) => existsSync(p));
  }
  const tek = join(dir, "decisions.jsonl");
  return existsSync(tek) ? [tek] : [];
}

function effectFiles(dir: string): string[] {
  const manifest = readLedgerManifest(dir);
  if (manifest && Array.isArray(manifest.pieces) && manifest.pieces.length > 0) {
    return manifest.pieces.map((p) => join(dir, p.effects)).filter((p) => existsSync(p));
  }
  const tek = join(dir, "effects.jsonl");
  return existsSync(tek) ? [tek] : [];
}

/** Parses JSONL, reporting the line a bad row sits on rather than throwing. */
function readJsonl(path: string, problems: string[]): unknown[] {
  const out: unknown[] = [];
  const text = readFileSync(path, "utf8");
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

export async function verifyLedger(dir: string, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const problems: string[] = [];
  const kararDosyalari = decisionFiles(dir);
  const records: SignedDecisionRecord[] = [];
  for (const path of kararDosyalari) {
    for (const row of readJsonl(path, problems)) {
      records.push(row as SignedDecisionRecord);
    }
  }

  // An empty directory is not a clean ledger. Saying "valid" over no records
  // would let a deleted ledger pass as a verified one.
  if (records.length === 0) {
    problems.push("no decisions found: this directory holds no ledger to verify");
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
  for (let i = 0; i < records.length; i += 1) {
    const rec = records[i]!;
    let gecerli = false;
    try {
      gecerli = verifyDecisionRecord(rec, anahtar ?? undefined);
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
  const brk = findDecisionRecordChainBreak(records, anahtar ? [anahtar] : undefined);
  const chainBreakAt = brk ? brk.index : null;
  if (brk) {
    problems.push(`chain breaks at record ${brk.index} (${brk.reason}): a row was changed, removed or inserted`);
  }

  // Each effect names the decision it belongs to. An effect whose ref is on no
  // record is an action with no decision behind it — the loudest thing this
  // file can find, so it is counted rather than summarised away.
  const refler = new Set<string>();
  for (const r of records) {
    if (typeof r.claims?.ref === "string") refler.add(r.claims.ref);
  }
  let effects = 0;
  let effectsBound = 0;
  let effectsOrphaned = 0;
  for (const path of effectFiles(dir)) {
    for (const row of readJsonl(path, problems)) {
      effects += 1;
      const e = row as { row?: { ref?: unknown } };
      const ref = typeof e.row?.ref === "string" ? e.row.ref : null;
      if (ref !== null && refler.has(ref)) {
        effectsBound += 1;
      } else {
        effectsOrphaned += 1;
        problems.push(`effect with no decision: ref ${ref ?? "(missing)"}`);
      }
    }
  }

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
    problems,
  };
}
