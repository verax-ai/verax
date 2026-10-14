import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { join } from "node:path";

import { signDecisionRecord } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";

import { sha256Canonical } from "./hash.ts";
import type { LedgerWriter } from "./ledger.ts";
import type { DecisionInputs, InputsLog, OperatorRemovalInput, RecordSigner } from "./types.ts";

/**
 * Same directory as `packages/body/src/operator-credentials.ts`. The directory
 * stays the switch: the body treats a passkey as removed when its mark is
 * one of the names there, and it does not read what that name holds. This
 * module keeps the ledger's account of that set of names.
 *
 * The ledger's list is replayed from its `verax.operator` records of effect
 * class `verax.control`. A mark in the directory and not in that list is one
 * `passkey-removed` record; a mark in that list and gone from the directory
 * is one `passkey-removal-undone` record, because taking the mark away lets
 * that passkey in again and nothing else would say so. Both are denies with
 * no effect: a removal refuses, it does not let a call through, and a
 * verifier that predates these records reads them as ordinary denies.
 *
 * A removal is not in the ledger until the body opens or the next call
 * reaches the proxy. The command that writes the mark does not.
 *
 * A directory that cannot be listed is left unwritten. It is not an empty
 * directory: the marks were not taken away, and a `passkey-removal-undone`
 * record would say that they were.
 */
export const OPERATOR_REMOVED_DIR = "operator-removed";

const SUBJECT = "verax.operator";
const CONTROL_EFFECT = "verax.control";
const MARK_NAME = /^[0-9a-f]{64}$/;

/** The name a removed passkey's mark is filed under. An id can be longer than a file name may be. */
export function operatorRemovalMark(id: string): string {
  return createHash("sha256").update(id, "utf8").digest("hex");
}

/** `unlistable` is a directory we could not read. It is not an empty name list. */
type Listing = { kind: "marks"; names: string[] } | { kind: "unlistable" };

export type OperatorRemovalMemory = {
  loaded: boolean;
  stamp: Listing | null;
  removed: Set<string>;
};

export function createOperatorRemovalMemory(): OperatorRemovalMemory {
  return { loaded: false, stamp: null, removed: new Set() };
}

/**
 * True when the sorted mark names, or the fact that they cannot be listed,
 * are unchanged since the last sync. A directory timestamp is not a stamp:
 * the names are the list, and a timestamp can change without them.
 */
export function operatorRemovalUnchanged(stateDir: string, memory: OperatorRemovalMemory): boolean {
  const listing = listMarks(stateDir);
  if (!sameListing(memory.stamp, listing)) return false;
  // Nothing to reconcile until the names can be read. Opening the ledger on
  // every such call would only repeat the same miss.
  if (listing.kind === "unlistable") return true;
  return memory.loaded;
}

export async function syncOperatorRemovalControl(opts: {
  stateDir: string;
  now: () => number;
  nonce: () => string;
  policyHash: string;
  recordSigner: RecordSigner;
  inputsLog: InputsLog;
  decisions: () => Promise<SignedDecisionRecord[]>;
  memory: OperatorRemovalMemory;
  writer: LedgerWriter;
}): Promise<void> {
  const memory = opts.memory;
  if (operatorRemovalUnchanged(opts.stateDir, memory)) return;

  let listing = listMarks(opts.stateDir);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const after = listMarks(opts.stateDir);
    if (sameListing(listing, after)) break;
    listing = after;
  }

  if (listing.kind === "unlistable") {
    // Remember the miss so the next call does not open the ledger again.
    // Do not replay and do not write: an unlisted directory is not "no marks".
    memory.stamp = listing;
    return;
  }

  if (!memory.loaded) {
    memory.removed = await replay(opts);
    memory.loaded = true;
  }

  try {
    const inDir = new Set(listing.names);
    for (const mark of listing.names) {
      if (memory.removed.has(mark)) continue;
      const atMs = opts.now();
      await writeRemoval(opts, { action: "remove", mark, by: "unknown", via: "file", atMs });
      memory.removed.add(mark);
    }
    for (const mark of [...memory.removed]) {
      if (inDir.has(mark)) continue;
      const atMs = opts.now();
      await writeRemoval(opts, { action: "restore", mark, by: "unknown", via: "file", atMs });
      memory.removed.delete(mark);
    }
    memory.stamp = listing;
  } catch (err) {
    // A partial append is already on disk. Replay the ledger next time rather
    // than trust a list that may be ahead of it or behind it.
    memory.loaded = false;
    throw err;
  }
}

function listMarks(stateDir: string): Listing {
  let names: string[];
  try {
    names = readdirSync(join(stateDir, OPERATOR_REMOVED_DIR));
  } catch (err) {
    // Missing means nothing has been removed. Any other error means the
    // names cannot be known; the caller must not treat that as an empty list.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { kind: "marks", names: [] };
    return { kind: "unlistable" };
  }
  // The body matches the name and does not open it, so a mark counts whether
  // it is a file or a directory, and any other name is ignored.
  return { kind: "marks", names: names.filter((name) => MARK_NAME.test(name)).sort() };
}

function sameListing(a: Listing | null, b: Listing): boolean {
  if (a === null || a.kind !== b.kind) return false;
  if (a.kind === "unlistable" || b.kind === "unlistable") return true;
  if (a.names.length !== b.names.length) return false;
  for (let i = 0; i < a.names.length; i += 1) {
    if (a.names[i] !== b.names[i]) return false;
  }
  return true;
}

async function replay(opts: {
  decisions: () => Promise<SignedDecisionRecord[]>;
  inputsLog: InputsLog;
}): Promise<Set<string>> {
  const removed = new Set<string>();
  for (const decision of await opts.decisions()) {
    if (decision.claims.subject !== SUBJECT || decision.claims.effectClass !== CONTROL_EFFECT) continue;
    const ref = decision.claims.ref;
    if (typeof ref !== "string") continue;
    const row = (await opts.inputsLog.get(ref))?.operatorRemoval;
    if (!row || typeof row.mark !== "string") continue;
    if (row.action === "remove") removed.add(row.mark);
    else if (row.action === "restore") removed.delete(row.mark);
  }
  return removed;
}

async function writeRemoval(
  opts: {
    nonce: () => string;
    policyHash: string;
    recordSigner: RecordSigner;
    inputsLog: InputsLog;
    writer: LedgerWriter;
  },
  operatorRemoval: OperatorRemovalInput,
): Promise<void> {
  const ref = opts.nonce();
  const inputs: DecisionInputs = {
    principal: { brain: "verax-proxy", scopes: [] },
    inputs: [],
    operatorRemoval,
  };
  const inputsHash = sha256Canonical(inputs);
  await opts.inputsLog.append(ref, inputs);
  await opts.writer.appendDecisionChained((prevRecordHash) =>
    signDecisionRecord(
      {
        decider: "verax-proxy",
        subject: SUBJECT,
        requestHash: sha256Canonical(operatorRemoval),
        policyHash: opts.policyHash,
        inputsHash,
        decision: "deny",
        reasonCode: operatorRemoval.action === "remove" ? "passkey-removed" : "passkey-removal-undone",
        ref,
        effectHash: null,
        effectClass: CONTROL_EFFECT,
        timestampMs: operatorRemoval.atMs,
        nonce: ref,
        prevRecordHash,
      },
      opts.recordSigner.privateKeyPem,
      opts.recordSigner.publicKeyPem,
    ),
  );
}
