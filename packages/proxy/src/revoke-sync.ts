import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { signDecisionRecord } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";

import { sha256Canonical } from "./hash.ts";
import type { LedgerWriter } from "./ledger.ts";
import type { DecisionInputs, InputsLog, RecordSigner, RevokeInput } from "./types.ts";

/**
 * Same file as `packages/body/src/revoke.ts` and the issuer's `POST /revoke`.
 * The file stays the switch: the body refuses a listed jti whether or not the
 * ledger has caught up. This module keeps the ledger's account of that list.
 *
 * The ledger's list is replayed from its `verax.revoke` records. A jti in the
 * file and not in that list is one `token-revoked` record; a jti in that list
 * and gone from the file is one `revoke-removed` record, because removing a
 * line lets that token in again and nothing else would say so. Both are
 * denies with no effect: a revocation refuses, it does not let a call through,
 * and a verifier that predates these records reads them as ordinary denies.
 *
 * Like a CLI halt, a revocation is not in the ledger until the body opens,
 * the halt doors sync, or the next call reaches the proxy. A call made with
 * the revoked token is refused before the proxy and does not sync.
 */
const REVOKED = "revoked-jti.jsonl";
const SUBJECT = "verax.revoke";
const CONTROL_EFFECT = "verax.control";
const MAX_JTI = 256;
const MAX_BY = 256;

type Stamp = { size: number; mtimeMs: number } | null;

export type RevokeMemory = {
  loaded: boolean;
  stamp: Stamp;
  revoked: Set<string>;
};

export function createRevokeMemory(): RevokeMemory {
  return { loaded: false, stamp: null, revoked: new Set() };
}

export function revokeUnchanged(stateDir: string, memory: RevokeMemory): boolean {
  return memory.loaded && sameStamp(memory.stamp, fileStamp(stateDir));
}

type Listed = { jti: string; by: string; via: RevokeInput["via"]; atMs: number | null };

export async function syncRevokeControl(opts: {
  stateDir: string;
  now: () => number;
  nonce: () => string;
  policyHash: string;
  recordSigner: RecordSigner;
  inputsLog: InputsLog;
  decisions: () => Promise<SignedDecisionRecord[]>;
  memory: RevokeMemory;
  writer: LedgerWriter;
}): Promise<void> {
  const memory = opts.memory;
  if (revokeUnchanged(opts.stateDir, memory)) return;

  let stamp = fileStamp(opts.stateDir);
  let listed: Listed[] = [];
  for (let attempt = 0; attempt < 3; attempt += 1) {
    listed = readListed(opts.stateDir);
    const after = fileStamp(opts.stateDir);
    if (sameStamp(stamp, after)) break;
    stamp = after;
  }

  if (!memory.loaded) {
    memory.revoked = await replay(opts);
    memory.loaded = true;
  }

  try {
    const inFile = new Set<string>();
    for (const row of listed) {
      if (inFile.has(row.jti)) continue;
      inFile.add(row.jti);
      if (memory.revoked.has(row.jti)) continue;
      await writeRevoke(opts, {
        action: "revoke",
        jti: row.jti,
        by: row.by,
        via: row.via,
        atMs: row.atMs ?? opts.now(),
      });
      memory.revoked.add(row.jti);
    }
    for (const jti of [...memory.revoked]) {
      if (inFile.has(jti)) continue;
      await writeRevoke(opts, { action: "unrevoke", jti, by: "unknown", via: "file", atMs: opts.now() });
      memory.revoked.delete(jti);
    }
    memory.stamp = stamp;
  } catch (err) {
    // A partial append is already on disk. Replay the ledger next time rather
    // than trust a list that may be ahead of it or behind it.
    memory.loaded = false;
    throw err;
  }
}

function fileStamp(stateDir: string): Stamp {
  try {
    const st = statSync(join(stateDir, REVOKED));
    return { size: st.size, mtimeMs: st.mtimeMs };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function sameStamp(a: Stamp, b: Stamp): boolean {
  if (a === null || b === null) return a === b;
  return a.size === b.size && a.mtimeMs === b.mtimeMs;
}

/**
 * Lines that name no usable jti are skipped here. The body's own check reads
 * the same file and decides what such a line does to a token; this list only
 * records jtis it can name.
 */
function readListed(stateDir: string): Listed[] {
  let text: string;
  try {
    text = readFileSync(join(stateDir, REVOKED), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const out: Listed[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (line.trim() === "") continue;
    let row: { jti?: unknown; by?: unknown; atMs?: unknown };
    try {
      row = JSON.parse(line) as typeof row;
    } catch {
      continue;
    }
    if (!row || typeof row !== "object") continue;
    if (typeof row.jti !== "string" || row.jti === "" || row.jti.length > MAX_JTI) continue;
    const named = typeof row.by === "string" && row.by !== "" && row.by.length <= MAX_BY;
    const atMs = typeof row.atMs === "number" && Number.isFinite(row.atMs) ? row.atMs : null;
    out.push({ jti: row.jti, by: named ? (row.by as string) : "unknown", via: named ? "http" : "file", atMs });
  }
  return out;
}

async function replay(opts: {
  decisions: () => Promise<SignedDecisionRecord[]>;
  inputsLog: InputsLog;
}): Promise<Set<string>> {
  const revoked = new Set<string>();
  for (const decision of await opts.decisions()) {
    if (decision.claims.subject !== SUBJECT || decision.claims.effectClass !== CONTROL_EFFECT) continue;
    const ref = decision.claims.ref;
    if (typeof ref !== "string") continue;
    const row = (await opts.inputsLog.get(ref))?.revoke;
    if (!row || typeof row.jti !== "string") continue;
    if (row.action === "revoke") revoked.add(row.jti);
    else if (row.action === "unrevoke") revoked.delete(row.jti);
  }
  return revoked;
}

async function writeRevoke(
  opts: {
    nonce: () => string;
    policyHash: string;
    recordSigner: RecordSigner;
    inputsLog: InputsLog;
    writer: LedgerWriter;
  },
  revoke: RevokeInput,
): Promise<void> {
  const ref = opts.nonce();
  const inputs: DecisionInputs = {
    principal: { brain: "verax-proxy", scopes: [] },
    inputs: [],
    revoke,
  };
  const inputsHash = sha256Canonical(inputs);
  await opts.inputsLog.append(ref, inputs);
  await opts.writer.appendDecisionChained((prevRecordHash) =>
    signDecisionRecord(
      {
        decider: "verax-proxy",
        subject: SUBJECT,
        requestHash: sha256Canonical(revoke),
        policyHash: opts.policyHash,
        inputsHash,
        decision: "deny",
        reasonCode: revoke.action === "revoke" ? "token-revoked" : "revoke-removed",
        ref,
        effectHash: null,
        effectClass: CONTROL_EFFECT,
        timestampMs: revoke.atMs,
        nonce: ref,
        prevRecordHash,
      },
      opts.recordSigner.privateKeyPem,
      opts.recordSigner.publicKeyPem,
    ),
  );
}
