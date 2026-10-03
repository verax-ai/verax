/**
 * A halt or resume over HTTP can carry the operator's passkey assertion. The
 * challenge names the action and the newest line of `halt-history.jsonl`, so
 * one assertion fits the one line appended after that tail and no later one.
 * The body rebuilds it from the file when the request arrives; `verax verify`
 * rebuilds it from the previous control record. Nothing is remembered.
 *
 * A resume lets every held call through again, so once an operator is
 * registered a resume over HTTP must be signed. A halt is never made to wait
 * for a passkey: it may carry one, and one that is offered must verify.
 */
import { createHash } from "node:crypto";

import { canonical, type SignedDecisionRecord } from "@cedulon/core";
import { listPieceFiles } from "@verax-ai/proxy";
import type { ControlSignature } from "@verax-ai/proxy";

import { asAssertion, assertionMatches, readLines, trustOf } from "./approval-signature.ts";
import { historyTail } from "./halt.ts";
import {
  credentialsPath,
  findCredential,
  hasRegisteredOperator,
  readCredentialsAt,
  updateCounter,
} from "./operator-credentials.ts";
import { readRpConfig } from "./rp-config.ts";
import { verifyAssertion } from "./webauthn-verify.ts";

export type ControlAction = "halt" | "resume";

export function controlChallenge(input: { action: ControlAction; prev: string | null }): string {
  const json = canonical({ v: 1, purpose: `verax.${input.action}`, prev: input.prev });
  return createHash("sha256").update(json).digest("base64url");
}

/** The challenge for the next line, from the history as it is now. */
export function nextControlChallenge(stateDir: string, action: ControlAction): { challenge: string; prev: string | null } {
  const prev = historyTail(stateDir);
  return { challenge: controlChallenge({ action, prev }), prev };
}

export type ControlGate =
  | { ok: true; signature?: ControlSignature }
  | {
      ok: false;
      status: 403 | 503;
      error:
        | "resume-signature-required"
        | "control-signature-invalid"
        | "unknown-credential"
        | "cloned-authenticator"
        | "passkey-closed";
      reason?: string;
    };

/**
 * Synchronous on purpose: the server reads the tail here and appends the line
 * right after, with nothing awaited in between, so no other request of this
 * body can append a line the assertion was not made for.
 */
export function gateControlSignature(opts: {
  stateDir: string;
  env: NodeJS.ProcessEnv;
  action: ControlAction;
  assertion: unknown;
}): ControlGate {
  if (opts.assertion === undefined || opts.assertion === null) {
    if (opts.action === "resume" && hasRegisteredOperator(opts.stateDir)) {
      return { ok: false, status: 403, error: "resume-signature-required" };
    }
    return { ok: true };
  }
  const rp = readRpConfig(opts.env);
  if (!rp.ok) return { ok: false, status: 503, error: "passkey-closed", reason: rp.reason };
  const assertion = asAssertion(opts.assertion);
  if (!assertion) return { ok: false, status: 403, error: "control-signature-invalid" };
  const stored = findCredential(opts.stateDir, assertion.id);
  if (!stored) return { ok: false, status: 403, error: "unknown-credential" };
  const { challenge, prev } = nextControlChallenge(opts.stateDir, opts.action);
  const verified = verifyAssertion({
    response: assertion,
    expectedChallenge: challenge,
    expectedOrigins: rp.config.origins,
    rpId: rp.config.rpID,
    publicKeyCose: stored.publicKey,
  });
  if (!verified.ok) return { ok: false, status: 403, error: "control-signature-invalid" };
  if (!updateCounter(opts.stateDir, stored.id, verified.counter)) {
    return { ok: false, status: 403, error: "cloned-authenticator" };
  }
  return {
    ok: true,
    signature: {
      credentialId: stored.id,
      sub: stored.sub,
      authenticatorData: assertion.response.authenticatorData,
      clientDataJSON: assertion.response.clientDataJSON,
      signature: assertion.response.signature,
      rpId: rp.config.rpID,
      prev,
    },
  };
}

export type ControlSignatureReport = {
  ok: boolean;
  signedVerified: number;
  signedFailed: number;
  unsignedHttp: number;
  cli: number;
  file: number;
  line: string;
  trustSource: "pinned" | "in-ledger" | "none";
  trustNote: string;
};

type ControlOnDisk = {
  action?: unknown;
  via?: unknown;
  line?: unknown;
  lineHash?: unknown;
  signature?: unknown;
};

function controlSignatureOf(value: unknown): ControlSignature | null {
  if (!value || typeof value !== "object") return null;
  const row = value as ControlSignature;
  for (const field of ["credentialId", "sub", "authenticatorData", "clientDataJSON", "signature", "rpId"] as const) {
    if (typeof row[field] !== "string" || row[field] === "") return null;
  }
  if (row.prev !== null && (typeof row.prev !== "string" || row.prev === "")) return null;
  return row;
}

/**
 * Recount halt and resume signatures without a body. A signature must name,
 * as `prev`, the line hash of the control record copied from the history line
 * just before its own (`null` for line 0), and verify under the operator key
 * over the challenge rebuilt from that and the record's subject. A challenge
 * counts once. The authenticator counter is not consulted.
 */
export async function verifyControlSignatures(
  stateDir: string,
  opts: { credentialsFile?: string } = {},
): Promise<ControlSignatureReport> {
  const pinned = typeof opts.credentialsFile === "string";
  const credentials = readCredentialsAt(pinned ? opts.credentialsFile! : credentialsPath(stateDir));
  const trust = trustOf(pinned, credentials);
  const decisions: SignedDecisionRecord[] = [];
  const inputsByRef = new Map<string, Map<string, ControlOnDisk | null>>();
  for (const piece of listPieceFiles(stateDir)) {
    for (const line of readLines(piece.decisions)) {
      try {
        decisions.push(JSON.parse(line) as SignedDecisionRecord);
      } catch {
        // The ledger statement names a line that does not parse.
      }
    }
    for (const line of readLines(piece.inputs)) {
      try {
        const row = JSON.parse(line) as { ref?: unknown; inputs?: { control?: ControlOnDisk } };
        if (typeof row.ref !== "string" || row.inputs === undefined) continue;
        const hash = createHash("sha256").update(canonical(row.inputs), "utf8").digest("hex");
        const byHash = inputsByRef.get(row.ref) ?? new Map<string, ControlOnDisk | null>();
        byHash.set(hash, row.inputs?.control ?? null);
        inputsByRef.set(row.ref, byHash);
      } catch {
        // Same as a decision line.
      }
    }
  }

  let signedVerified = 0;
  let signedFailed = 0;
  let unsignedHttp = 0;
  let cli = 0;
  let file = 0;
  const lineHashByLine = new Map<number, string>();
  const used = new Set<string>();
  for (const row of decisions) {
    if (!row || typeof row !== "object" || !row.claims || typeof row.claims !== "object") continue;
    const claims = row.claims;
    if (claims.effectClass !== "verax.control" || claims.decision !== "allow") continue;
    if (claims.subject !== "verax.halt" && claims.subject !== "verax.resume") continue;
    if (typeof claims.ref !== "string" || typeof claims.inputsHash !== "string") continue;
    const control = inputsByRef.get(claims.ref)?.get(claims.inputsHash);
    if (!control) continue;
    const at = typeof control.line === "number" && Number.isInteger(control.line) ? control.line : -1;

    if (control.signature === undefined) {
      if (control.via === "http") unsignedHttp += 1;
      else if (control.via === "cli") cli += 1;
      else file += 1;
    } else {
      const sig = controlSignatureOf(control.signature);
      const expectedPrev = at === 0 ? null : at > 0 ? lineHashByLine.get(at - 1) : undefined;
      const action: ControlAction = claims.subject === "verax.halt" ? "halt" : "resume";
      const challenge =
        sig && expectedPrev !== undefined && sig.prev === expectedPrev
          ? controlChallenge({ action, prev: expectedPrev })
          : null;
      const firstUse = challenge !== null && !used.has(challenge);
      if (challenge !== null) used.add(challenge);
      const cred = sig ? credentials.find((c) => c.id === sig.credentialId && c.sub === sig.sub) : undefined;
      if (sig && cred && challenge && firstUse && assertionMatches(sig, cred.publicKey, challenge)) signedVerified += 1;
      else signedFailed += 1;
    }
    if (at >= 0 && typeof control.lineHash === "string") lineHashByLine.set(at, control.lineHash);
  }

  return {
    ok: signedFailed === 0,
    signedVerified,
    signedFailed,
    unsignedHttp,
    cli,
    file,
    line: `control signatures   signed-verified ${signedVerified} · signed-failed ${signedFailed} · unsigned-http ${unsignedHttp} · cli ${cli} · file ${file}`,
    trustSource: trust.trustSource,
    trustNote: trust.trustNote,
  };
}
