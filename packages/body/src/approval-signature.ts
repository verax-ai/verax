/**
 * An HTTP approval is bound to one defer record by a challenge the body and
 * `verax verify` both rebuild from that record. Nothing about that challenge
 * is remembered on the server.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { canonical, decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { listPieceFiles } from "@verax-ai/proxy";
import type { ApprovalSignature } from "@verax-ai/proxy";

import {
  credentialsPath,
  findCredential,
  hasRegisteredOperator,
  readCredentialsAt,
  updateCounter,
  type StoredCredential,
} from "./operator-credentials.ts";
import { readRpConfig } from "./rp-config.ts";
import { verifyAssertion } from "./webauthn-verify.ts";

export function approvalChallenge(input: {
  ref: string;
  requestHash: string;
  deferRecordHash: string;
}): string {
  const json = canonical({
    v: 1,
    purpose: "verax.approve",
    ref: input.ref,
    requestHash: input.requestHash,
    deferRecordHash: input.deferRecordHash,
  });
  return createHash("sha256").update(json).digest("base64url");
}

export type ApprovalGate =
  | { ok: true; signature?: ApprovalSignature }
  | {
      ok: false;
      status: 403 | 503;
      error:
        | "approve-signature-required"
        | "approve-signature-invalid"
        | "unknown-credential"
        | "cloned-authenticator"
        | "passkey-closed";
      reason?: string;
    };

type PostedAssertion = {
  id: string;
  rawId: string;
  type: "public-key";
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
  };
  clientExtensionResults: Record<string, unknown>;
};

function asAssertion(value: unknown): PostedAssertion | null {
  if (!value || typeof value !== "object") return null;
  const row = value as PostedAssertion;
  if (typeof row.id !== "string" || row.id === "" || row.rawId !== row.id) return null;
  if (row.type !== "public-key") return null;
  const response = row.response;
  if (!response || typeof response !== "object") return null;
  if (typeof response.clientDataJSON !== "string" || response.clientDataJSON === "") return null;
  if (typeof response.authenticatorData !== "string" || response.authenticatorData === "") return null;
  if (typeof response.signature !== "string" || response.signature === "") return null;
  if (row.clientExtensionResults === undefined) return { ...row, clientExtensionResults: {} };
  return row;
}

/**
 * When an operator is registered, the approval body must carry that
 * operator's assertion for this defer. No registered operator keeps today's
 * unsigned HTTP approval, and the signature is not written.
 */
export async function gateApprovalSignature(opts: {
  stateDir: string;
  env: NodeJS.ProcessEnv;
  assertion: unknown;
  ref: string;
  requestHash: string;
  deferRecordHash: string;
}): Promise<ApprovalGate> {
  if (!hasRegisteredOperator(opts.stateDir)) return { ok: true };
  const rp = readRpConfig(opts.env);
  if (!rp.ok) return { ok: false, status: 503, error: "passkey-closed", reason: rp.reason };
  if (opts.assertion === undefined || opts.assertion === null) {
    return { ok: false, status: 403, error: "approve-signature-required" };
  }
  const assertion = asAssertion(opts.assertion);
  if (!assertion) return { ok: false, status: 403, error: "approve-signature-invalid" };
  const stored = findCredential(opts.stateDir, assertion.id);
  if (!stored) return { ok: false, status: 403, error: "unknown-credential" };
  const expectedChallenge = approvalChallenge({
    ref: opts.ref,
    requestHash: opts.requestHash,
    deferRecordHash: opts.deferRecordHash,
  });
  const verified = verifyAssertion({
    response: assertion,
    expectedChallenge,
    expectedOrigins: rp.config.origins,
    rpId: rp.config.rpID,
    publicKeyCose: stored.publicKey,
  });
  if (!verified.ok) return { ok: false, status: 403, error: "approve-signature-invalid" };
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
      deferRecordHash: opts.deferRecordHash,
      rpId: rp.config.rpID,
    },
  };
}

export type ApprovalSignatureReport = {
  ok: boolean;
  signedVerified: number;
  signedFailed: number;
  unsignedHttp: number;
  cli: number;
  line: string;
  trustSource: "pinned" | "in-ledger" | "none";
  trustNote: string;
};

const PINNED_NOTE = "verified against a key the reader supplied, not one taken from these files";
const FILE_NOTE =
  "verified against the key carried in operator-credentials.json: this shows the files are internally consistent, not that the key was ever trusted. Pin a key you hold to check that.";
const NO_KEY_NOTE = "no operator key was found in these files";

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

type ApproverOnDisk = {
  via?: unknown;
  resolves?: unknown;
  signature?: unknown;
};

function signatureOf(value: unknown): ApprovalSignature | null {
  if (!value || typeof value !== "object") return null;
  const row = value as ApprovalSignature;
  if (typeof row.credentialId !== "string" || row.credentialId === "") return null;
  if (typeof row.sub !== "string" || row.sub === "") return null;
  if (typeof row.authenticatorData !== "string" || row.authenticatorData === "") return null;
  if (typeof row.clientDataJSON !== "string" || row.clientDataJSON === "") return null;
  if (typeof row.signature !== "string" || row.signature === "") return null;
  if (typeof row.deferRecordHash !== "string" || row.deferRecordHash === "") return null;
  if (typeof row.rpId !== "string" || row.rpId === "") return null;
  return row;
}

function originInClientData(clientDataJSON: string): string | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    const origin = (parsed as { origin?: unknown }).origin;
    return typeof origin === "string" && origin !== "" ? origin : null;
  } catch {
    return null;
  }
}

function originOnSignature(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const clientDataJSON = (value as { clientDataJSON?: unknown }).clientDataJSON;
  if (typeof clientDataJSON !== "string" || clientDataJSON === "") return null;
  return originInClientData(clientDataJSON);
}

function assertionMatches(sig: ApprovalSignature, publicKey: string, challenge: string): boolean {
  // The origin stays in clientDataJSON and is reported on the verify line.
  // This re-read does not judge it: the allow-list is not in these files, so
  // handing the claimed origin back is not an allow-list decision. rpIdHash
  // and the user-verification flag are still required.
  const origin = originInClientData(sig.clientDataJSON);
  if (!origin) return false;
  return verifyAssertion({
    response: {
      response: {
        clientDataJSON: sig.clientDataJSON,
        authenticatorData: sig.authenticatorData,
        signature: sig.signature,
      },
    },
    expectedChallenge: challenge,
    expectedOrigins: [origin],
    rpId: sig.rpId,
    publicKeyCose: publicKey,
  }).ok;
}

function trustOf(pinned: boolean, credentials: StoredCredential[]): Pick<ApprovalSignatureReport, "trustSource" | "trustNote"> {
  if (pinned) return { trustSource: "pinned", trustNote: PINNED_NOTE };
  if (credentials.length > 0) return { trustSource: "in-ledger", trustNote: FILE_NOTE };
  return { trustSource: "none", trustNote: NO_KEY_NOTE };
}

/**
 * Recount operator approvals without a body. A signature is checked against
 * the operator public key and the challenge rebuilt from the defer record.
 * The authenticator counter is not consulted: this is a re-read, not a second use.
 * `cli` and `cli-script` are both the unsigned CLI door.
 */
export async function verifyApprovalSignatures(
  stateDir: string,
  opts: { credentialsFile?: string } = {},
): Promise<ApprovalSignatureReport> {
  const pinned = typeof opts.credentialsFile === "string";
  const credentials = readCredentialsAt(pinned ? opts.credentialsFile! : credentialsPath(stateDir));
  const trust = trustOf(pinned, credentials);
  const decisions: SignedDecisionRecord[] = [];
  const approverByAllow = new Map<string, ApproverOnDisk>();
  for (const piece of listPieceFiles(stateDir)) {
    for (const line of readLines(piece.decisions)) {
      try {
        decisions.push(JSON.parse(line) as SignedDecisionRecord);
      } catch {
        // A line that does not parse is the ledger statement's problem.
      }
    }
    for (const line of readLines(piece.inputs)) {
      try {
        const row = JSON.parse(line) as { ref?: unknown; inputs?: { approver?: ApproverOnDisk } };
        if (typeof row.ref !== "string" || !row.inputs?.approver) continue;
        approverByAllow.set(row.ref, row.inputs.approver);
      } catch {
        // Same as a decision line: skip, do not invent a failure from a torn line.
      }
    }
  }

  let signedVerified = 0;
  let signedFailed = 0;
  let unsignedHttp = 0;
  let cli = 0;
  const origins: string[] = [];
  for (const row of decisions) {
    if (row.claims.decision !== "allow" || typeof row.claims.ref !== "string") continue;
    const approver = approverByAllow.get(row.claims.ref);
    if (!approver) continue;
    if (approver.signature === undefined) {
      if (approver.via === "http") unsignedHttp += 1;
      else if (approver.via === "cli" || approver.via === "cli-script") cli += 1;
      continue;
    }
    const seen = originOnSignature(approver.signature);
    if (seen && !origins.includes(seen)) origins.push(seen);
    const sig = signatureOf(approver.signature);
    const cred = sig ? credentials.find((c) => c.id === sig.credentialId && c.sub === sig.sub) : undefined;
    const defer =
      sig && typeof approver.resolves === "string"
        ? decisions.find((d) => d.claims.ref === approver.resolves && d.claims.decision === "defer")
        : undefined;
    let recordHash: string | null = null;
    if (defer) {
      try {
        recordHash = decisionRecordHash(defer);
      } catch {
        recordHash = null;
      }
    }
    const challenge =
      sig && defer && recordHash && recordHash === sig.deferRecordHash && typeof defer.claims.requestHash === "string"
        ? approvalChallenge({ ref: approver.resolves as string, requestHash: defer.claims.requestHash, deferRecordHash: recordHash })
        : null;
    if (sig && cred && challenge && assertionMatches(sig, cred.publicKey, challenge)) signedVerified += 1;
    else signedFailed += 1;
  }

  const originSuffix = origins.length === 0 ? "" : ` · origin ${origins.join(", ")}`;
  const report: ApprovalSignatureReport = {
    ok: signedFailed === 0,
    signedVerified,
    signedFailed,
    unsignedHttp,
    cli,
    line: `approval signatures  signed-verified ${signedVerified} · signed-failed ${signedFailed} · unsigned-http ${unsignedHttp} · cli ${cli}${originSuffix}`,
    trustSource: trust.trustSource,
    trustNote: trust.trustNote,
  };
  return report;
}
