/**
 * What an operator session may do over HTTP: stop and resume the body, and
 * approve a held call. The listener decides who is asking and hands that in;
 * nothing here reads a bearer.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { approvalsLogFor, approvePending, createApprovalBudgetGuard, loadApprovalsFromDir, terminalText } from "@verax-ai/proxy";

import { approvalChallenge, gateApprovalSignature } from "./approval-signature.ts";
import { gateControlSignature, nextControlChallenge } from "./control-signature.ts";
import { haltBody, readHalt, resumeBody } from "./halt.ts";
import { MAX_BODY_BYTES, readJsonBody, send } from "./http-io.ts";
import { loadOrCreateSigners } from "./keys.ts";
import { readCredentials } from "./operator-credentials.ts";
import { readRpConfig } from "./rp-config.ts";
import type { createBodyServices } from "./wiring.ts";

export type OperatorRequest = {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  stateDir: string;
  services: ReturnType<typeof createBodyServices>;
  /** The session's subject. It is written as who stopped, resumed or approved. */
  subject: string;
  scopes: ReadonlySet<string>;
  /** Answers for a session that died since it was let in, and says so. */
  refuseStale: () => Promise<boolean>;
  /** Where the passkey relying party is read from. */
  env: NodeJS.ProcessEnv;
};

async function signedDefer(
  ledger: { decisions(): Promise<SignedDecisionRecord[]> },
  ref: string,
): Promise<SignedDecisionRecord | null> {
  const rows = await ledger.decisions();
  return rows.find((row) => row.claims.ref === ref && row.claims.decision === "defer") ?? null;
}

/** `GET|POST halt`, `POST resume`, and the challenge for either. */
export async function handleControl(ctx: OperatorRequest, what: { resuming: boolean; challenge: boolean }): Promise<void> {
  const { req, res, stateDir, services, scopes } = ctx;
  const { resuming } = what;
  if (await ctx.refuseStale()) return;
  const operator = scopes.has("verax:audit") || scopes.has("verax:approve");
  // Stopping is the safe direction, so any operator session may do it.
  // Lifting a halt lets everything through again: that is an approval of
  // everything at once and needs the approve scope. The agent token
  // carries neither, so an agent cannot stop itself being stopped.
  if (!operator || (resuming && !scopes.has("verax:approve"))) {
    send(res, 403, { error: "scope-missing" });
    return;
  }
  if (what.challenge) {
    const rp = readRpConfig(ctx.env);
    if (!rp.ok) {
      send(res, 503, { error: "passkey-closed", reason: rp.reason });
      return;
    }
    send(res, 200, {
      ...nextControlChallenge(stateDir, resuming ? "resume" : "halt"),
      rpId: rp.config.rpID,
      allowCredentials: readCredentials(stateDir).map((row) => ({ id: row.id, type: "public-key" as const })),
    });
    return;
  }
  if (req.method === "GET") {
    send(res, 200, readHalt(stateDir));
    return;
  }
  const parsed = await readJsonBody(req, MAX_BODY_BYTES);
  if (await ctx.refuseStale()) return;
  if (!parsed.ok && resuming) {
    send(res, 400, { error: "bad-body" });
    return;
  }
  const asked = parsed.ok && parsed.value && typeof parsed.value === "object" ? parsed.value : {};
  // The tail is read inside the gate and the line is appended right
  // after it, with nothing awaited in between.
  const gated = gateControlSignature({
    stateDir,
    env: ctx.env,
    action: resuming ? "resume" : "halt",
    assertion: (asked as { assertion?: unknown }).assertion,
  });
  // A refused resume writes nothing. A halt is never refused for its
  // signature: it stops unsigned, and the answer says what was refused.
  if (!gated.ok && resuming) {
    send(res, gated.status, { error: gated.error, ...(gated.reason ? { reason: gated.reason } : {}) });
    return;
  }
  const signature = gated.ok ? gated.signature : undefined;
  const refused = !parsed.ok ? "bad-body" : gated.ok ? undefined : gated.error;
  const by = ctx.subject;
  const state = resuming
    ? resumeBody(stateDir, by, "http", Date.now(), signature)
    : {
        ...haltBody(stateDir, by, "http", Date.now(), signature),
        ...(refused ? { signatureRefused: refused } : {}),
      };
  try {
    await services.proxy.syncControlRecords();
  } catch (err) {
    // The switch is already on disk. A sync miss must not turn this into a 500.
    const message = (err instanceof Error ? err.message : String(err)).replace(/[\r\n]+/g, " ");
    process.stderr.write(`verax-proxy: control sync failed: ${terminalText(message)}\n`);
  }
  send(res, 200, state);
}

export async function handleApproveChallenge(ctx: OperatorRequest): Promise<void> {
  const { res, stateDir, services } = ctx;
  if (!ctx.scopes.has("verax:approve")) {
    send(res, 403, { error: "scope-missing" });
    return;
  }
  if (await ctx.refuseStale()) return;
  const ref = ctx.url.searchParams.get("ref") ?? "";
  const deferRecord = ref === "" ? null : await signedDefer(services.ledger, ref);
  if (!deferRecord) {
    send(res, 404, { error: "unknown-ref" });
    return;
  }
  const rp = readRpConfig(ctx.env);
  if (!rp.ok) {
    send(res, 503, { error: "passkey-closed", reason: rp.reason });
    return;
  }
  send(res, 200, {
    challenge: approvalChallenge({
      ref,
      requestHash: deferRecord.claims.requestHash,
      deferRecordHash: decisionRecordHash(deferRecord),
    }),
    rpId: rp.config.rpID,
    allowCredentials: readCredentials(stateDir).map((row) => ({ id: row.id, type: "public-key" as const })),
  });
}

export async function handleApprove(ctx: OperatorRequest): Promise<void> {
  const { req, res, stateDir, services } = ctx;
  // Reading the ledger is not approving from it. The audit scope opens
  // every door above; this one signs a new decision and lets money go,
  // so it has a scope of its own.
  if (!ctx.scopes.has("verax:approve")) {
    send(res, 403, { error: "scope-missing" });
    return;
  }
  const parsed = await readJsonBody(req, MAX_BODY_BYTES);
  if (await ctx.refuseStale()) return;
  if (!parsed.ok) {
    send(res, 400, { error: "bad-body" });
    return;
  }
  const asked = (parsed.value ?? {}) as { ref?: unknown; requestHash?: unknown; assertion?: unknown };
  const ref = typeof asked.ref === "string" ? asked.ref : "";
  const sawHash = typeof asked.requestHash === "string" ? asked.requestHash : "";
  if (ref === "" || sawHash === "") {
    send(res, 400, { error: "ref-and-requestHash-required" });
    return;
  }
  const waiting = loadApprovalsFromDir(stateDir).find((row) => row.ref === ref);
  if (!waiting) {
    send(res, 404, { error: "unknown-ref" });
    return;
  }
  // The list on a phone can be ten minutes old. An approval names the
  // request the operator was looking at, and if that is not what is
  // waiting any more, nothing is approved: "I approved what I saw" is
  // only true when something checks it.
  if (waiting.requestHash !== sawHash) {
    send(res, 409, { error: "stale", requestHash: waiting.requestHash });
    return;
  }
  const deferRecord = await signedDefer(services.ledger, ref);
  if (!deferRecord) {
    send(res, 404, { error: "unknown-ref" });
    return;
  }
  const deferRecordHash = decisionRecordHash(deferRecord);
  // The challenge is rebuilt from the defer on disk, not from anything the client sent.
  const gated = await gateApprovalSignature({
    stateDir,
    env: ctx.env,
    assertion: asked.assertion,
    ref,
    requestHash: deferRecord.claims.requestHash,
    deferRecordHash,
  });
  if (!gated.ok) {
    send(res, gated.status, {
      error: gated.error,
      ...(gated.reason ? { reason: gated.reason } : {}),
    });
    return;
  }
  // Who approved, on the record. The CLI writes the machine's login name,
  // which says nothing about the person holding the phone; the session's
  // own subject does.
  const approver = ctx.subject;
  const approvals = approvalsLogFor(services.ledger);
  const outcome = await approvePending({
    ledger: services.ledger,
    recordSigner: loadOrCreateSigners(stateDir).recordSigner,
    now: () => Date.now(),
    nonce: () => crypto.randomUUID(),
    ref,
    approverId: approver,
    via: "http",
    policyHash: deferRecord.claims.policyHash,
    ...(gated.signature ? { signature: gated.signature } : {}),
    approvals,
    budgetGuard: createApprovalBudgetGuard({
      policy: services.policy,
      approvals,
      now: () => Date.now(),
      ledger: services.ledger,
    }),
  });
  if (!outcome.ok) {
    if (outcome.reason === "halted") {
      send(res, 409, { error: "approve-halted" });
      return;
    }
    const code = outcome.reason === "unknown-ref" || outcome.reason === "snapshot-missing" ? 404 : 409;
    send(res, code, {
      error: outcome.reason,
      ...(outcome.allowRef ? { allowRef: outcome.allowRef } : {}),
    });
    return;
  }
  send(res, 200, { allowRef: outcome.allowRef, approver });
}
