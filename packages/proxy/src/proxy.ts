import { existsSync } from "node:fs";
import { join } from "node:path";
import { signDecisionRecord } from "@cedulon/core";
import type { DecisionKind } from "@cedulon/core";
import type { EffectRow } from "@cedulon/effect-extract";
import {
  approvePending,
  approvalsLogFor,
  createApprovalBudgetGuard,
  drainApprovalCommands,
  spentTodayMinorOf,
} from "./approvals.ts";
import { SerialQueue } from "./serial-queue.ts";
import { diskProbe } from "./disk.ts";
import { markEnded, markStarted, startedWithoutEnd } from "./in-flight-log.ts";
import { effectDescriptor, sha256Canonical } from "./hash.ts";
import { inputsLogFor } from "./inputs.ts";
import {
  countedWork,
  hasPrimaryEffect,
  lookupDecisionByRef,
  lookupReauthByHash,
  lookupResolvedBy,
  noteResolution,
  noteTenantRef,
} from "./ledger.ts";
import { spokenReason } from "./spoken-reason.ts";
import { tenantKey } from "./tenant.ts";
import type { DecisionInputRow, DecisionInputs, Principal, ProxyDeps, ToolCall, ToolResult } from "./types.ts";

function scopedClaimsRef(principal: Principal, raw: string): string {
  if (principal.iss || principal.tenant || principal.org) {
    return `${tenantKey(principal)}:${raw}`;
  }
  return raw;
}

function principalInputs(principal: Principal): DecisionInputs["principal"] {
  return {
    brain: principal.brain,
    scopes: [...principal.scopes].sort(),
    ...(principal.iss ? { iss: principal.iss } : {}),
    ...(principal.tenant ? { tenant: principal.tenant } : {}),
    ...(principal.org ? { org: principal.org } : {}),
  };
}

export class LedgerDenyUnrecorded extends Error {
  readonly reasonCode: string;
  constructor(reasonCode: string, cause?: unknown) {
    super(`ledger-deny-unrecorded:${reasonCode}`);
    this.name = "LedgerDenyUnrecorded";
    this.reasonCode = reasonCode;
    if (cause !== undefined) this.cause = cause;
  }
}

export const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function denied(reasonCode: string, ref: string, call?: ToolCall): ToolResult {
  const spoken = spokenReason(reasonCode);
  if (spoken !== reasonCode) {
    const payload: Record<string, unknown> = { error: spoken };
    if (call && typeof call.arguments.id === "string") {
      payload.id = call.arguments.id;
    }
    return {
      content: [{ type: "text", text: JSON.stringify(payload) }],
      isError: true,
    };
  }
  return {
    content: [{ type: "text", text: `denied:${reasonCode}:${ref}` }],
    isError: true,
  };
}

function deferred(ref: string): ToolResult {
  return {
    content: [{ type: "text", text: `deferred:approval-required:${ref}` }],
    isError: true,
  };
}

function allowedReplay(ref: string): ToolResult {
  return {
    content: [{ type: "text", text: `allowed:${ref}` }],
    isError: false,
  };
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value as object)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
  }
  return value;
}

function thrownPayload(err: unknown): unknown {
  if (err instanceof Error) {
    return { name: err.name, message: err.message };
  }
  return { name: "thrown" };
}

function declaredInputs(
  args: Record<string, unknown>,
): { id: string; versionHash: string; source?: Record<string, unknown> }[] | "invalid" | null {
  if (!Object.prototype.hasOwnProperty.call(args, "_inputs")) return null;
  const raw = args._inputs;
  if (!Array.isArray(raw)) return "invalid";
  const out: { id: string; versionHash: string; source?: Record<string, unknown> }[] = [];
  for (const item of raw) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) return "invalid";
    const rec = item as Record<string, unknown>;
    if (typeof rec.id !== "string" || rec.id === "" || typeof rec.versionHash !== "string" || rec.versionHash === "") {
      return "invalid";
    }
    const row: { id: string; versionHash: string; source?: Record<string, unknown> } = {
      id: rec.id,
      versionHash: rec.versionHash,
    };
    if (rec.source !== undefined) {
      if (rec.source === null || typeof rec.source !== "object" || Array.isArray(rec.source)) {
        return "invalid";
      }
      row.source = rec.source as Record<string, unknown>;
    }
    out.push(row);
  }
  return out;
}

function readRef(args: Record<string, unknown>): string | "invalid" | null {
  if (!Object.prototype.hasOwnProperty.call(args, "_ref")) return null;
  const raw = args._ref;
  if (typeof raw !== "string" || !REF_RE.test(raw)) return "invalid";
  return raw;
}

function toolCallOf(call: ToolCall): ToolCall {
  const args = { ...call.arguments };
  delete args._inputs;
  delete args._ref;
  return { name: call.name, arguments: args };
}

export function createProxy(deps: ProxyDeps) {
  const inputsLog = deps.inputsLog ?? inputsLogFor(deps.ledger);
  const approvals = approvalsLogFor(deps.ledger);
  const admission = new SerialQueue();
  const inFlight = new Map<string, Promise<ToolResult>>();
  const budgetGuard = createApprovalBudgetGuard({
    policy: deps.policy,
    approvals,
    now: deps.now,
  });
  (deps.ledger as { effectSigner?: ProxyDeps["effectSigner"] }).effectSigner = deps.effectSigner;
  const ledgerDir = (deps.ledger as unknown as { dir?: unknown }).dir;
  const stateDir = typeof ledgerDir === "string" ? ledgerDir : null;
  if (stateDir === null) {
    process.stderr.write("verax-proxy: halt and disk limits are inactive without a ledger directory\n");
  }

  async function writeRecord(opts: {
    decision: DecisionKind;
    reasonCode: string;
    ref: string;
    requestHash: string;
    inputs: DecisionInputs;
    effectHash: string | null;
    subject: string;
    timestampMs: number;
    decider?: string;
  }): Promise<void> {
    const inputsHash = sha256Canonical(opts.inputs);
    await inputsLog.append(opts.ref, opts.inputs);
    await deps.ledger.appendDecisionChained((prevRecordHash) =>
      signDecisionRecord(
        {
          decider: opts.decider ?? "verax-proxy",
          subject: opts.subject,
          requestHash: opts.requestHash,
          policyHash: deps.policy.hash,
          inputsHash,
          decision: opts.decision,
          reasonCode: opts.reasonCode,
          ref: opts.ref,
          effectHash: opts.effectHash,
          // The class of effect this decision names, in this channel's own
          // vocabulary: the call it decided about. An allow must carry one, and
          // a refusal names what it refused, so the audit can hold a decision
          // and an effect row to the same word.
          effectClass: opts.subject,
          timestampMs: opts.timestampMs,
          nonce: opts.ref,
          prevRecordHash,
        },
        deps.recordSigner.privateKeyPem,
        deps.recordSigner.publicKeyPem,
      ),
    );
    if (opts.inputs.approver?.resolves) {
      const kind =
        opts.reasonCode === "expired" ? "expired" : opts.decision === "allow" ? "allow" : null;
      if (kind) noteResolution(deps.ledger, opts.inputs.approver.resolves, { ref: opts.ref, kind });
    }
  }

  async function writeRecordOrUnrecorded(opts: Parameters<typeof writeRecord>[0]): Promise<void> {
    if (diskProbe.failAppend) {
      throw new LedgerDenyUnrecorded("ledger-disk-low");
    }
    try {
      await writeRecord(opts);
    } catch (err) {
      if (opts.reasonCode === "ledger-disk-low") {
        throw new LedgerDenyUnrecorded("ledger-disk-low", err);
      }
      throw err;
    }
  }

  function rateBound(timestampMs: number, wouldCount: boolean): string | null {
    if (!wouldCount) return null;
    const limits = deps.policy.limits;
    if (limits.ratePerMinute === undefined && limits.dailyMax === undefined) return null;
    const counts = countedWork(deps.ledger, timestampMs);
    if (!counts.ok) return "rate-limited";
    if (limits.ratePerMinute !== undefined && counts.minute >= limits.ratePerMinute) return "rate-limited";
    if (limits.dailyMax !== undefined && counts.day >= limits.dailyMax) return "daily-limited";
    return null;
  }

  async function spendReauth(
    requestHash: string,
    inputs: DecisionInputs,
    timestampMs: number,
    subject: string,
  ): Promise<ToolResult> {
    const existingReauth = await lookupReauthByHash(deps.ledger, requestHash);
    if (existingReauth) return denied("spend-reauth-required", existingReauth);
    const ref = deps.nonce();
    await writeRecord({
      decision: "deny",
      reasonCode: "spend-reauth-required",
      ref,
      requestHash,
      inputs,
      effectHash: null,
      subject,
      timestampMs,
    });
    return denied("spend-reauth-required", ref);
  }

  async function runInner(call: ToolCall, principal: Principal, ref: string): Promise<ToolResult> {
    const dispatchedName = call.name;
    const dispatchedArgs = deepFreeze(structuredClone(call.arguments));
    const dispatchedHash = sha256Canonical(effectDescriptor(dispatchedName, dispatchedArgs));
    const thrownHash = sha256Canonical(effectDescriptor(dispatchedName, dispatchedArgs, true));
    const frozenCall: ToolCall = Object.freeze({
      name: dispatchedName,
      arguments: dispatchedArgs,
    });
    try {
      const result = await deps.inner(frozenCall, principal, ref);
      const row: EffectRow = {
        ref,
        effectHash: dispatchedHash,
        effectClass: dispatchedName,
        timestampMs: deps.now(),
        actor: principal.brain,
      };
      await deps.ledger.appendEffect(row, "self", sha256Canonical(result));
      return result;
    } catch (err) {
      const row: EffectRow = {
        ref,
        effectHash: thrownHash,
        effectClass: `${dispatchedName}:threw`,
        timestampMs: deps.now(),
        actor: principal.brain,
      };
      await deps.ledger.appendEffect(row, "self", sha256Canonical(thrownPayload(err)));
      throw err;
    }
  }

  async function resolveInputs(
    call: ToolCall,
    principal: Principal,
    timestampMs: number,
  ): Promise<{ inputs: DecisionInputs; reasonCode: string | null }> {
    const declared = declaredInputs(call.arguments);
    if (declared === "invalid") {
      return {
        inputs: { principal: principalInputs(principal), inputs: [] },
        reasonCode: "input-invalid",
      };
    }
    if (declared === null && deps.policy.requireInputs === true) {
      return {
        inputs: { principal: principalInputs(principal), inputs: [] },
        reasonCode: "inputs-required",
      };
    }
    const rows: DecisionInputRow[] = [];
    if (declared) {
      for (const item of declared) {
        const got = deps.resolveInput ? await deps.resolveInput(item.id, principal) : null;
        if (
          !got ||
          got.versionHash !== item.versionHash ||
          got.validFromMs > timestampMs ||
          got.validUntilMs < timestampMs
        ) {
          return {
            inputs: { principal: principalInputs(principal), inputs: [] },
            reasonCode: "input-invalid",
          };
        }
        const row: DecisionInputRow = {
          id: item.id,
          versionHash: item.versionHash,
          validFromMs: got.validFromMs,
          validUntilMs: got.validUntilMs,
        };
        if (item.source) row.source = item.source;
        rows.push(row);
      }
    }
    return {
      inputs: { principal: principalInputs(principal), inputs: rows },
      reasonCode: null,
    };
  }

  type AdmissionPlan =
    | { kind: "done"; result: ToolResult }
    | { kind: "run"; work: Promise<ToolResult>; key: string; replayRef: string }
    | { kind: "wait"; work: Promise<ToolResult>; replayRef: string };

  function launchInner(
    dispatchedCall: ToolCall,
    principal: Principal,
    allowRef: string,
    flightKey: string,
  ): AdmissionPlan {
    // Written before the tool runs, removed after the effect is recorded. A
    // mark that survives the process is what tells a restarted body that this
    // ref was already started (in-flight-log.ts).
    if (stateDir !== null) markStarted(stateDir, flightKey, dispatchedCall.name);
    const work = runInner(dispatchedCall, principal, allowRef);
    inFlight.set(flightKey, work);
    return { kind: "run", work, key: flightKey, replayRef: allowRef };
  }

  async function retryPolicyDeny(
    dispatchedCall: ToolCall,
    principal: Principal,
    requestHash: string,
    inputs: DecisionInputs,
    timestampMs: number,
    subject: string,
    scopedRef: string,
  ): Promise<ToolResult | null> {
    let spendCtx: { spentTodayMinor: (currency: string) => number } | undefined;
    if (dispatchedCall.name === "spend") {
      const approvalRows = await approvals.listAll();
      spendCtx = {
        spentTodayMinor: (currency) =>
          spentTodayMinorOf(approvalRows, timestampMs, currency, deps.policy.approvalTtlMs),
      };
    }
    const verdict = deps.policy.evaluate(dispatchedCall, principal, spendCtx);
    if (verdict.decision !== "deny") return null;
    const denyRef = deps.nonce();
    await writeRecord({
      decision: "deny",
      reasonCode: verdict.reasonCode,
      ref: denyRef,
      requestHash,
      inputs: {
        ...inputs,
        approver: { id: "verax-proxy", via: "proxy", resolves: scopedRef },
      },
      effectHash: null,
      subject,
      timestampMs,
    });
    return denied(verdict.reasonCode, denyRef);
  }

  return {
    approvals,
    inputsLog,
    async call(call: ToolCall, principal: Principal): Promise<ToolResult> {
      if (stateDir) {
        await drainApprovalCommands(stateDir, async (cmd) => {
          const defer = await lookupDecisionByRef(deps.ledger, cmd.ref);
          if (!defer || defer.decision !== "defer") return;
          await approvePending({
            ledger: deps.ledger,
            recordSigner: deps.recordSigner,
            now: deps.now,
            nonce: deps.nonce,
            ref: cmd.ref,
            approverId: cmd.approverId,
            // Only `verax approve` queues a command, when the ledger is locked.
            via: "cli",
            policyHash: defer.policyHash,
            approvals,
            inputsLog,
            budgetGuard,
          });
        });
      }
      const dispatched = toolCallOf(call);
      const requestHash = sha256Canonical(dispatched);
      const timestampMs = deps.now();
      const resolved = await resolveInputs(call, principal, timestampMs);
      if (stateDir && existsSync(join(stateDir, "halted"))) {
        const ref = deps.nonce();
        await writeRecord({
          decision: "deny",
          reasonCode: "halted",
          ref,
          requestHash,
          inputs: resolved.inputs,
          effectHash: null,
          subject: call.name,
          timestampMs,
        });
        return denied("halted", ref);
      }
      if (stateDir && diskProbe.freeBytes(stateDir) < deps.policy.limits.diskFreeBytes) {
        const ref = deps.nonce();
        await writeRecordOrUnrecorded({
          decision: "deny",
          reasonCode: "ledger-disk-low",
          ref,
          requestHash,
          inputs: resolved.inputs,
          effectHash: null,
          subject: call.name,
          timestampMs,
        });
        return denied("ledger-disk-low", ref);
      }
      const given = readRef(call.arguments);

      const plan = await admission.enqueue(async (): Promise<AdmissionPlan> => {
        if (given === "invalid") {
          const ref = deps.nonce();
          await writeRecord({
            decision: "deny",
            reasonCode: "ref-invalid",
            ref,
            requestHash,
            inputs: resolved.inputs,
            effectHash: null,
            subject: call.name,
            timestampMs,
          });
          return { kind: "done", result: denied("ref-invalid", ref) };
        }

        if (typeof given === "string") {
          // The ledger, the approvals snapshot and the resolution index all key on the
          // scoped ref. The brain only ever sees and resends the raw `_ref` it chose.
          const scopedRef = scopedClaimsRef(principal, given);
          const existing = await lookupDecisionByRef(deps.ledger, given, tenantKey(principal));
          if (existing) {
            if (existing.requestHash !== requestHash) {
              const ref = deps.nonce();
              await writeRecord({
                decision: "deny",
                reasonCode: "ref-reuse",
                ref,
                requestHash,
                inputs: resolved.inputs,
                effectHash: null,
                subject: call.name,
                timestampMs,
              });
              return { kind: "done", result: denied("ref-reuse", ref) };
            }
            if (existing.decision === "defer") {
              const snap = await approvals.get(scopedRef);
              const boundHit = lookupResolvedBy(deps.ledger, scopedRef);
              if (boundHit?.kind === "expired") {
                if (snap?.status === "pending") await approvals.updateStatus(scopedRef, "expired");
                return { kind: "done", result: denied("expired", boundHit.ref) };
              }
              if (snap && timestampMs > snap.expiresAtMs) {
                const expireRef = deps.nonce();
                await writeRecord({
                  decision: "deny",
                  reasonCode: "expired",
                  ref: expireRef,
                  requestHash,
                  inputs: {
                    ...resolved.inputs,
                    approver: { id: "verax-proxy", via: "proxy", resolves: scopedRef },
                  },
                  effectHash: null,
                  subject: call.name,
                  timestampMs,
                });
                await approvals.updateStatus(scopedRef, "expired");
                return { kind: "done", result: denied("expired", expireRef) };
              }
              const allowRef = snap?.allowRef ?? (boundHit?.kind === "allow" ? boundHit.ref : undefined);
              const allow = allowRef ? await lookupDecisionByRef(deps.ledger, allowRef) : null;
              if (allow?.ref && allow.decision === "allow" && allow.reasonCode === "approved-by-operator") {
                const bound = await inputsLog.get(allow.ref);
                if (bound?.approver?.resolves && bound.approver.resolves !== scopedRef) {
                  return { kind: "done", result: deferred(given) };
                }
                if (!snap?.allowRef) {
                  await approvals.updateStatus(scopedRef, "approved", { allowRef: allow.ref });
                }
                if (await hasPrimaryEffect(deps.ledger, allow.ref)) {
                  return { kind: "done", result: allowedReplay(allow.ref) };
                }
                if (allow.subject === "spend") {
                  return {
                    kind: "done",
                    result: await spendReauth(requestHash, resolved.inputs, timestampMs, call.name),
                  };
                }
                const policyDeny = await retryPolicyDeny(
                  dispatched,
                  principal,
                  requestHash,
                  resolved.inputs,
                  timestampMs,
                  call.name,
                  scopedRef,
                );
                if (policyDeny) return { kind: "done", result: policyDeny };
                const flying = inFlight.get(scopedRef);
                if (flying) return { kind: "wait", work: flying, replayRef: allow.ref };
                // An approved allow means "the operator said yes", not "it ran",
                // so the first retry after an approval is the first run. Only a
                // mark left on disk says a run was already started and never
                // finished — that one cannot be run again.
                if (stateDir !== null && startedWithoutEnd(stateDir, scopedRef)) {
                  const unknownRef = deps.nonce();
                  await writeRecord({
                    decision: "deny",
                    reasonCode: "outcome-unknown",
                    ref: unknownRef,
                    requestHash,
                    inputs: {
                      ...resolved.inputs,
                      approver: { id: "verax-proxy", via: "proxy", resolves: scopedRef },
                    },
                    effectHash: null,
                    subject: call.name,
                    timestampMs,
                  });
                  return { kind: "done", result: denied("outcome-unknown", unknownRef) };
                }
                return launchInner(dispatched, principal, allow.ref, scopedRef);
              }
              return { kind: "done", result: deferred(given) };
            }
            if (existing.decision === "deny") {
              return { kind: "done", result: denied(existing.reasonCode, given, call) };
            }
            if (existing.decision === "allow" && existing.ref) {
              if (await hasPrimaryEffect(deps.ledger, existing.ref)) {
                return { kind: "done", result: allowedReplay(existing.ref) };
              }
              if (existing.subject === "spend") {
                return {
                  kind: "done",
                  result: await spendReauth(requestHash, resolved.inputs, timestampMs, call.name),
                };
              }
              const policyDeny = await retryPolicyDeny(
                dispatched,
                principal,
                requestHash,
                resolved.inputs,
                timestampMs,
                call.name,
                scopedRef,
              );
              if (policyDeny) return { kind: "done", result: policyDeny };
              const flying = inFlight.get(scopedRef);
              if (flying) return { kind: "wait", work: flying, replayRef: existing.ref };
              const denyRef = deps.nonce();
              await writeRecord({
                decision: "deny",
                reasonCode: "outcome-unknown",
                ref: denyRef,
                requestHash,
                inputs: {
                  ...resolved.inputs,
                  approver: { id: "verax-proxy", via: "proxy", resolves: scopedRef },
                },
                effectHash: null,
                subject: call.name,
                timestampMs,
              });
              return { kind: "done", result: denied("outcome-unknown", denyRef) };
            }
          }
        }

        let spendCtx: { spentTodayMinor: (currency: string) => number } | undefined;
        if (dispatched.name === "spend") {
          const approvalRows = await approvals.listAll();
          spendCtx = {
            spentTodayMinor: (currency) =>
              spentTodayMinorOf(approvalRows, timestampMs, currency, deps.policy.approvalTtlMs),
          };
        }
        const verdict = deps.policy.evaluate(dispatched, principal, spendCtx);
        let reasonCode = resolved.reasonCode ?? verdict.reasonCode;
        let decision = resolved.reasonCode ? ("deny" as const) : verdict.decision;
        const bound = rateBound(timestampMs, decision === "allow" || decision === "defer");
        if (bound) {
          decision = "deny";
          reasonCode = bound;
        }
        if (
          !bound &&
          decision === "allow" &&
          deps.checkTenantMismatch &&
          (await deps.checkTenantMismatch(dispatched, principal))
        ) {
          decision = "deny";
          reasonCode = "tenant-mismatch";
        }
        const ref = typeof given === "string" ? scopedClaimsRef(principal, given) : deps.nonce();
        // What the brain is told: its own `_ref`, so a retry carries the same key back.
        const shown = typeof given === "string" ? given : ref;
        const allow = decision === "allow";
        await writeRecord({
          decision,
          reasonCode,
          ref,
          requestHash,
          inputs: resolved.inputs,
          effectHash: allow ? sha256Canonical(effectDescriptor(dispatched.name, dispatched.arguments)) : null,
          subject: call.name,
          timestampMs,
        });
        if (typeof given === "string") {
          noteTenantRef(deps.ledger, tenantKey(principal), given);
        }
        if (decision === "defer") {
          const rule = deps.policy.rule(verdict.rule);
          const amount = dispatched.name === "spend" ? dispatched.arguments.amountMinor : dispatched.arguments.amount;
          const payee = dispatched.arguments.payee;
          const currency = dispatched.arguments.currency;
          await approvals.append({
            ref,
            requestHash,
            subject: dispatched.name,
            args: dispatched.arguments,
            ruleId: verdict.rule,
            ruleText: rule?.text ?? null,
            inputsSummary: {
              count: resolved.inputs.inputs.length,
              ids: resolved.inputs.inputs.map((i) => i.id),
            },
            ...(amount !== undefined ? { amount } : {}),
            ...(payee !== undefined ? { payee } : {}),
            ...(currency !== undefined ? { currency } : {}),
            createdAtMs: timestampMs,
            expiresAtMs: timestampMs + deps.policy.approvalTtlMs,
            status: "pending",
            brain: principal.brain,
          });
          return { kind: "done", result: deferred(shown) };
        }
        if (!allow) {
          return { kind: "done", result: denied(reasonCode, shown, call) };
        }
        return launchInner(dispatched, principal, ref, ref);
      });

      if (plan.kind === "done") return plan.result;
      if (plan.kind === "wait") {
        try {
          await plan.work;
        } catch {
          // The first call recorded the throw on its effect row.
        }
        return allowedReplay(plan.replayRef);
      }
      try {
        return await plan.work;
      } finally {
        inFlight.delete(plan.key);
        // runInner has written its effect row by now — on the throw path too,
        // as `<name>:threw`. The outcome is on the ledger, so the mark goes.
        if (stateDir !== null) markEnded(stateDir, plan.key);
      }
    },
  };
}
