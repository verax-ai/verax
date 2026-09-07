import { existsSync } from "node:fs";
import { join } from "node:path";
import { signDecisionRecord } from "@cedulon/core";
import type { DecisionKind } from "@cedulon/core";
import type { EffectRow } from "@cedulon/effect-extract";
import { approvePending, approvalsLogFor, drainApprovalCommands } from "./approvals.ts";
import { diskProbe } from "./disk.ts";
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

function denied(reasonCode: string, ref: string): ToolResult {
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

function declaredInputs(args: Record<string, unknown>): { id: string; versionHash: string }[] | "invalid" | null {
  if (!Object.prototype.hasOwnProperty.call(args, "_inputs")) return null;
  const raw = args._inputs;
  if (!Array.isArray(raw)) return "invalid";
  const out: { id: string; versionHash: string }[] = [];
  for (const item of raw) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) return "invalid";
    const rec = item as Record<string, unknown>;
    if (typeof rec.id !== "string" || rec.id === "" || typeof rec.versionHash !== "string" || rec.versionHash === "") {
      return "invalid";
    }
    out.push({ id: rec.id, versionHash: rec.versionHash });
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

  function utcDayStart(ms: number): number {
    const d = new Date(ms);
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  }

  function spentTodayMinorOf(rows: { subject: string; status: string; createdAtMs?: number; expiresAtMs: number; args: Record<string, unknown> }[], nowMs: number, currency: string): number {
    const start = utcDayStart(nowMs);
    const end = start + 86_400_000;
    let sum = 0;
    for (const row of rows) {
      if (row.subject !== "spend") continue;
      if (row.status !== "pending" && row.status !== "approved") continue;
      const created = row.createdAtMs ?? row.expiresAtMs - deps.policy.approvalTtlMs;
      if (created < start || created >= end) continue;
      if (row.args.currency !== currency) continue;
      const amt = row.args.amountMinor;
      if (typeof amt === "number") sum += amt;
    }
    return sum;
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
        rows.push({
          id: item.id,
          versionHash: item.versionHash,
          validFromMs: got.validFromMs,
          validUntilMs: got.validUntilMs,
        });
      }
    }
    return {
      inputs: { principal: principalInputs(principal), inputs: rows },
      reasonCode: null,
    };
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
            policyHash: defer.policyHash,
            approvals,
            inputsLog,
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
        return denied("ref-invalid", ref);
      }

      if (typeof given === "string") {
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
            return denied("ref-reuse", ref);
          }
          if (existing.decision === "defer") {
            const snap = await approvals.get(given);
            const boundHit = lookupResolvedBy(deps.ledger, given);
            if (boundHit?.kind === "expired") {
              if (snap?.status === "pending") await approvals.updateStatus(given, "expired");
              return denied("expired", boundHit.ref);
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
                  approver: { id: "verax-proxy", via: "proxy", resolves: given },
                },
                effectHash: null,
                subject: call.name,
                timestampMs,
              });
              await approvals.updateStatus(given, "expired");
              return denied("expired", expireRef);
            }
            const allowRef = snap?.allowRef ?? (boundHit?.kind === "allow" ? boundHit.ref : undefined);
            const allow = allowRef ? await lookupDecisionByRef(deps.ledger, allowRef) : null;
            if (allow?.ref && allow.decision === "allow" && allow.reasonCode === "approved-by-operator") {
              const bound = await inputsLog.get(allow.ref);
              if (bound?.approver?.resolves && bound.approver.resolves !== given) {
                return deferred(given);
              }
              if (!snap?.allowRef) {
                await approvals.updateStatus(given, "approved", { allowRef: allow.ref });
              }
              if (await hasPrimaryEffect(deps.ledger, allow.ref)) return allowedReplay(allow.ref);
              if (allow.subject === "spend") {
                return spendReauth(requestHash, resolved.inputs, timestampMs, call.name);
              }
              return runInner(dispatched, principal, allow.ref);
            }
            return deferred(given);
          }
          if (existing.decision === "deny") {
            return denied(existing.reasonCode, given);
          }
          if (existing.decision === "allow" && existing.ref) {
            if (await hasPrimaryEffect(deps.ledger, existing.ref)) {
              return allowedReplay(existing.ref);
            }
            if (existing.subject === "spend") {
              return spendReauth(requestHash, resolved.inputs, timestampMs, call.name);
            }
            return runInner(dispatched, principal, existing.ref);
          }
        }
      }

      let spendCtx: { spentTodayMinor: (currency: string) => number } | undefined;
      if (dispatched.name === "spend") {
        const approvalRows = await approvals.listAll();
        spendCtx = {
          spentTodayMinor: (currency) => spentTodayMinorOf(approvalRows, timestampMs, currency),
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
        return deferred(ref);
      }
      if (!allow) {
        return denied(reasonCode, ref);
      }
      return runInner(dispatched, principal, ref);
    },
  };
}
