import { signDecisionRecord } from "@cedulon/core";
import type { DecisionKind } from "@cedulon/core";
import type { EffectRow } from "@cedulon/effect-extract";
import { approvePending, approvalsLogFor, drainApprovalCommands } from "./approvals.ts";
import { effectDescriptor, sha256Canonical } from "./hash.ts";
import { inputsLogFor } from "./inputs.ts";
import { hasPrimaryEffect, lookupDecisionByRef, lookupResolvedBy, noteResolution } from "./ledger.ts";
import type { DecisionInputRow, DecisionInputs, Principal, ProxyDeps, ToolCall, ToolResult } from "./types.ts";

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
      const result = await deps.inner(frozenCall, principal);
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
        inputs: { principal: { brain: principal.brain, scopes: [...principal.scopes].sort() }, inputs: [] },
        reasonCode: "input-invalid",
      };
    }
    const rows: DecisionInputRow[] = [];
    if (declared) {
      for (const item of declared) {
        const got = deps.resolveInput ? await deps.resolveInput(item.id) : null;
        if (
          !got ||
          got.versionHash !== item.versionHash ||
          got.validFromMs > timestampMs ||
          got.validUntilMs < timestampMs
        ) {
          return {
            inputs: { principal: { brain: principal.brain, scopes: [...principal.scopes].sort() }, inputs: [] },
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
      inputs: { principal: { brain: principal.brain, scopes: [...principal.scopes].sort() }, inputs: rows },
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
        const existing = await lookupDecisionByRef(deps.ledger, given);
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
            return runInner(dispatched, principal, existing.ref);
          }
        }
      }

      const verdict = deps.policy.evaluate(call, principal);
      let reasonCode = resolved.reasonCode ?? verdict.reasonCode;
      let decision = resolved.reasonCode ? ("deny" as const) : verdict.decision;
      const ref = given ?? deps.nonce();
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
      if (decision === "defer") {
        const rule = deps.policy.rule(verdict.rule);
        const amount = dispatched.arguments.amount;
        const payee = dispatched.arguments.payee;
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
