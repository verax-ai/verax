import { signDecisionRecord } from "@cedulon/core";
import type { EffectRow } from "@cedulon/effect-extract";
import { effectDescriptor, sha256Canonical } from "./hash.ts";
import { inputsLogFor } from "./inputs.ts";
import type { DecisionInputRow, DecisionInputs, Principal, ProxyDeps, ToolCall, ToolResult } from "./types.ts";

function denied(reasonCode: string, ref: string): ToolResult {
  return {
    content: [{ type: "text", text: `denied:${reasonCode}:${ref}` }],
    isError: true,
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

function toolCallOf(call: ToolCall): ToolCall {
  const args = { ...call.arguments };
  delete args._inputs;
  return { name: call.name, arguments: args };
}

export function createProxy(deps: ProxyDeps) {
  const inputsLog = deps.inputsLog ?? inputsLogFor(deps.ledger);
  return {
    async call(call: ToolCall, principal: Principal): Promise<ToolResult> {
      const verdict = deps.policy.evaluate(call, principal);
      const ref = deps.nonce();
      const timestampMs = deps.now();
      const declared = declaredInputs(call.arguments);
      let reasonCode = verdict.reasonCode;
      let decision = verdict.decision;
      const rows: DecisionInputRow[] = [];
      if (declared === "invalid") {
        decision = "deny";
        reasonCode = "input-invalid";
      } else if (declared) {
        for (const item of declared) {
          const got = deps.resolveInput ? await deps.resolveInput(item.id) : null;
          if (
            !got ||
            got.versionHash !== item.versionHash ||
            got.validFromMs > timestampMs ||
            got.validUntilMs < timestampMs
          ) {
            decision = "deny";
            reasonCode = "input-invalid";
            break;
          }
          rows.push({
            id: item.id,
            versionHash: item.versionHash,
            validFromMs: got.validFromMs,
            validUntilMs: got.validUntilMs,
          });
        }
      }
      const inputs: DecisionInputs = {
        principal: { brain: principal.brain, scopes: [...principal.scopes].sort() },
        inputs: reasonCode === "input-invalid" ? [] : rows,
      };
      const inputsHash = sha256Canonical(inputs);
      await inputsLog.append(ref, inputs);
      const allow = decision === "allow";
      const dispatched = toolCallOf(call);
      await deps.ledger.appendDecisionChained((prevRecordHash) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: call.name,
            requestHash: sha256Canonical(dispatched),
            policyHash: deps.policy.hash,
            inputsHash,
            decision,
            reasonCode,
            ref,
            effectHash: allow ? sha256Canonical(effectDescriptor(dispatched.name, dispatched.arguments)) : null,
            timestampMs,
            nonce: ref,
            prevRecordHash,
          },
          deps.recordSigner.privateKeyPem,
          deps.recordSigner.publicKeyPem,
        ),
      );
      if (!allow) {
        return denied(reasonCode, ref);
      }

      const dispatchedName = dispatched.name;
      const dispatchedArgs = deepFreeze(structuredClone(dispatched.arguments));
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
    },
  };
}
