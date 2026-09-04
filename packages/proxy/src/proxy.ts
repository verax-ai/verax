import { signDecisionRecord } from "@cedulon/core";
import type { EffectRow } from "@cedulon/effect-extract";
import { effectDescriptor, sha256Canonical } from "./hash.ts";
import type { Principal, ProxyDeps, ToolCall, ToolResult } from "./types.ts";

function denied(reasonCode: string, ref: string): ToolResult {
  return {
    content: [{ type: "text", text: `denied:${reasonCode}:${ref}` }],
    isError: true,
  };
}

function thrownPayload(err: unknown): unknown {
  if (err instanceof Error) {
    return { name: err.name, message: err.message };
  }
  return { name: "thrown" };
}

export function createProxy(deps: ProxyDeps) {
  return {
    async call(call: ToolCall, principal: Principal): Promise<ToolResult> {
      const verdict = deps.policy.evaluate(call, principal);
      const ref = deps.nonce();
      const timestampMs = deps.now();
      const allow = verdict.decision === "allow";
      await deps.ledger.appendDecisionChained((prevRecordHash) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: call.name,
            requestHash: sha256Canonical(call),
            policyHash: deps.policy.hash,
            inputsHash: null,
            decision: verdict.decision,
            reasonCode: verdict.reasonCode,
            ref,
            effectHash: allow ? sha256Canonical(effectDescriptor(call.name, call.arguments)) : null,
            timestampMs,
            nonce: ref,
            prevRecordHash,
          },
          deps.recordSigner.privateKeyPem,
          deps.recordSigner.publicKeyPem,
        ),
      );
      if (!allow) {
        return denied(verdict.reasonCode, ref);
      }

      try {
        const result = await deps.inner(call, principal);
        const executed = result.executed ?? { tool: call.name, arguments: call.arguments };
        const row: EffectRow = {
          ref,
          effectHash: sha256Canonical(effectDescriptor(executed.tool, executed.arguments)),
          effectClass: call.name,
          timestampMs: deps.now(),
          actor: principal.brain,
        };
        await deps.ledger.appendEffect(row, "self", sha256Canonical(result));
        return result;
      } catch (err) {
        const row: EffectRow = {
          ref,
          effectHash: sha256Canonical(effectDescriptor(call.name, call.arguments, true)),
          effectClass: `${call.name}:threw`,
          timestampMs: deps.now(),
          actor: principal.brain,
        };
        await deps.ledger.appendEffect(row, "self", sha256Canonical(thrownPayload(err)));
        throw err;
      }
    },
  };
}
