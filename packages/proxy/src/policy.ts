import { parseIJson } from "@cedulon/core";
import { sha256Canonical } from "./hash.ts";
import type { Policy, PolicyDecision, Principal, ToolCall } from "./types.ts";

export type PolicyRule = {
  id: string;
  tool: string;
  requires: readonly string[];
  text: string;
  mode?: "allow" | "approve";
};

export type PolicyDocument = {
  version: 1;
  default: "deny";
  approvalTtlMs?: number;
  rules: PolicyRule[];
};

const DEFAULT_APPROVAL_TTL_MS = 86_400_000;

const SPEND_TOOLS = new Set(["spend", "pay"]);

function asRule(raw: unknown, index: number): PolicyRule {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`policy-rule-invalid:${index}`);
  }
  const rec = raw as Record<string, unknown>;
  if (typeof rec.id !== "string" || rec.id === "") {
    throw new Error(`policy-rule-id:${index}`);
  }
  if (typeof rec.tool !== "string" || rec.tool === "") {
    throw new Error(`policy-rule-tool:${rec.id}`);
  }
  if (!Array.isArray(rec.requires) || rec.requires.some((s) => typeof s !== "string" || s === "")) {
    throw new Error(`policy-rule-requires:${rec.id}`);
  }
  if (typeof rec.text !== "string" || rec.text.trim() === "") {
    throw new Error(`policy-rule-text:${rec.id}`);
  }
  const rule: PolicyRule = {
    id: rec.id,
    tool: rec.tool,
    requires: rec.requires as string[],
    text: rec.text,
  };
  if (rec.mode !== undefined) {
    if (rec.mode !== "allow" && rec.mode !== "approve") {
      throw new Error(`policy-rule-mode:${rec.id}`);
    }
    rule.mode = rec.mode;
  }
  return rule;
}

export function parsePolicyDocument(json: unknown): PolicyDocument {
  const raw = typeof json === "string" ? parseIJson(json) : json;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("policy-not-object");
  }
  const rec = raw as Record<string, unknown>;
  if (rec.version !== 1) {
    throw new Error("policy-version");
  }
  if (rec.default !== "deny") {
    throw new Error("policy-default-not-deny");
  }
  if (!Array.isArray(rec.rules)) {
    throw new Error("policy-rules");
  }
  const document: PolicyDocument = {
    version: 1,
    default: "deny",
    rules: rec.rules.map(asRule),
  };
  if (rec.approvalTtlMs !== undefined) {
    if (typeof rec.approvalTtlMs !== "number" || !Number.isFinite(rec.approvalTtlMs) || rec.approvalTtlMs < 0) {
      throw new Error("policy-approval-ttl");
    }
    document.approvalTtlMs = rec.approvalTtlMs;
  }
  return document;
}

export function ruleTextHash(text: string): string {
  return sha256Canonical(text);
}

export function loadPolicy(json: unknown): Policy {
  const document = parsePolicyDocument(json);
  const hash = sha256Canonical(document);
  return {
    hash,
    approvalTtlMs: document.approvalTtlMs ?? DEFAULT_APPROVAL_TTL_MS,
    rule(id: string | null) {
      if (id === null) return null;
      const found = document.rules.find((r) => r.id === id);
      return found ? { id: found.id, text: found.text } : null;
    },
    evaluate(call: ToolCall, principal: Principal): PolicyDecision {
      if (SPEND_TOOLS.has(call.name)) {
        return { decision: "deny", reasonCode: "spend-not-wired", rule: null };
      }
      const rule = document.rules.find((r) => r.tool === call.name);
      if (!rule) {
        return { decision: "deny", reasonCode: "no-rule", rule: null };
      }
      for (const scope of rule.requires) {
        if (!principal.scopes.has(scope)) {
          return { decision: "deny", reasonCode: "scope-missing", rule: rule.id };
        }
      }
      if (rule.mode === "approve") {
        return { decision: "defer", reasonCode: "approval-required", rule: rule.id };
      }
      return { decision: "allow", reasonCode: "allow", rule: rule.id };
    },
  };
}
