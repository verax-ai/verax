import { parseIJson } from "@cedulon/core";
import { sha256Canonical } from "./hash.ts";
import type { Policy, PolicyDecision, PolicyEvalCtx, Principal, ToolCall } from "./types.ts";

export type PolicySpend = {
  maxAmountMinor: number;
  currency: string;
  payees: readonly string[];
  dailyMaxMinor?: number;
};

export type PolicyRule = {
  id: string;
  tool: string;
  requires: readonly string[];
  text: string;
  mode?: "allow" | "approve";
  spend?: PolicySpend;
};

export type PolicyDocument = {
  version: 1;
  default: "deny";
  approvalTtlMs?: number;
  rules: PolicyRule[];
};

const DEFAULT_APPROVAL_TTL_MS = 86_400_000;

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
  if (rec.tool === "spend") {
    if (rule.mode !== "approve") {
      throw new Error(`policy-rule-spend-mode:${rec.id}`);
    }
    if (rec.spend === undefined) {
      throw new Error(`policy-rule-spend-missing:${rec.id}`);
    }
    rule.spend = asSpend(rec.spend, rec.id);
  }
  return rule;
}

function asSpend(raw: unknown, id: string): PolicySpend {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  const rec = raw as Record<string, unknown>;
  if (
    typeof rec.maxAmountMinor !== "number" ||
    !Number.isInteger(rec.maxAmountMinor) ||
    rec.maxAmountMinor <= 0
  ) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  if (typeof rec.currency !== "string" || !/^[A-Z]{3}$/.test(rec.currency)) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  if (!Array.isArray(rec.payees) || rec.payees.length === 0 || rec.payees.some((p) => typeof p !== "string" || p === "")) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  const spend: PolicySpend = {
    maxAmountMinor: rec.maxAmountMinor,
    currency: rec.currency,
    payees: rec.payees as string[],
  };
  if (rec.dailyMaxMinor !== undefined) {
    if (typeof rec.dailyMaxMinor !== "number" || !Number.isInteger(rec.dailyMaxMinor) || rec.dailyMaxMinor <= 0) {
      throw new Error(`policy-rule-spend-missing:${id}`);
    }
    spend.dailyMaxMinor = rec.dailyMaxMinor;
  }
  return spend;
}

function spendArgsInvalid(args: Record<string, unknown>): boolean {
  const keys = Object.keys(args);
  const allowed = new Set(["amountMinor", "currency", "payee", "reference"]);
  if (keys.length !== 4 || keys.some((k) => !allowed.has(k))) return true;
  const amt = args.amountMinor;
  if (typeof amt !== "number" || !Number.isInteger(amt) || amt <= 0) return true;
  if (typeof args.currency !== "string" || !/^[A-Z]{3}$/.test(args.currency)) return true;
  if (typeof args.payee !== "string" || args.payee === "") return true;
  if (typeof args.reference !== "string" || args.reference.length > 140) return true;
  return false;
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
    evaluate(call: ToolCall, principal: Principal, ctx?: PolicyEvalCtx): PolicyDecision {
      if (call.name === "pay") {
        return { decision: "deny", reasonCode: "spend-not-wired", rule: null };
      }
      if (call.name === "spend") {
        const rule = document.rules.find((r) => r.tool === "spend");
        if (!rule || !rule.spend) {
          return { decision: "deny", reasonCode: "spend-not-wired", rule: null };
        }
        for (const scope of rule.requires) {
          if (!principal.scopes.has(scope)) {
            return { decision: "deny", reasonCode: "scope-missing", rule: rule.id };
          }
        }
        if (spendArgsInvalid(call.arguments)) {
          return { decision: "deny", reasonCode: "spend-args-invalid", rule: rule.id };
        }
        const amountMinor = call.arguments.amountMinor as number;
        const currency = call.arguments.currency as string;
        const payee = call.arguments.payee as string;
        if (currency !== rule.spend.currency) {
          return { decision: "deny", reasonCode: "spend-currency", rule: rule.id };
        }
        if (amountMinor > rule.spend.maxAmountMinor) {
          return { decision: "deny", reasonCode: "spend-cap", rule: rule.id };
        }
        if (!rule.spend.payees.includes(payee)) {
          return { decision: "deny", reasonCode: "spend-payee", rule: rule.id };
        }
        if (rule.spend.dailyMaxMinor !== undefined) {
          const spent = ctx?.spentTodayMinor?.(currency) ?? 0;
          if (spent + amountMinor > rule.spend.dailyMaxMinor) {
            return { decision: "deny", reasonCode: "spend-daily", rule: rule.id };
          }
        }
        return { decision: "defer", reasonCode: "approval-required", rule: rule.id };
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
