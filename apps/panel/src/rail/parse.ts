import type {
  PolicyBundle,
  PolicyDocument,
  PolicyRule,
  RailAction,
  RailDecision,
  RailEffect,
  RailInputs,
  RailRule,
} from "./types.ts";

export type PolicyStore = Record<string, PolicyDocument>;

function isBundle(value: PolicyStore | PolicyBundle | null | undefined): value is PolicyBundle {
  return value !== null && value !== undefined && "document" in value && "hash" in value;
}

function storeOf(policies?: PolicyStore | PolicyBundle | null): PolicyStore {
  if (!policies) return {};
  if (isBundle(policies)) return { [policies.hash]: policies.document };
  return policies;
}

function matchRule(subject: string, rules: readonly PolicyRule[]): PolicyRule | null {
  return rules.find((r) => r.tool === subject) ?? null;
}

function resolveRule(record: RailDecision, store: PolicyStore): RailRule | null {
  const document = store[record.claims.policyHash];
  if (!document) {
    return { text: null, missing: "historical policy unavailable" };
  }
  return matchRule(record.claims.subject, document.rules ?? []);
}

export function parseLedger(
  decisionsText: string,
  effectsText: string,
  policies?: PolicyStore | PolicyBundle | null,
  inputs?: Record<string, RailInputs> | null,
): RailAction[] {
  const decisions = decisionsText
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as RailDecision);
  const effects = effectsText
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as RailEffect);
  const byRef = new Map(effects.map((e) => [e.row.ref, e]));
  const store = storeOf(policies);
  return [...decisions].reverse().map((record) => {
    const doc = record.claims.ref ? (inputs?.[record.claims.ref] ?? null) : null;
    return {
      record,
      effect: record.claims.ref ? (byRef.get(record.claims.ref) ?? null) : null,
      rule: resolveRule(record, store),
      finding: null,
      inputs: doc,
      inputsBound: doc !== null,
    };
  });
}
