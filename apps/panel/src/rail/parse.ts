import type { PolicyBundle, PolicyRule, RailAction, RailDecision, RailEffect } from "./types.ts";

function matchRule(subject: string, rules: readonly PolicyRule[]): PolicyRule | null {
  return rules.find((r) => r.tool === subject) ?? null;
}

export function parseLedger(
  decisionsText: string,
  effectsText: string,
  policy?: PolicyBundle | null,
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
  const rules = policy?.document.rules ?? [];
  return [...decisions].reverse().map((record) => ({
    record,
    effect: record.claims.ref ? (byRef.get(record.claims.ref) ?? null) : null,
    rule: matchRule(record.claims.subject, rules),
    finding: null,
  }));
}
