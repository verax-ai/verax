/**
 * Named checks, in the order a verifier meets them. A negative vector names
 * the first one that must fail. The names are this set's own; where another
 * implementer's labels fit (DIGEST / CANONICAL / SIGNATURE), the README maps
 * them.
 */
export const STAGES = [
  "record-header",
  "record-signature",
  "record-claims",
  "chain",
  "inputs-binding",
  "effect-binding",
  "index",
  "approval-signature",
  "checkpoint-signature",
  "checkpoint-coverage",
  "checkpoint-totals",
  "control",
] as const;

export type Stage = (typeof STAGES)[number];

/**
 * `verax verify` reports the three record checks as one line ("signature does
 * not verify"), so a problem line maps to a group of stages, not always to
 * one. A vector's stage passes the comparison when it is in the group of the
 * first problem line.
 */
const LINES: { pattern: RegExp; stages: readonly Stage[] }[] = [
  { pattern: /^signature does not verify: record /, stages: ["record-header", "record-signature", "record-claims"] },
  { pattern: /^public key is not ed25519/, stages: ["record-header"] },
  { pattern: /^chain breaks at record /, stages: ["chain"] },
  { pattern: /^inputs (row|hash)/, stages: ["inputs-binding"] },
  {
    pattern:
      /^(effect |thrown effect|duplicate-effect|ref .* has more than one effect row|same-org rows need|self rows need)/,
    stages: ["effect-binding"],
  },
  { pattern: /^index /, stages: ["index"] },
  { pattern: /^approval signatures: /, stages: ["approval-signature"] },
  { pattern: /^checkpoint (signature does not verify|chain )/, stages: ["checkpoint-signature"] },
  { pattern: /^(checkpoint covers |newest checkpoint names |checkpoint names a head )/, stages: ["checkpoint-coverage"] },
  { pattern: /^checkpoint totals /, stages: ["checkpoint-totals"] },
  { pattern: /^allow-while-halted /, stages: ["control"] },
];

/** Stages a problem line can stand for, or null for a line this table does not know. */
export function stagesOf(line: string): readonly Stage[] | null {
  for (const entry of LINES) {
    if (entry.pattern.test(line)) return entry.stages;
  }
  return null;
}

/** The earliest stage any problem line stands for, by STAGES order. */
export function firstStage(problems: readonly string[]): { stages: readonly Stage[]; line: string } | null {
  let best: { stages: readonly Stage[]; line: string; at: number } | null = null;
  for (const line of problems) {
    const stages = stagesOf(line);
    if (!stages) continue;
    const at = Math.min(...stages.map((s) => STAGES.indexOf(s)));
    if (!best || at < best.at) best = { stages, line, at };
  }
  return best ? { stages: best.stages, line: best.line } : null;
}
