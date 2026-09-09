import type { Copy } from "../copy.ts";
import { readLang, type Lang } from "../lang.ts";
import { formatMinor } from "./money.ts";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { approvalForRef, resolutionOf } from "./approval-state.ts";

export type RecordKind = "allow" | "deny" | "defer" | "threw" | "expired";

export function kindOf(action: RailAction, approvals: readonly PendingApproval[] = []): RecordKind {
  if (action.effect?.row.effectClass.endsWith(":threw")) return "threw";
  const resolution = resolutionOf(action, approvals);
  if (resolution === "waiting") return "defer";
  if (resolution === "expired") return "expired";
  return action.record.claims.decision === "deny" ? "deny" : "allow";
}

export function statusWord(copy: Copy, kind: RecordKind): string {
  if (kind === "allow") return copy["status.allow"];
  if (kind === "deny") return copy["status.deny"];
  if (kind === "defer") return copy["status.defer"];
  if (kind === "expired") return copy["status.expired"];
  return copy["status.threw"];
}

/**
 * What happened, as the ledger has it now. The record's own claim stays in
 * the sentence: a defer that was later answered reads "defer
 * approval-required -> allowed", never one word in place of the other. The
 * word after the arrow comes from kindOf, the same source as the status
 * column, so the two cannot end up voting differently.
 */
export function outcomeText(
  copy: Copy,
  action: RailAction,
  approvals: readonly PendingApproval[] = [],
): string {
  const { decision, reasonCode } = action.record.claims;
  // "allow allow" is the ledger repeating itself, not two facts.
  const claim = reasonCode === decision ? decision : `${decision} ${reasonCode}`;
  const resolution = resolutionOf(action, approvals);
  if (resolution === "not-deferred" || resolution === "waiting") return claim;
  return `${claim} → ${statusWord(copy, kindOf(action, approvals))}`;
}

function ruleText(copy: Copy, action: RailAction): string {
  if (action.rule && "missing" in action.rule) return copy["line.rule.missing"];
  if (action.rule && !("missing" in action.rule) && action.rule.text) return action.rule.text;
  return copy["line.rule.none"];
}

function asked(action: RailAction, approvals: readonly PendingApproval[], lang: Lang): string {
  const subject = action.record.claims.subject;
  const ref = action.record.claims.ref;
  const snap = approvalForRef(approvals, ref) ?? null;
  if (subject === "spend" && snap && snap.payee !== undefined) {
    const payee = String(snap.payee);
    // The snapshot carries minor units. An unreadable amount is left out of
    // the line rather than printed raw: a wrong number reads as a true one.
    const money = formatMinor(snap.amount, snap.currency, lang);
    return money !== null ? `${subject} ${money} → ${payee}` : `${subject} → ${payee}`;
  }
  return subject;
}

export function recordLine(
  copy: Copy,
  action: RailAction,
  approvals: readonly PendingApproval[] = [],
  lang: Lang = readLang(),
): { asked: string; rule: string; outcome: string; kind: RecordKind; label: string } {
  const kind = kindOf(action, approvals);
  const askedText = asked(action, approvals, lang);
  const rule = ruleText(copy, action);
  const outcome = outcomeText(copy, action, approvals);
  return {
    asked: askedText,
    rule,
    outcome,
    kind,
    label: `${askedText} · ${rule} · ${outcome}`,
  };
}
