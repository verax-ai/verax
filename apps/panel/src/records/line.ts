import type { Copy } from "../copy.ts";
import { readLang, type Lang } from "../lang.ts";
import { formatMinor } from "./money.ts";
import type { PendingApproval, RailAction } from "../rail/types.ts";

export type RecordKind = "allow" | "deny" | "defer" | "threw";

export function kindOf(action: RailAction): RecordKind {
  if (action.effect?.row.effectClass.endsWith(":threw")) return "threw";
  if (action.record.claims.decision === "defer") return "defer";
  return action.record.claims.decision === "deny" ? "deny" : "allow";
}

export function statusWord(copy: Copy, kind: RecordKind): string {
  if (kind === "allow") return copy["status.allow"];
  if (kind === "deny") return copy["status.deny"];
  if (kind === "defer") return copy["status.defer"];
  return copy["status.threw"];
}

function ruleText(copy: Copy, action: RailAction): string {
  if (action.rule && "missing" in action.rule) return copy["line.rule.missing"];
  if (action.rule && !("missing" in action.rule) && action.rule.text) return action.rule.text;
  return copy["line.rule.none"];
}

function asked(action: RailAction, approvals: readonly PendingApproval[], lang: Lang): string {
  const subject = action.record.claims.subject;
  const ref = action.record.claims.ref;
  const snap =
    approvals.find((p) => p.allowRef && p.allowRef === ref) ??
    approvals.find((p) => p.ref === ref) ??
    null;
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
  const kind = kindOf(action);
  const askedText = asked(action, approvals, lang);
  const rule = ruleText(copy, action);
  const outcome = `${action.record.claims.decision} ${action.record.claims.reasonCode}`;
  return {
    asked: askedText,
    rule,
    outcome,
    kind,
    label: `${askedText} · ${rule} · ${outcome}`,
  };
}
