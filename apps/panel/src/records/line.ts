import type { Copy } from "../copy.ts";
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

function asked(action: RailAction, approvals: readonly PendingApproval[]): string {
  const subject = action.record.claims.subject;
  const ref = action.record.claims.ref;
  const snap =
    approvals.find((p) => p.allowRef && p.allowRef === ref) ??
    approvals.find((p) => p.ref === ref) ??
    null;
  if (subject === "spend" && snap && snap.payee !== undefined) {
    const amount = snap.amount !== undefined ? String(snap.amount) : "";
    const currency = snap.currency !== undefined ? String(snap.currency) : "";
    const payee = String(snap.payee);
    const money = [amount, currency].filter((s) => s !== "").join(" ");
    return money !== "" ? `${subject} ${money} → ${payee}` : `${subject} → ${payee}`;
  }
  return subject;
}

export function recordLine(
  copy: Copy,
  action: RailAction,
  approvals: readonly PendingApproval[] = [],
): { asked: string; rule: string; outcome: string; kind: RecordKind; label: string } {
  const kind = kindOf(action);
  const askedText = asked(action, approvals);
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
