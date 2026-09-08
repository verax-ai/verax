import type { Copy } from "../copy.ts";
import { readLang, type Lang } from "../lang.ts";
import { formatMinor } from "./money.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";

export type SpendFields = {
  amount: string;
  payee: string;
  approver: string;
  statement: string;
};

function approvalFor(action: RailAction, approvals: readonly PendingApproval[]): PendingApproval | null {
  const ref = action.record.claims.ref;
  if (!ref) return null;
  return (
    [...approvals].reverse().find((p) => p.allowRef === ref) ??
    [...approvals].reverse().find((p) => p.ref === ref) ??
    null
  );
}

function statementLine(copy: Copy, action: RailAction, reconcile: ReconcileCardReport | null): string {
  if (reconcile === null) return copy["spend.statement.unbound"];
  const ref = action.effect?.row.ref ?? action.record.claims.ref;
  if (action.effect?.row.effectClass !== "spend" || !ref) return copy["spend.statement.unmeasured"];
  for (const row of reconcile.matched ?? []) {
    if (row.effect?.ref === ref) return copy["spend.statement.matched"];
  }
  for (const row of reconcile.authorizedUnpaid ?? []) {
    if (row.ref === ref) return copy["spend.statement.unpaid"];
  }
  return copy["spend.statement.absent"];
}

export function spendFields(
  copy: Copy,
  action: RailAction,
  approvals: readonly PendingApproval[],
  reconcile: ReconcileCardReport | null,
  lang: Lang = readLang(),
): SpendFields | null {
  if (action.record.claims.subject !== "spend") return null;
  const snap = approvalFor(action, approvals);
  // Minor units in, a spendable amount out. When either side is unreadable
  // the field says so; it never shows the raw stored number.
  const money = snap ? formatMinor(snap.amount, snap.currency, lang) : null;
  const amount =
    money !== null ? copy["spend.amount"].replace("{amount}", money) : copy["spend.amount.unmeasured"];
  const payee =
    snap && snap.payee !== undefined
      ? copy["spend.payee"].replace("{payee}", String(snap.payee))
      : copy["spend.payee.unmeasured"];
  const approverId = action.inputs?.approver?.id;
  const via = action.inputs?.approver?.via;
  const approver =
    typeof approverId === "string" && approverId !== ""
      ? copy["spend.approver"]
          .replace("{id}", approverId)
          .replace("{via}", typeof via === "string" && via !== "" ? via : copy["unmeasured"])
      : copy["spend.approver.unmeasured"];
  return {
    amount,
    payee,
    approver,
    statement: statementLine(copy, action, reconcile),
  };
}
