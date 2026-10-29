/**
 * What a held spend is shown as, wherever an operator is asked to approve
 * one. The terminal and the operator door read the same four fields from
 * here, so neither can show a payee or an amount the other would not.
 */
import { approvalDispatchArgs, type ApprovalRow } from "@verax-ai/proxy";

export type HeldSpend = { payee: string; amountMinor: number | null; currency: string; reference: string };

function integerMinor(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

/** An integer minor-unit amount, or null when the stored amount cannot be read as one. */
export function minorUnits(row: ApprovalRow): number | null {
  return integerMinor(approvalDispatchArgs(row).amountMinor);
}

/** Null for a held call that is not a spend. */
export function heldSpend(row: ApprovalRow): HeldSpend | null {
  if (row.subject !== "spend") return null;
  const args = approvalDispatchArgs(row);
  return {
    payee: typeof args.payee === "string" ? args.payee : String(args.payee ?? ""),
    amountMinor: minorUnits(row),
    currency: typeof args.currency === "string" ? args.currency : String(args.currency ?? ""),
    reference: typeof args.reference === "string" ? args.reference : "",
  };
}
