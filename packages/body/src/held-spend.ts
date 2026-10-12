/**
 * What a held spend is shown as, wherever an operator is asked to approve
 * one. The terminal and the operator door read the same four fields from
 * here, so neither can show a payee or an amount the other would not.
 */
import type { ApprovalRow } from "@verax-ai/proxy";

export type HeldSpend = { payee: string; amountMinor: number | null; currency: string; reference: string };

function integerMinor(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

/** An integer minor-unit amount, or null when the stored amount cannot be read as one. */
export function minorUnits(row: ApprovalRow): number | null {
  if (typeof row.amount === "number") return integerMinor(row.amount);
  return integerMinor(row.args.amountMinor);
}

/** Null for a held call that is not a spend. */
export function heldSpend(row: ApprovalRow): HeldSpend | null {
  if (row.subject !== "spend") return null;
  return {
    payee: typeof row.payee === "string" ? row.payee : String(row.args.payee ?? ""),
    amountMinor: minorUnits(row),
    currency: typeof row.currency === "string" ? row.currency : String(row.args.currency ?? ""),
    reference: typeof row.args.reference === "string" ? row.args.reference : "",
  };
}
