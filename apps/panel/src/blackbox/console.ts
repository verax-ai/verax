import type { PendingApproval, RailAction } from "../rail/types.ts";
import { lastApprovalByRef } from "../records/approval-state.ts";
import type { Lang } from "../lang.ts";

/**
 * What the black box's console stands on: one approval request read from the
 * ledger. The console on the public site plays a sample; this one only shows
 * a request the body recorded, and says so when there is none.
 */
export type ConsoleView =
  | { kind: "none" }
  | {
      kind: "waiting" | "approved" | "expired";
      row: PendingApproval;
      defer: RailAction | null;
      resolution: RailAction | null;
    };

/**
 * The request the console opens on: the newest one still waiting, otherwise
 * the newest one that was answered. Rows are read as the ledger holds them;
 * a later row for the same ref replaces the earlier one.
 */
export function consoleView(actions: readonly RailAction[], pending: readonly PendingApproval[]): ConsoleView {
  const rows = [...lastApprovalByRef(pending).values()];
  const newest = (list: PendingApproval[]) => list[list.length - 1];
  const row = newest(rows.filter((r) => r.status === "pending")) ?? newest(rows);
  if (!row) return { kind: "none" };
  const byRef = (ref: string | undefined) =>
    ref ? actions.find((a) => a.record.claims.ref === ref) ?? null : null;
  return {
    kind: row.status === "pending" ? "waiting" : row.status,
    row,
    defer: byRef(row.ref),
    resolution: row.status === "approved" ? byRef(row.allowRef) : null,
  };
}

/** Counts the box's layers carry. Each one is read from the ledger, none is declared. */
export type LayerCounts = { records: number; memory: number; spend: number; waiting: number };

export function layerCounts(
  actions: readonly RailAction[],
  pending: readonly PendingApproval[],
  decisions: number | undefined,
): LayerCounts {
  const subjects = actions.map((a) => a.record.claims.subject);
  return {
    records: decisions ?? actions.length,
    memory: subjects.filter((s) => s.startsWith("memory.")).length,
    spend: subjects.filter((s) => s === "spend").length,
    waiting: [...lastApprovalByRef(pending).values()].filter((r) => r.status === "pending").length,
  };
}

/**
 * The console prints a sum large and its fraction small. The two halves come
 * from one formatted string, so together they read exactly what the record
 * list prints for the same row.
 */
export function splitMoney(amountMinor: unknown, currency: unknown, lang: Lang): { whole: string; fraction: string } | null {
  if (typeof amountMinor !== "number" || !Number.isFinite(amountMinor)) return null;
  if (typeof currency !== "string" || currency.trim() === "") return null;
  try {
    const format = new Intl.NumberFormat(lang, { style: "currency", currency: currency.trim().toUpperCase() });
    const digits = format.resolvedOptions().maximumFractionDigits ?? 2;
    const parts = format.formatToParts(amountMinor / 10 ** digits);
    const at = parts.findIndex((p) => p.type === "decimal");
    const text = (list: Intl.NumberFormatPart[]) => list.map((p) => p.value).join("");
    if (at === -1) return { whole: text(parts), fraction: "" };
    return { whole: text(parts.slice(0, at)), fraction: text(parts.slice(at)) };
  } catch {
    return null;
  }
}
