import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { EffectRow } from "@cedulon/effect-extract";

import type { ApprovalRow } from "./approvals.ts";
import type { LedgerEffect } from "./types.ts";

export type ChannelRow = {
  channel: string;
  externalId: string;
  occurredAtMs: number;
  subject: string;
  actor?: string;
  ref?: string;
  nearestEffectDtMs?: number;
  amountMinor?: number;
  currency?: string;
  credit?: boolean;
};

export type ReconcileReport = {
  scope: {
    channel: string;
    windowStartMs: number;
    windowEndMs: number;
    rowCount: number;
  };
  matched: Array<{ channel: ChannelRow; effect: EffectRow }>;
  ghost: ChannelRow[];
  unsent: EffectRow[];
  authorizedUnpaid: EffectRow[];
  outOfScope: ChannelRow[];
};

function asChannelRow(raw: unknown, line: number): ChannelRow {
  if (raw === null || typeof raw !== "object") {
    throw new Error(`channel-row-invalid:${line}`);
  }
  const o = raw as Record<string, unknown>;
  if (typeof o.channel !== "string" || o.channel === "") {
    throw new Error(`channel-row-invalid:${line}:channel`);
  }
  if (typeof o.externalId !== "string" || o.externalId === "") {
    throw new Error(`channel-row-invalid:${line}:externalId`);
  }
  if (typeof o.occurredAtMs !== "number" || !Number.isFinite(o.occurredAtMs)) {
    throw new Error(`channel-row-invalid:${line}:occurredAtMs`);
  }
  if (typeof o.subject !== "string" || o.subject === "") {
    throw new Error(`channel-row-invalid:${line}:subject`);
  }
  const row: ChannelRow = {
    channel: o.channel,
    externalId: o.externalId,
    occurredAtMs: o.occurredAtMs,
    subject: o.subject,
  };
  if (typeof o.actor === "string") row.actor = o.actor;
  if (typeof o.ref === "string") row.ref = o.ref;
  if (typeof o.amountMinor === "number") row.amountMinor = o.amountMinor;
  if (typeof o.currency === "string") row.currency = o.currency;
  if (o.credit === true) row.credit = true;
  return row;
}

export type CardCsvOpts = {
  currency: string;
  columns?: { date: string; amount: string; description: string; id?: string };
  delimiter?: ";" | ",";
  decimal?: "," | ".";
  dateFormat?: "DD.MM.YYYY" | "YYYY-MM-DD";
};

const VERAX_REF = /verax:([A-Za-z0-9][A-Za-z0-9._-]{0,63})/;

function parseCardDate(raw: string, format: "DD.MM.YYYY" | "YYYY-MM-DD"): number {
  const t = raw.trim();
  if (format === "YYYY-MM-DD") {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(t);
    if (!m) throw new Error(`card-csv-date:${raw}`);
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12, 0, 0);
  }
  const m = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(t);
  if (!m) throw new Error(`card-csv-date:${raw}`);
  return Date.UTC(Number(m[3]), Number(m[2]) - 1, Number(m[1]), 12, 0, 0);
}

function parseCardAmount(raw: string, decimal: "," | "."): number {
  const thousand = decimal === "," ? "." : ",";
  const cleaned = raw.trim().replaceAll(thousand, "").replace(decimal, ".");
  const n = Number(cleaned);
  if (!Number.isFinite(n)) throw new Error(`card-csv-amount:${raw}`);
  return Math.round(n * 100);
}

export function parseCardCsv(text: string, opts: CardCsvOpts): ChannelRow[] {
  const delimiter = opts.delimiter ?? ";";
  const decimal = opts.decimal ?? ",";
  const dateFormat = opts.dateFormat ?? "DD.MM.YYYY";
  const columns = opts.columns ?? { date: "Tarih", amount: "Tutar", description: "Açıklama" };
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => l !== "");
  if (lines.length === 0) return [];
  const header = lines[0]!.split(delimiter).map((h) => h.trim());
  const dateIdx = header.indexOf(columns.date);
  const amountIdx = header.indexOf(columns.amount);
  const descIdx = header.indexOf(columns.description);
  const idIdx = columns.id ? header.indexOf(columns.id) : -1;
  if (dateIdx < 0 || amountIdx < 0 || descIdx < 0) {
    throw new Error("card-csv-columns");
  }
  const rows: ChannelRow[] = [];
  for (const line of lines.slice(1)) {
    const cells = line.split(delimiter);
    const date = cells[dateIdx] ?? "";
    const amountRaw = cells[amountIdx] ?? "";
    const description = cells[descIdx] ?? "";
    const signed = parseCardAmount(amountRaw, decimal);
    const amountMinor = Math.abs(signed);
    const occurredAtMs = parseCardDate(date, dateFormat);
    const refHit = VERAX_REF.exec(description);
    const idCell = idIdx >= 0 ? (cells[idIdx] ?? "").trim() : "";
    const externalId =
      idCell !== ""
        ? idCell
        : createHash("sha256").update(`${date}|${amountRaw}|${description}`, "utf8").digest("hex");
    const row: ChannelRow = {
      channel: "card",
      externalId,
      occurredAtMs,
      subject: "spend",
      amountMinor,
      currency: opts.currency,
    };
    if (refHit) row.ref = refHit[1];
    if (signed > 0) row.credit = true;
    rows.push(row);
  }
  return rows;
}

export function parseChannelJsonl(text: string): ChannelRow[] {
  const rows: ChannelRow[] = [];
  let n = 0;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    n += 1;
    rows.push(asChannelRow(JSON.parse(line), n));
  }
  return rows;
}

/** Read-only: does not take ledger.lock. */
export function loadEffectsFromDir(stateDir: string): LedgerEffect[] {
  try {
    const text = readFileSync(join(stateDir, "effects.jsonl"), "utf8");
    const rows: LedgerEffect[] = [];
    for (const line of text.split("\n")) {
      if (line === "") continue;
      rows.push(JSON.parse(line) as LedgerEffect);
    }
    return rows;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

/**
 * Match a Sent-style channel export to ledger effects. Cedulon audit()
 * is not called; buckets use that vocabulary (ghost / unsent / outOfScope
 * are the unreconciled classes).
 */
function nearestEffectDtMs(row: ChannelRow, effects: readonly LedgerEffect[]): number | undefined {
  let best: number | undefined;
  for (const effect of effects) {
    const dt = Math.abs(row.occurredAtMs - effect.row.timestampMs);
    if (best === undefined || dt < best) best = dt;
  }
  return best;
}

function asGhost(row: ChannelRow, effects: readonly LedgerEffect[]): ChannelRow {
  const dt = nearestEffectDtMs(row, effects);
  return dt === undefined ? { ...row } : { ...row, nearestEffectDtMs: dt };
}

function approvalForEffect(approvals: readonly ApprovalRow[] | undefined, effectRef: string): ApprovalRow | undefined {
  if (!approvals) return undefined;
  return approvals.find((r) => r.allowRef === effectRef || r.ref === effectRef);
}

function effectAmount(
  effect: LedgerEffect,
  approvals: readonly ApprovalRow[] | undefined,
): { amountMinor?: number; currency?: string } {
  const snap = approvalForEffect(approvals, effect.row.ref);
  const amountMinor = snap && typeof snap.args.amountMinor === "number" ? snap.args.amountMinor : undefined;
  const currency = snap && typeof snap.args.currency === "string" ? snap.args.currency : undefined;
  return { amountMinor, currency };
}

function amountsClose(a?: number, b?: number): boolean {
  if (typeof a !== "number" || typeof b !== "number") return false;
  return Math.abs(a - b) <= 1;
}

export function reconcile(
  channelRows: readonly ChannelRow[],
  effects: readonly LedgerEffect[],
  opts?: { toleranceMs?: number; window?: { startMs: number; endMs: number }; approvals?: readonly ApprovalRow[] },
): ReconcileReport {
  const toleranceMs = opts?.toleranceMs ?? 60_000;
  if (channelRows.length === 0) {
    return {
      scope: { channel: "", windowStartMs: 0, windowEndMs: 0, rowCount: 0 },
      matched: [],
      ghost: [],
      unsent: effects.filter((e) => e.row.effectClass !== "spend").map((e) => e.row),
      authorizedUnpaid: effects.filter((e) => e.row.effectClass === "spend").map((e) => e.row),
      outOfScope: [],
    };
  }
  const channel = channelRows[0]!.channel;
  const times = channelRows.map((r) => r.occurredAtMs);
  const explicit = opts?.window;
  const windowStartMs = explicit ? explicit.startMs : Math.min(...times);
  const windowEndMs = explicit ? explicit.endMs : Math.max(...times);
  const used = new Set<number>();
  const matched: ReconcileReport["matched"] = [];
  const ghost: ChannelRow[] = [];
  const outOfScope: ChannelRow[] = [];

  for (const row of channelRows) {
    if (row.channel !== channel) {
      throw new Error(`channel-mixed:${row.channel}`);
    }
    if (row.credit === true) {
      outOfScope.push(row);
      continue;
    }
    if (explicit && (row.occurredAtMs < windowStartMs || row.occurredAtMs > windowEndMs)) {
      outOfScope.push(row);
      continue;
    }
    if (typeof row.ref === "string" && row.ref !== "") {
      const idx = effects.findIndex(
        (e, i) =>
          !used.has(i) &&
          (e.row.ref === row.ref ||
            opts?.approvals?.some((a) => a.ref === row.ref && a.allowRef === e.row.ref)),
      );
      if (idx === -1) {
        ghost.push(asGhost(row, effects));
        continue;
      }
      const dt = Math.abs(row.occurredAtMs - effects[idx]!.row.timestampMs);
      if (dt <= toleranceMs) {
        used.add(idx);
        matched.push({ channel: row, effect: effects[idx]!.row });
      } else {
        ghost.push(asGhost(row, effects));
      }
      continue;
    }
    const near = effects.findIndex((e, i) => {
      if (used.has(i) || e.row.effectClass !== row.subject) return false;
      if (Math.abs(row.occurredAtMs - e.row.timestampMs) > toleranceMs) return false;
      const fromSnap = effectAmount(e, opts?.approvals);
      if (fromSnap.amountMinor === undefined || fromSnap.currency === undefined) {
        return true;
      }
      return amountsClose(row.amountMinor, fromSnap.amountMinor) && row.currency === fromSnap.currency;
    });
    if (near !== -1) {
      used.add(near);
      matched.push({ channel: row, effect: effects[near]!.row });
      continue;
    }
    ghost.push(asGhost(row, effects));
  }

  const lo = windowStartMs - toleranceMs;
  const hi = windowEndMs + toleranceMs;
  const leftover = effects.filter((e, i) => !used.has(i) && e.row.timestampMs >= lo && e.row.timestampMs <= hi);
  const authorizedUnpaid = leftover.filter((e) => e.row.effectClass === "spend").map((e) => e.row);
  const unsent = leftover.filter((e) => e.row.effectClass !== "spend").map((e) => e.row);

  return {
    scope: { channel, windowStartMs, windowEndMs, rowCount: channelRows.length },
    matched,
    ghost,
    unsent,
    authorizedUnpaid,
    outOfScope,
  };
}
