import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { EffectRow } from "@cedulon/effect-extract";

import type { LedgerEffect } from "./types.ts";

export type ChannelRow = {
  channel: string;
  externalId: string;
  occurredAtMs: number;
  subject: string;
  actor?: string;
  ref?: string;
  nearestEffectDtMs?: number;
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
  return row;
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

export function reconcile(
  channelRows: readonly ChannelRow[],
  effects: readonly LedgerEffect[],
  opts?: { toleranceMs?: number; window?: { startMs: number; endMs: number } },
): ReconcileReport {
  const toleranceMs = opts?.toleranceMs ?? 60_000;
  if (channelRows.length === 0) {
    return {
      scope: { channel: "", windowStartMs: 0, windowEndMs: 0, rowCount: 0 },
      matched: [],
      ghost: [],
      unsent: effects.map((e) => e.row),
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
    if (explicit && (row.occurredAtMs < windowStartMs || row.occurredAtMs > windowEndMs)) {
      outOfScope.push(row);
      continue;
    }
    if (typeof row.ref === "string" && row.ref !== "") {
      const idx = effects.findIndex((e, i) => !used.has(i) && e.row.ref === row.ref);
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
    const near = effects.findIndex(
      (e, i) =>
        !used.has(i) &&
        e.row.effectClass === row.subject &&
        Math.abs(row.occurredAtMs - e.row.timestampMs) <= toleranceMs,
    );
    if (near !== -1) {
      used.add(near);
      matched.push({ channel: row, effect: effects[near]!.row });
      continue;
    }
    ghost.push(asGhost(row, effects));
  }

  const lo = windowStartMs - toleranceMs;
  const hi = windowEndMs + toleranceMs;
  const unsent = effects
    .filter((e, i) => !used.has(i) && e.row.timestampMs >= lo && e.row.timestampMs <= hi)
    .map((e) => e.row);

  return {
    scope: { channel, windowStartMs, windowEndMs, rowCount: channelRows.length },
    matched,
    ghost,
    unsent,
    outOfScope,
  };
}
