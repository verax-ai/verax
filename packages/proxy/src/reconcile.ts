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
export function reconcile(
  channelRows: readonly ChannelRow[],
  effects: readonly LedgerEffect[],
  opts?: { toleranceMs?: number },
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
  const windowStartMs = Math.min(...times);
  const windowEndMs = Math.max(...times);
  const used = new Set<number>();
  const matched: ReconcileReport["matched"] = [];
  const ghost: ChannelRow[] = [];
  const outOfScope: ChannelRow[] = [];

  for (const row of channelRows) {
    if (row.channel !== channel) {
      throw new Error(`channel-mixed:${row.channel}`);
    }
    if (typeof row.ref === "string" && row.ref !== "") {
      const idx = effects.findIndex((e, i) => !used.has(i) && e.row.ref === row.ref);
      if (idx === -1) {
        ghost.push(row);
        continue;
      }
      const dt = Math.abs(row.occurredAtMs - effects[idx]!.row.timestampMs);
      if (dt <= toleranceMs) {
        used.add(idx);
        matched.push({ channel: row, effect: effects[idx]!.row });
      } else {
        outOfScope.push(row);
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
    if (effects.some((e) => e.row.effectClass === row.subject)) {
      outOfScope.push(row);
    } else {
      ghost.push(row);
    }
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
