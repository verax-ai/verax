import type { RailAction } from "../rail/types.ts";

export type TimelineMark = {
  ref: string;
  timestampMs: number;
  leftPct: number;
  stamp: string;
};

export function formatStamp(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "not measured";
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Place marks from the records' own timestamps. No fake ruler: a sparse
 * ledger stays sparse. A single stamp sits at the start, not in a
 * invented middle.
 */
export function timelineMarks(actions: readonly RailAction[]): TimelineMark[] {
  const rows = actions
    .map((a) => {
      const ref = a.record.claims.ref;
      if (!ref) return null;
      return { ref, timestampMs: a.record.claims.timestampMs };
    })
    .filter((row): row is { ref: string; timestampMs: number } => row !== null);
  if (rows.length === 0) return [];
  const times = rows.map((r) => r.timestampMs);
  const min = Math.min(...times);
  const max = Math.max(...times);
  const span = max - min;
  return rows.map((r) => ({
    ref: r.ref,
    timestampMs: r.timestampMs,
    leftPct: span === 0 ? 0 : ((r.timestampMs - min) / span) * 100,
    stamp: formatStamp(r.timestampMs),
  }));
}
