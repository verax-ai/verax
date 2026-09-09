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

export type TimelineGroup = {
  key: string;
  refs: string[];
  leftPx: number;
  label: string;
  title: string;
  count: number;
};

/** Time of day, for a strip whose records all fall on one UTC day. */
export function shortStamp(ms: number): string {
  const full = formatStamp(ms);
  const t = full.indexOf("T");
  return t === -1 ? full : full.slice(t + 1);
}

export function sameUtcDay(marks: readonly TimelineMark[]): boolean {
  if (marks.length === 0) return true;
  const day = (ms: number) => formatStamp(ms).slice(0, 10);
  const first = day(marks[0]!.timestampMs);
  return marks.every((m) => day(m.timestampMs) === first);
}

/**
 * Lay the marks out in pixels and fold the ones that would print on top of
 * each other into a single mark that says how many it stands for. Positions
 * stay the records' own; crowding is measured on the boxes, not guessed, and
 * a fold is declared on the strip rather than hidden behind a clipped label.
 *
 * A track of unknown width means nothing was measured, so nothing is folded:
 * the caller gets one group per mark and can place them by percentage.
 */
export function timelineGroups(
  marks: readonly TimelineMark[],
  trackWidthPx: number,
  markWidthPx: number,
  short: boolean,
): TimelineGroup[] {
  const stamp = (ms: number) => (short ? shortStamp(ms) : formatStamp(ms));
  const rows = [...marks].sort((a, b) => a.timestampMs - b.timestampMs);
  if (trackWidthPx <= 0 || markWidthPx <= 0) {
    return rows.map((m) => ({
      key: m.ref,
      refs: [m.ref],
      leftPx: -1,
      label: stamp(m.timestampMs),
      title: formatStamp(m.timestampMs),
      count: 1,
    }));
  }
  const span = Math.max(trackWidthPx - markWidthPx, 0);
  const out: { refs: string[]; times: number[]; leftPx: number }[] = [];
  for (const m of rows) {
    const leftPx = Math.min(Math.max((m.leftPct / 100) * span, 0), span);
    const last = out[out.length - 1];
    if (last && leftPx - last.leftPx < markWidthPx) {
      last.refs.push(m.ref);
      last.times.push(m.timestampMs);
      continue;
    }
    out.push({ refs: [m.ref], times: [m.timestampMs], leftPx });
  }
  return out.map((g) => ({
    key: g.refs[0]!,
    refs: g.refs,
    leftPx: g.leftPx,
    label: g.refs.length === 1 ? stamp(g.times[0]!) : String(g.refs.length),
    title: g.times.map((t) => formatStamp(t)).join(" · "),
    count: g.refs.length,
  }));
}
