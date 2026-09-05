export const TIER_COUNTS = [20_000, 10_000, 5_000] as const;

export type Quality = {
  readonly count: number;
  readonly tierIndex: number;
  push(frameMs: number): void;
};

function percentile95(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const i = Math.min(sorted.length - 1, Math.ceil(0.95 * sorted.length) - 1);
  return sorted[i] ?? 0;
}

/**
 * Two-second windows. Two slow P95s in a row step down; ten fast
 * windows step up. A single spike cannot move the tier.
 */
export function createQuality(now: () => number): Quality {
  let tierIndex = 0;
  let frames: number[] = [];
  let windowStart = now();
  let high = 0;
  let low = 0;

  const close = (): void => {
    if (frames.length === 0) {
      windowStart = now();
      return;
    }
    const p95 = percentile95(frames);
    if (p95 > 16.7) {
      high += 1;
      low = 0;
    } else if (p95 < 10) {
      low += 1;
      high = 0;
    } else {
      high = 0;
      low = 0;
    }
    if (high >= 2 && tierIndex < TIER_COUNTS.length - 1) {
      tierIndex += 1;
      high = 0;
    }
    if (low >= 10 && tierIndex > 0) {
      tierIndex -= 1;
      low = 0;
    }
    frames = [];
    windowStart = now();
  };

  return {
    get count() {
      return TIER_COUNTS[tierIndex] ?? TIER_COUNTS[TIER_COUNTS.length - 1];
    },
    get tierIndex() {
      return tierIndex;
    },
    push(frameMs: number) {
      frames.push(frameMs);
      if (now() - windowStart >= 2000) close();
    },
  };
}
