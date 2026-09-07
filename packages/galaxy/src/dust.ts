import { hash01 } from "./address.ts";
import { galaxyTier } from "./quality.ts";

/**
 * Depth dust. The count is a quality knob, not a record count.
 * It must not be derived from stars, planets, or agents.
 */
export function dustCount(tierIndex: number): number {
  return galaxyTier(tierIndex).dust;
}

function unit(seed: string): number {
  return hash01(seed);
}

/** Deterministic positions. Same tier + radius → same cloud. Not a tally. */
export function dustPositions(tierIndex: number, radius: number): Float32Array {
  const n = dustCount(tierIndex);
  const out = new Float32Array(n * 3);
  for (let i = 0; i < n; i += 1) {
    const u = unit(`dust:${i}:u`);
    const v = unit(`dust:${i}:v`);
    const w = unit(`dust:${i}:w`);
    const r = radius * (0.35 + u * 1.4);
    const th = v * Math.PI * 2;
    const ph = Math.acos(Math.min(1, Math.max(-1, 2 * w - 1)));
    out[i * 3] = r * Math.sin(ph) * Math.cos(th);
    out[i * 3 + 1] = r * Math.cos(ph) * 0.28;
    out[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
  }
  return out;
}
