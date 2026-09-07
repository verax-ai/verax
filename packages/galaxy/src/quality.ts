export const TIER_DUST = [20_000, 10_000, 5_000] as const;

/** UnrealBloomPass(strength, radius, threshold) — tried values from the cockpit. */
export const BLOOM_FULL = { strength: 1.8, radius: 0.4, threshold: 0.35 } as const;
export const BLOOM_MID = { strength: 0.9, radius: 0.35, threshold: 0.5 } as const;
export const BLOOM_OFF = { strength: 0, radius: 0.4, threshold: 1 } as const;

export type BloomTune = {
  readonly strength: number;
  readonly radius: number;
  readonly threshold: number;
};

export type GalaxyTier = {
  readonly index: number;
  readonly dust: number;
  readonly bloom: BloomTune;
};

/**
 * Quality ladder. A slower machine drops dust and bloom.
 * Record counts (stars, planets, agents) are never trimmed here.
 */
export function galaxyTier(index: number): GalaxyTier {
  const i = Math.max(0, Math.min(TIER_DUST.length - 1, Math.floor(index)));
  const bloom = i === 0 ? BLOOM_FULL : i === 1 ? BLOOM_MID : BLOOM_OFF;
  return { index: i, dust: TIER_DUST[i] ?? TIER_DUST[TIER_DUST.length - 1], bloom };
}

export function readForcedTier(search = ""): number | null {
  const raw = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search).get("tier");
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  const exact = (TIER_DUST as readonly number[]).indexOf(n as (typeof TIER_DUST)[number]);
  if (exact !== -1) return exact;
  // Harness still says 15000 (old presence count). Snap to the nearest
  // dust knob; a tie prefers the smaller cloud so the budget is not ignored.
  let best = 0;
  let dist = Math.abs((TIER_DUST[0] ?? 0) - n);
  for (let i = 1; i < TIER_DUST.length; i += 1) {
    const dust = TIER_DUST[i] ?? 0;
    const d = Math.abs(dust - n);
    if (d < dist || (d === dist && dust < (TIER_DUST[best] ?? 0))) {
      dist = d;
      best = i;
    }
  }
  return best;
}
