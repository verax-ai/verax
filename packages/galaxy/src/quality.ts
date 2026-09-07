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
  return (TIER_DUST as readonly number[]).includes(n) ? TIER_DUST.indexOf(n as (typeof TIER_DUST)[number]) : null;
}
