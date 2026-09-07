import { isMeasured, type Measured } from "./measured.ts";

/** Purple / dim mark for a field that has no measured value. Not a fallback number. */
export const UNMEASURED_RGB = { r: 0.3, g: 0.16, b: 0.42 } as const;
export const UNMEASURED_HEX = 0x4d296b;
export const UNMEASURED_BRIGHTNESS = 0.22;

export type Rgb = { readonly r: number; readonly g: number; readonly b: number };

export type Appearance = {
  readonly size: number;
  readonly brightness: number;
  readonly color: Rgb;
  readonly unmeasured: boolean;
};

export type CoreDraw = {
  pulse: Measured<number>;
  label: string;
};

export type PlanetDraw = {
  id: string;
  label: string;
  size: Measured<number>;
  freshness: Measured<number>;
  ring?: Measured<number>;
};

export type AgentDraw = {
  id: string;
  label: string;
  lastActMs: Measured<number>;
  witness?: "self" | "same-org";
};

export type StarDraw = {
  id: string;
  planetId: string | null;
  at: number;
  kind: string;
  flag?: "deny" | "ghost" | "reauth";
};

function markUnmeasured(): Appearance {
  return {
    size: 1,
    brightness: UNMEASURED_BRIGHTNESS,
    color: UNMEASURED_RGB,
    unmeasured: true,
  };
}

/**
 * Core pulse → scale. Unmeasured pulse is the purple mark; it does not
 * become a quiet default heartbeat.
 */
export function coreAppearance(input: CoreDraw): Appearance {
  if (!isMeasured(input.pulse)) return markUnmeasured();
  const t = Math.max(0, input.pulse.value);
  return {
    size: 1.4 + Math.min(1, t) * 0.8,
    brightness: 0.55 + Math.min(1, t) * 0.45,
    color: { r: 0.95, g: 0.86, b: 0.62 },
    unmeasured: false,
  };
}

/**
 * Planet size and freshness both have to be measured to light the body.
 * A missing size or freshness is the same purple mark — never a guessed radius.
 */
export function planetAppearance(input: PlanetDraw): Appearance {
  if (!isMeasured(input.size) || !isMeasured(input.freshness)) return markUnmeasured();
  const count = Math.max(0, input.size.value);
  const fresh = Math.max(0, Math.min(1, input.freshness.value));
  return {
    size: 0.9 + Math.sqrt(count) * 0.18,
    brightness: 0.35 + fresh * 0.55,
    color: {
      r: 0.45 + fresh * 0.4,
      g: 0.55 + fresh * 0.3,
      b: 0.85,
    },
    unmeasured: false,
  };
}

export function planetRingAppearance(ring: Measured<number>): Appearance {
  if (!isMeasured(ring)) return markUnmeasured();
  const t = Math.max(0, Math.min(1, ring.value));
  return {
    size: 1.15 + t * 0.35,
    brightness: 0.2 + t * 0.5,
    color: { r: 0.7, g: 0.78, b: 0.95 },
    unmeasured: false,
  };
}

/**
 * Agent activity. Unmeasured last-act is grey/dim, not "recent".
 */
export function agentAppearance(input: AgentDraw): Appearance {
  if (!isMeasured(input.lastActMs)) {
    return {
      size: 0.62,
      brightness: UNMEASURED_BRIGHTNESS,
      color: { r: 0.45, g: 0.47, b: 0.5 },
      unmeasured: true,
    };
  }
  return {
    size: 0.62,
    brightness: 0.7,
    color: { r: 0.72, g: 0.82, b: 0.95 },
    unmeasured: false,
  };
}

export function starFlagColor(flag: StarDraw["flag"]): Rgb | null {
  if (flag === "deny") return { r: 0.92, g: 0.22, b: 0.28 };
  if (flag === "ghost") return { r: 0.85, g: 0.35, b: 0.15 };
  if (flag === "reauth") return { r: 0.95, g: 0.72, b: 0.2 };
  return null;
}
