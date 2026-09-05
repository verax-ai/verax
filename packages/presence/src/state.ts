export const PRESENCE_STATES = [
  "booting",
  "idle",
  "listening",
  "thinking",
  "speaking",
  "acting",
  "awaiting-approval",
  "asleep",
] as const;

export type PresenceState = (typeof PRESENCE_STATES)[number];

export type StateParams = {
  budgetScale: number;
  coreColor: readonly [number, number, number];
  ringSpin: number;
  breathAmp: number;
  pullToChest: number;
};

export const TRANSITIONS: Record<PresenceState, readonly PresenceState[]> = {
  booting: ["idle"],
  idle: ["listening", "thinking", "acting", "awaiting-approval", "asleep"],
  listening: ["idle", "thinking", "speaking"],
  thinking: ["idle", "speaking", "acting", "awaiting-approval"],
  speaking: ["idle", "listening", "thinking"],
  acting: ["idle", "thinking", "awaiting-approval"],
  "awaiting-approval": ["idle", "acting", "asleep"],
  asleep: ["idle"],
};

/** Colours and motion from the phase-2 presence table. */
export const STATE_PARAMS: Record<PresenceState, StateParams> = {
  booting: { budgetScale: 1, coreColor: [0.25, 0.35, 0.55], ringSpin: 0.4, breathAmp: 0, pullToChest: 0 },
  idle: { budgetScale: 1, coreColor: [0.2, 0.45, 0.9], ringSpin: 0.15, breathAmp: 0.02, pullToChest: 0 },
  listening: { budgetScale: 1, coreColor: [0.15, 0.4, 1], ringSpin: 0.25, breathAmp: 0.03, pullToChest: 0.4 },
  thinking: { budgetScale: 1, coreColor: [1, 0.45, 0.1], ringSpin: 1.2, breathAmp: 0.02, pullToChest: 0 },
  speaking: { budgetScale: 1, coreColor: [0.35, 0.65, 1], ringSpin: 0.8, breathAmp: 0.08, pullToChest: 0 },
  acting: { budgetScale: 1, coreColor: [1, 1, 1], ringSpin: 0.35, breathAmp: 0.01, pullToChest: 0.2 },
  "awaiting-approval": { budgetScale: 0.85, coreColor: [1, 0.85, 0.15], ringSpin: 0, breathAmp: 0, pullToChest: 0.15 },
  asleep: { budgetScale: 0.35, coreColor: [0.06, 0.08, 0.12], ringSpin: 0, breathAmp: 0, pullToChest: 0 },
};

const BOOT_MS = 4000;

export type Presence = {
  readonly state: PresenceState;
  params(): StateParams;
  transition(next: PresenceState): void;
};

export function createPresence(now: () => number, start: PresenceState = "booting"): Presence {
  let current: PresenceState = start;
  const bootStartedMs = now();

  const settle = (): PresenceState => {
    if (start === "booting" && current === "booting" && now() - bootStartedMs >= BOOT_MS) {
      current = "idle";
    }
    return current;
  };

  return {
    get state() {
      return settle();
    },
    params() {
      return STATE_PARAMS[settle()];
    },
    transition(next: PresenceState) {
      const from = settle();
      if (!TRANSITIONS[from].includes(next)) {
        throw new Error(`illegal-transition:${from}->${next}`);
      }
      current = next;
    },
  };
}
