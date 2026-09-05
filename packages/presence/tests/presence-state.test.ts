import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  createPresence,
  PRESENCE_STATES,
  TRANSITIONS,
  type Presence,
  type PresenceState,
} from "../src/state.ts";

const FROM_IDLE: Record<Exclude<PresenceState, "booting" | "idle">, PresenceState[]> = {
  listening: ["listening"],
  thinking: ["thinking"],
  speaking: ["listening", "speaking"],
  acting: ["acting"],
  "awaiting-approval": ["thinking", "awaiting-approval"],
  asleep: ["asleep"],
};

function at(from: PresenceState): Presence {
  if (from === "booting") return createPresence(() => 0);
  const clock = { t: 0 };
  const p = createPresence(() => clock.t);
  clock.t = 4000;
  if (from === "idle") return p;
  for (const step of FROM_IDLE[from]) p.transition(step);
  return p;
}

describe("presence state machine", () => {
  it("allows listed transitions and throws on the rest", () => {
    for (const from of PRESENCE_STATES) {
      for (const to of PRESENCE_STATES) {
        const p = at(from);
        assert.equal(p.state, from);
        const allowed = TRANSITIONS[from].includes(to);
        if (allowed) {
          p.transition(to);
          assert.equal(p.state, to);
        } else {
          assert.throws(() => p.transition(to), /illegal-transition/);
        }
      }
    }
  });

  it("moves booting to idle at 4000 ms", () => {
    const clock = { t: 0 };
    const p = createPresence(() => clock.t);
    assert.equal(p.state, "booting");
    clock.t = 3999;
    assert.equal(p.state, "booting");
    clock.t = 4000;
    assert.equal(p.state, "idle");
  });
});
