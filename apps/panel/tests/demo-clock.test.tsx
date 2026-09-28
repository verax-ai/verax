import { describe, expect, it } from "vitest";

import { layTape } from "../src/blackbox/recorder.ts";
import { loadDemoActions, loadDemoAgents } from "../src/observatory/demo.ts";

/**
 * The sample borrows the golden ledger, whose clock starts at 10 ms. Left as
 * it is, the tape drew a 56-year silence between 1970 and the spend and the
 * status tab named 1970 as an agent's last activity. The sample moves those
 * rows next to its own spend; this holds it there.
 */
describe("the sample's clock", () => {
  const since2026 = Date.UTC(2026, 0, 1);

  it("puts every decision and effect in the sample's own year", () => {
    for (const action of loadDemoActions()) {
      expect(action.record.claims.timestampMs).toBeGreaterThanOrEqual(since2026);
      if (action.effect) expect(action.effect.row.timestampMs).toBeGreaterThanOrEqual(since2026);
    }
    expect(loadDemoAgents().fromMs).toBeGreaterThanOrEqual(since2026);
  });

  it("draws one continuous tape, with no break for a silence the sample never had", () => {
    expect(layTape(loadDemoActions()).breaks).toEqual([]);
  });
});
