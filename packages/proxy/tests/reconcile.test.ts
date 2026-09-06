import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { parseChannelJsonl, reconcile } from "../src/reconcile.ts";
import type { LedgerEffect } from "../src/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const goldenEffects = join(here, "fixtures", "ledger-golden", "effects.jsonl");
const sentPath = join(here, "fixtures", "channel-sent.jsonl");

function loadEffects(): LedgerEffect[] {
  return readFileSync(goldenEffects, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as LedgerEffect);
}

describe("reconcile channel export against the ledger", () => {
  it("sent fixture: 3 matched, 1 ghost, 1 unsent, 1 outOfScope; scope window is min/max", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    assert.equal(channel.length, 5);
    const report = reconcile(channel, loadEffects());
    assert.deepEqual(report.scope, {
      channel: "sent",
      windowStartMs: 20,
      windowEndMs: 180100,
      rowCount: 5,
    });
    assert.equal(report.matched.length, 3);
    assert.deepEqual(
      report.matched.map((m) => m.effect.ref),
      ["n1", "n2", "n3"],
    );
    assert.equal(report.ghost.length, 1);
    assert.equal(report.ghost[0]?.externalId, "msg-ghost");
    assert.equal(report.unsent.length, 1);
    assert.equal(report.unsent[0]?.ref, "n6");
    assert.equal(report.outOfScope.length, 1);
    assert.equal(report.outOfScope[0]?.externalId, "msg-far");
  });

  it("a class match outside toleranceMs is outOfScope, not ghost", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    const tight = reconcile(channel, loadEffects(), { toleranceMs: 1 });
    assert.ok(tight.outOfScope.some((r) => r.externalId === "msg-far"));
    const loose = reconcile(channel, loadEffects(), { toleranceMs: 200_000 });
    assert.equal(
      loose.outOfScope.some((r) => r.externalId === "msg-far"),
      false,
    );
    assert.ok(loose.matched.some((m) => m.effect.ref === "n6"));
  });
});
