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
  it("sent fixture: 3 matched, 2 ghost, 1 unsent, 0 outOfScope; msg-far is ghost", () => {
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
    assert.equal(report.ghost.length, 2);
    assert.deepEqual(
      report.ghost.map((g) => g.externalId).sort(),
      ["msg-far", "msg-ghost"],
    );
    assert.equal(
      report.ghost.find((g) => g.externalId === "msg-far")?.nearestEffectDtMs !== undefined,
      true,
    );
    assert.equal(report.unsent.length, 1);
    assert.equal(report.unsent[0]?.ref, "n6");
    assert.equal(report.outOfScope.length, 0);
  });

  it("a class match outside toleranceMs is ghost when no explicit window", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    const tight = reconcile(channel, loadEffects(), { toleranceMs: 1 });
    assert.equal(tight.outOfScope.length, 0);
    assert.ok(tight.ghost.some((r) => r.externalId === "msg-far"));
    const loose = reconcile(channel, loadEffects(), { toleranceMs: 200_000 });
    assert.equal(
      loose.ghost.some((r) => r.externalId === "msg-far"),
      false,
    );
    assert.ok(loose.matched.some((m) => m.effect.ref === "n6"));
  });

  it("an explicit window puts rows outside it in outOfScope", () => {
    const channel = parseChannelJsonl(readFileSync(sentPath, "utf8"));
    const report = reconcile(channel, loadEffects(), { window: { startMs: 20, endMs: 60 } });
    assert.deepEqual(report.scope, {
      channel: "sent",
      windowStartMs: 20,
      windowEndMs: 60,
      rowCount: 5,
    });
    assert.equal(report.outOfScope.length, 1);
    assert.equal(report.outOfScope[0]?.externalId, "msg-far");
    assert.ok(report.ghost.some((r) => r.externalId === "msg-ghost"));
    assert.equal(
      report.ghost.some((r) => r.externalId === "msg-far"),
      false,
    );
  });
});
