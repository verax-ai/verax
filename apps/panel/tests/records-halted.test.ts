import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { chainFor } from "../src/blackbox/recorder.ts";
import { kindOf, statusWord } from "../src/records/line.ts";
import type { RailAction } from "../src/rail/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const en = JSON.parse(readFileSync(join(here, "..", "src", "copy", "en.json"), "utf8")) as Record<string, string>;
const tr = JSON.parse(readFileSync(join(here, "..", "src", "copy", "tr.json"), "utf8")) as Record<string, string>;

function haltedAllow(): RailAction {
  return {
    record: {
      claims: {
        subject: "memory.get",
        decision: "allow",
        reasonCode: "rule",
        timestampMs: 1,
        decider: "verax-proxy",
        ref: "halt-1",
        policyHash: "f7",
        effectHash: "ed",
      },
    },
    effect: {
      row: {
        ref: "halt-1",
        effectClass: "memory.get:halted",
        effectHash: "ed",
        timestampMs: 2,
      },
    },
    rule: { id: "get", tool: "memory.get", text: "read" },
    finding: null,
  };
}

describe("panel :halted is its own outcome", () => {
  it("kindOf and statusWord name halted in every language", () => {
    const action = haltedAllow();
    assert.equal(kindOf(action), "halted");
    assert.equal(statusWord(en, "halted"), en["status.halted"]);
    assert.equal(statusWord(tr, "halted"), tr["status.halted"]);
    assert.notEqual(en["status.halted"], tr["status.halted"]);
    assert.notEqual(en["rec.say.effect.halted"], tr["rec.say.effect.halted"]);
    assert.match(tr["rec.say.effect.halted"], /çalışmadı|durduruldu/);
  });

  it("the chain says the tool did not run because it was halted", () => {
    const action = haltedAllow();
    const links = chainFor(action, [action], []);
    const effect = links.find((link) => link.id === "effect");
    assert.equal(effect?.say, "effect.halted");
    assert.equal(effect?.state, "stopped");
    assert.notEqual(effect?.say, "effect");
  });
});
