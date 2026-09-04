import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { loadPolicy } from "../src/policy.ts";
import { parsePolicyDocument, ruleTextHash } from "../src/policy.ts";
import type { Principal } from "../src/types.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyPath = join(root, "policy", "default.json");
const fixtureDir = join(root, "tests", "fixtures", "policy");

type Fixture = {
  textHash: string;
  call: { name: string; arguments: Record<string, unknown> };
  principal: { brain: string; scopes: string[] };
  expected: { decision: string; reasonCode: string; rule: string | null };
};

describe("policy fixtures", () => {
  const document = parsePolicyDocument(readFileSync(policyPath, "utf8"));
  const policy = loadPolicy(document);
  const files = readdirSync(fixtureDir).filter((n) => n.endsWith(".json"));

  it("every rule has a fixture file named after its id", () => {
    const ids = new Set(files.map((n) => n.replace(/\.json$/, "")));
    for (const rule of document.rules) {
      assert.ok(ids.has(rule.id), `missing fixture for rule ${rule.id}`);
    }
  });

  it("each fixture textHash matches the live rule text", () => {
    for (const name of files) {
      const fx = JSON.parse(readFileSync(join(fixtureDir, name), "utf8")) as Fixture;
      const id = name.replace(/\.json$/, "");
      const rule = document.rules.find((r) => r.id === id);
      assert.ok(rule, `no rule ${id}`);
      assert.equal(fx.textHash, ruleTextHash(rule.text), `textHash stale for ${id}`);
    }
  });

  it("each fixture evaluates to the recorded decision", () => {
    for (const name of files) {
      const fx = JSON.parse(readFileSync(join(fixtureDir, name), "utf8")) as Fixture;
      const principal: Principal = {
        brain: fx.principal.brain,
        scopes: new Set(fx.principal.scopes),
      };
      const got = policy.evaluate(fx.call, principal);
      assert.deepEqual(got, fx.expected, name);
    }
  });

  it("refuses a missing text and a non-deny default", () => {
    assert.throws(
      () =>
        loadPolicy({
          version: 1,
          default: "deny",
          rules: [{ id: "x", tool: "x", requires: ["verax:read"], text: "" }],
        }),
      /policy-rule-text/,
    );
    assert.throws(
      () => loadPolicy({ version: 1, default: "allow", rules: [] }),
      /policy-default-not-deny/,
    );
  });

  it("denies spend by name before any rule", () => {
    const got = policy.evaluate(
      { name: "spend", arguments: { amount: "1" } },
      { brain: "brain-1", scopes: new Set(["verax:pay"]) },
    );
    assert.deepEqual(got, { decision: "deny", reasonCode: "spend-not-wired", rule: null });
  });
});
