import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", ".github", "workflows");
const workflows = readdirSync(dir)
  .filter((n) => n.endsWith(".yml"))
  .map((n) => ({ name: n, text: readFileSync(join(dir, n), "utf8") }));

/**
 * The commits of actions/checkout v4, actions/setup-node v4 and
 * actions/upload-artifact v4. Every run on main printed "Node.js 20 is
 * deprecated ... forced to run on Node.js 24" for the first two; v5 of each
 * runs on Node 24 by itself. The pins moved on 16 Sep 2026 and must not
 * drift back, in any workflow.
 */
const NODE_20_COMMITS = [
  "11d5960a326750d5838078e36cf38b85af677262",
  "49933ea5288caeca8642d1e84afbd3f7d6820020",
  "ea165f8d65b6e75b540449e92b4886f43607fa02",
];

describe("workflow pins", () => {
  it("finds the workflows", () => {
    assert.ok(workflows.length >= 6, `only ${workflows.length} workflows under .github/workflows`);
  });

  it("pins every action in every workflow to a commit, with the version beside it", () => {
    // release.yml already held this; the other five did not, and a tag pin
    // added to any of them would have passed the suite.
    for (const { name, text } of workflows) {
      const uses = [...text.matchAll(/uses: ([^@\s]+)@(\S+)(.*)$/gm)];
      assert.ok(uses.length > 0, `${name} uses no action`);
      for (const m of uses) {
        assert.match(m[2]!, /^[0-9a-f]{40}$/, `${name}: ${m[1]} is not pinned to a commit`);
        assert.match(m[3]!, /#\s*v\d/, `${name}: ${m[1]} does not say which version the commit is`);
      }
    }
  });

  it("no workflow still runs an action GitHub flagged as Node 20", () => {
    for (const { name, text } of workflows) {
      for (const sha of NODE_20_COMMITS) {
        assert.equal(text.includes(sha), false, `${name} still pins ${sha.slice(0, 8)}, a Node 20 build`);
      }
    }
  });
});
