import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { loadPolicy } from "@verax-ai/proxy";
import { persistPolicySnapshot, readPolicySnapshots } from "../packages/body/src/policy-store.ts";

// Up to 0.4.8 the parser dropped unknown keys, and the body stored the policy
// file as written. A state directory can therefore hold a snapshot with a key
// the parser now refuses, under the hash of the document without it. The
// operator's policy is refused; a snapshot already on disk is still read.

const clean = {
  version: 1,
  default: "deny",
  rules: [{ id: "r1", tool: "fs.read", requires: [], text: "read files" }],
};
const withNote = { ...clean, note: "written by hand" };

function stateWithOldSnapshot(): { stateDir: string; hash: string } {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-snap-keys-"));
  const hash = loadPolicy(clean).hash;
  mkdirSync(join(stateDir, "policies"), { recursive: true });
  writeFileSync(join(stateDir, "policies", `${hash}.json`), `${JSON.stringify(withNote)}\n`);
  return { stateDir, hash };
}

describe("policy snapshots written before unknown keys were refused", () => {
  it("the operator's policy with the extra key is refused", () => {
    assert.throws(() => loadPolicy(withNote), /^Error: policy-unknown-key:note$/);
  });

  it("the cleaned policy starts against the old snapshot of the same hash", () => {
    const { stateDir, hash } = stateWithOldSnapshot();
    try {
      assert.doesNotThrow(() => persistPolicySnapshot(stateDir, hash, clean));
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("the old snapshot is still offered as the historical policy", () => {
    const { stateDir, hash } = stateWithOldSnapshot();
    try {
      assert.deepEqual(Object.keys(readPolicySnapshots(stateDir, [hash])), [hash]);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
