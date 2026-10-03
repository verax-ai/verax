import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runVerify } from "../packages/body/src/verify-cli.ts";
import { runVectors } from "../test-vectors/tools/run.ts";
import { STAGES } from "../test-vectors/tools/stages.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = join(root, "test-vectors");

function walk(rel: string): string[] {
  return readdirSync(join(vectors, rel), { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(posix.join(rel, entry.name)) : [posix.join(rel, entry.name)],
  );
}

type Manifest = {
  version: string;
  stability: string;
  stages: string[];
  vectors: { id: string; dir: string; expected_result: string; first_failing_stage: string | null }[];
};

/**
 * Published vectors are pinned by other implementers. v1 is append-only: a
 * file under it never changes once merged, and every file is listed in
 * SHA256SUMS. A correction is a new vector or a new version directory.
 */
describe("test vectors v1", () => {
  it("every published file is listed in SHA256SUMS and still has that digest", () => {
    const listed = new Map<string, string>();
    for (const line of readFileSync(join(vectors, "SHA256SUMS"), "utf8").split("\n")) {
      if (line === "") continue;
      const match = /^([0-9a-f]{64}) {2}(v1\/\S+)$/.exec(line);
      assert.ok(match, `SHA256SUMS line is not '<sha256>  v1/<path>': ${line}`);
      listed.set(match[2]!, match[1]!);
    }
    const present = walk("v1").sort();
    assert.deepEqual(present, [...listed.keys()].sort(), "files under v1 and SHA256SUMS differ");
    for (const file of present) {
      const digest = createHash("sha256").update(readFileSync(join(vectors, file))).digest("hex");
      assert.equal(digest, listed.get(file), `${file} changed after it was published`);
    }
  });

  it("the manifest names every vector directory once, with the stage its expected.json names", () => {
    const manifest = JSON.parse(readFileSync(join(vectors, "manifest.json"), "utf8")) as Manifest;
    assert.equal(manifest.version, "v1");
    assert.equal(manifest.stability, "append-only");
    assert.deepEqual(manifest.stages, [...STAGES]);
    const dirs = readdirSync(join(vectors, "v1")).sort();
    assert.deepEqual(manifest.vectors.map((v) => v.id).sort(), dirs);
    for (const v of manifest.vectors) {
      assert.equal(v.dir, `v1/${v.id}`);
      const expected = JSON.parse(readFileSync(join(vectors, v.dir, "expected.json"), "utf8")) as {
        expected_result: string;
        first_failing_stage: string | null;
      };
      assert.equal(expected.expected_result, v.expected_result, v.id);
      assert.equal(expected.first_failing_stage, v.first_failing_stage, v.id);
      assert.equal(v.expected_result, v.first_failing_stage === null ? "VALID" : "INVALID", v.id);
      if (v.first_failing_stage !== null) assert.ok((STAGES as readonly string[]).includes(v.first_failing_stage), v.id);
    }
  });

  it("verax verify reaches every expected verdict and first failing stage", async () => {
    // In process rather than as a child: on an elevated runner the CLI refuses a
    // child of this checkout before any command runs (R15-1). The verdicts come
    // from the same runVerify the CLI calls.
    const outcomes = await runVectors(async (args) => {
      const out: string[] = [];
      const status = await runVerify(args, (line) => out.push(line));
      return { status, stdout: out.join("\n"), stderr: "" };
    });
    const missed = outcomes.filter((o) => !o.match);
    assert.deepEqual(missed, [], JSON.stringify(missed, null, 2));
    assert.equal(outcomes.length, 16);
  });
});
