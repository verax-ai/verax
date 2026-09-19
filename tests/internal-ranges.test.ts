import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

/**
 * `@verax-ai/body` names `@verax-ai/proxy` and `@verax-ai/inventory` as
 * dependencies. Through 0.1.4 it named them `^0.1.0`, which is a promise that
 * any 0.1.x will do. It was not true: body 0.1.4 imports `verifyLedger`, which
 * exists only in proxy 0.1.4 and later.
 *
 * Measured, not inferred: body 0.1.4 installed beside proxy 0.1.3 — which the
 * published range permits — fails at startup with
 *
 *   SyntaxError: The requested module '@verax-ai/proxy' does not provide an
 *   export named 'verifyLedger'
 *
 * and it takes the whole CLI with it, `--help` included, because the import
 * sits at the top of the entry. The path there is ordinary: a project that
 * installed 0.1.3 and then upgrades with `npm install @verax-ai/body@0.1.4`
 * keeps the proxy it already has, since that proxy still satisfies the range.
 * A fresh install never shows it, which is how it went unseen.
 *
 * The three packages ship together and are built against each other, so the
 * only range that is true is the version they ship at. This holds each
 * internal range to exactly `^<that package's own version>`.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function manifest(dir: string): {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
} {
  return JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
}

describe("internal dependency ranges name the version they were built against", () => {
  const body = manifest("packages/body");
  const internal = Object.entries(body.dependencies ?? {}).filter(([name]) => name.startsWith("@verax-ai/"));

  it("body has internal dependencies to check", () => {
    assert.ok(internal.length >= 2, `expected proxy and inventory, found ${internal.map(([n]) => n).join(", ")}`);
  });

  for (const [name, range] of internal) {
    it(`${name} is required at exactly ^<its own version>, not at any earlier release`, () => {
      const dir = `packages/${name.replace("@verax-ai/", "")}`;
      const shipped = manifest(dir).version;
      assert.equal(
        range,
        `^${shipped}`,
        `body accepts ${name}@${range} but the tree builds against ${shipped}; an older ${name} ` +
          `would satisfy the range and break body at startup`,
      );
    });
  }

  it("the three packages carry one version, so that rule has a single answer", () => {
    const versions = ["packages/body", "packages/proxy", "packages/inventory"].map((d) => manifest(d).version);
    assert.deepEqual([...new Set(versions)], [versions[0]], `versions differ: ${versions.join(", ")}`);
  });
});
