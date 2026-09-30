import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// @ts-expect-error -- a plain .mjs script with no declaration file
import { guardedNames, resolvesInTree, REVIEWED, scan } from "../scripts/optional-require-guard.mjs";

type Finding = { pkg: string; file: string; name: string; reviewed: boolean };
type Reviewed = { pkg: string; file: string; name: string };

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");

// Every module cli.ts imports, from source, so the check does not need a build.
const BODY_MODULES = [
  "approve-cli",
  "body-log",
  "demo",
  "doctor",
  "init-local",
  "install",
  "halt",
  "main",
  "operator-cli",
  "reconcile-cli",
  "verify-cli",
  "unlock",
  "witness",
  "server",
  "wiring",
  "downstream",
];

/**
 * R26 F-I1: a guarded require of a name the tree does not ship is the one
 * thing that makes a planted C:\node_modules load. The install refuses a
 * planted directory it can see; this closes the precondition, and says so
 * when a dependency bump opens it.
 */
describe("optional require guard", () => {
  it("finds every guarded load in a try block, not only the first", () => {
    // R28b: the first scanner stopped at the first require after `try {`,
    // skipped a block with a brace before the require, and ignored import().
    const text = [
      'try { require("first"); require("second"); } catch {}',
      'try { if (x) { require("nested"); } } catch {}',
      'try { await import("dynamic"); } catch {}',
      'require("unguarded");',
    ].join("\n");
    assert.deepEqual((guardedNames(text) as string[]).sort(), ["dynamic", "first", "nested", "second"]);
  });

  it("does not count a copy outside the checkout as being in the tree", () => {
    const here = join(repo, "scripts", "optional-require-guard.mjs");
    assert.equal(resolvesInTree("jose", here), true);
    // A planted C:\node_modules copy resolves, but outside the tree: the hole itself.
    assert.equal(resolvesInTree("jose", here, join(repo, "packages")), false);
    assert.equal(resolvesInTree("no-such-package-verax", here), false);
  });

  it("finds no guarded require of a missing name outside the reviewed list", { timeout: 120_000 }, () => {
    const findings = scan() as Finding[];
    const open = findings.filter((f) => !f.reviewed);
    assert.deepEqual(open, [], JSON.stringify(open, null, 2));
    // A reviewed entry that no longer matches anything is stale: remove it.
    for (const r of REVIEWED as Reviewed[]) {
      assert.ok(
        findings.some((f) => f.pkg === r.pkg && f.file === r.file && f.name === r.name),
        `reviewed entry no longer found: ${r.pkg}/${r.file} -> ${r.name}`,
      );
    }
  });

  it("the body never loads a package on the reviewed list", { timeout: 120_000 }, () => {
    const pkgs = (REVIEWED as Reviewed[]).map((r) => r.pkg);
    const script = `
      import { createRequire } from "node:module";
      import { pathToFileURL } from "node:url";
      const src = ${JSON.stringify(join(repo, "packages", "body", "src"))};
      for (const m of ${JSON.stringify(BODY_MODULES)}) await import(pathToFileURL(src + "/" + m + ".ts").href);
      const cache = Object.keys(createRequire(import.meta.url).cache);
      const hits = ${JSON.stringify(pkgs)}.filter((p) => cache.some((f) => f.split(/[\\\\/]/).join("/").includes("/node_modules/" + p + "/")));
      process.stdout.write(JSON.stringify({ loaded: cache.length, hits }));
    `;
    const run = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], {
      cwd: repo,
      encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stderr);
    const out = JSON.parse(run.stdout) as { loaded: number; hits: string[] };
    // Nothing loaded at all would make "not loaded" meaningless.
    assert.ok(out.loaded > 10, `only ${out.loaded} CommonJS modules loaded`);
    assert.deepEqual(out.hits, []);
  });
});
