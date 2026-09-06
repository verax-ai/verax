import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(pkgRoot, "..", "..");

const ALLOWED = new Set([
  "createProxy",
  "loadPolicy",
  "FileLedger",
  "MemoryLedger",
  "explain",
  "approvePending",
  "approvalsLogFor",
  "enqueueApprovalCommand",
  "loadApprovalsFromDir",
  "loadEffectsFromDir",
  "parseChannelJsonl",
  "parseCardCsv",
  "reconcile",
]);

describe("B1 exports map", () => {
  it("package.json exports only the root entry", () => {
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")) as {
      exports: Record<string, string>;
    };
    assert.deepEqual(Object.keys(pkg.exports), ["."]);
  });

  it("index.ts value exports are the allowed set", () => {
    const src = readFileSync(join(pkgRoot, "src", "index.ts"), "utf8");
    const names = [...src.matchAll(/export\s+\{([^}]+)\}/g)]
      .flatMap((m) => m[1].split(","))
      .map((s) => s.trim().split(/\s+/)[0])
      .filter((s) => s && s !== "type");
    for (const name of names) {
      assert.ok(ALLOWED.has(name), `unexpected export ${name}`);
    }
    for (const name of ALLOWED) {
      assert.ok(names.includes(name), `missing export ${name}`);
    }
  });

  it("npm pack --dry-run lists the package and no test fixtures", () => {
    const packed = spawnSync("npm", ["pack", "--dry-run", "-w", "@verax-ai/proxy"], {
      cwd: repoRoot,
      encoding: "utf8",
      shell: true,
    });
    const out = `${packed.stdout ?? ""}\n${packed.stderr ?? ""}`;
    assert.equal(packed.status, 0, out);
    assert.match(out, /@verax-ai\/proxy|verax-ai-proxy-0\.0\.0\.tgz/);
    assert.doesNotMatch(out, /tests\/fixtures/);
  });
});
