import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const bodyPkg = JSON.parse(readFileSync(join(root, "packages", "body", "package.json"), "utf8")) as {
  name: string;
  version: string;
  mcpName?: string;
  bin?: Record<string, string>;
};
const registry = JSON.parse(readFileSync(join(root, "server.json"), "utf8")) as {
  name: string;
  version: string;
  packages: { identifier: string; version: string }[];
};

/** No VERAX_* in the environment: this is a fresh install asking what it got. */
function runCli(args: string[]): { status: number; stdout: string; stderr: string } {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith("VERAX_")),
  ) as NodeJS.ProcessEnv;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", cli, ...args], {
    encoding: "utf8",
    env,
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

describe("the published command answers before it is configured", () => {
  it("--help exits 0 and names the commands, with no issuer configured", () => {
    const r = runCli(["--help"]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Usage: verax/);
    for (const command of ["doctor", "approve", "operator", "reconcile", "witness", "halt", "unlock"]) {
      assert.match(r.stdout, new RegExp(`\\b${command}\\b`), `help does not name ${command}`);
    }
    // The help may name the variables; it must not be the refusal to start.
    assert.doesNotMatch(r.stdout + r.stderr, /missing VERAX_ISSUER/);
  });

  it("--version prints this package's version, not a copy of it", () => {
    const r = runCli(["--version"]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), bodyPkg.version);
  });

  it("the registry manifest and the package say the same thing", () => {
    assert.equal(registry.name, bodyPkg.mcpName, "server.json name != package.json mcpName");
    assert.equal(registry.version, bodyPkg.version, "server.json version != package version");
    const npm = registry.packages.find((p) => p.identifier === bodyPkg.name);
    assert.ok(npm, `server.json does not list ${bodyPkg.name}`);
    assert.equal(npm.version, bodyPkg.version, "server.json package version != package version");
  });

  it("the bin points at built JavaScript, because Node will not run TypeScript from node_modules", () => {
    const bin = bodyPkg.bin?.verax ?? "";
    assert.match(bin, /\.js$/, `bin is ${bin}`);
    const src = readFileSync(cli, "utf8");
    assert.ok(src.startsWith("#!"), "the CLI has no shebang, so an installed bin cannot run it");
  });
});
