import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { loadConfig } from "../packages/body/src/config.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const configSource = readFileSync(join(root, "packages", "body", "src", "config.ts"), "utf8");
const serverSource = readFileSync(join(root, "packages", "body", "src", "server.ts"), "utf8");
const bodyPkg = JSON.parse(readFileSync(join(root, "packages", "body", "package.json"), "utf8")) as {
  name: string;
  version: string;
  mcpName?: string;
  bin?: Record<string, string>;
};
type RegistryPackage = {
  identifier: string;
  version: string;
  transport: { type: string; url?: string };
  environmentVariables?: { name: string; isRequired?: boolean }[];
};
const registry = JSON.parse(readFileSync(join(root, "server.json"), "utf8")) as {
  name: string;
  version: string;
  description: string;
  packages: RegistryPackage[];
};

/**
 * The variables the body refuses to start without, read from the body itself:
 * feed it an empty environment, take the names out of each refusal, set them,
 * and repeat until it accepts. The manifest is then compared with that, not
 * with a second list written by hand.
 */
function requiredByTheBody(): string[] {
  const env: NodeJS.ProcessEnv = {};
  const required: string[] = [];
  for (let round = 0; round < 10; round += 1) {
    const r = loadConfig(env);
    if (r.ok) return required.sort();
    const names = r.reason.match(/VERAX_[A-Z_]+/g) ?? [];
    assert.ok(names.length > 0, `the refusal names no variable: ${r.reason}`);
    for (const name of names) {
      required.push(name);
      env[name] = "set";
    }
  }
  assert.fail("loadConfig never accepted the environment");
}

/** The registry refuses a longer one with a 422, at publish time. */
const REGISTRY_DESCRIPTION_MAX = 100;

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

  it("--help names only variables the body reads", () => {
    const r = runCli(["--help"]);
    for (const name of new Set(r.stdout.match(/VERAX_[A-Z_]+/g) ?? [])) {
      assert.ok(configSource.includes(name), `help names ${name}, which the body's configuration never reads`);
    }
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

  it("the manifest marks as required exactly what the body refuses to start without", () => {
    const npm = registry.packages.find((p) => p.identifier === bodyPkg.name);
    assert.ok(npm, `server.json does not list ${bodyPkg.name}`);
    const listed = (npm.environmentVariables ?? [])
      .filter((v) => v.isRequired === true)
      .map((v) => v.name)
      .sort();
    assert.deepEqual(listed, requiredByTheBody(), "server.json and loadConfig disagree on what is required");
  });

  it("the manifest names the transport the body serves", () => {
    const npm = registry.packages.find((p) => p.identifier === bodyPkg.name);
    assert.ok(npm, `server.json does not list ${bodyPkg.name}`);
    // The body listens on node:http and speaks MCP over Streamable HTTP; there is no stdio path.
    assert.equal(npm.transport.type, "streamable-http", `server.json says ${npm.transport.type}`);
    const url = npm.transport.url ?? "";
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    assert.ok(path.length > 1, `transport url ${JSON.stringify(url)} names no path`);
    assert.ok(serverSource.includes(JSON.stringify(path)), `the body's server never routes ${path}`);
    const known = new Set((npm.environmentVariables ?? []).map((v) => v.name));
    for (const [, variable] of url.matchAll(/\{([A-Z_]+)\}/g)) {
      assert.ok(known.has(variable), `transport url uses {${variable}}, which the manifest does not list`);
    }
  });

  it("the manifest description is short enough for the registry to accept it", () => {
    assert.ok(
      registry.description.length <= REGISTRY_DESCRIPTION_MAX,
      `description is ${registry.description.length} characters; the registry allows ${REGISTRY_DESCRIPTION_MAX}`,
    );
  });

  it("the bin points at built JavaScript, because Node will not run TypeScript from node_modules", () => {
    const bin = bodyPkg.bin?.verax ?? "";
    assert.match(bin, /\.js$/, `bin is ${bin}`);
    const src = readFileSync(cli, "utf8");
    assert.ok(src.startsWith("#!"), "the CLI has no shebang, so an installed bin cannot run it");
  });
});
