import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runCli } from "../packages/body/src/cli.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

async function run(args: string[]) {
  let stdout = "";
  let stderr = "";
  const status = await runCli(args, {
    elevated: () => false,
    stdout: { write: (s: string) => (stdout += s) },
    stderr: { write: (s: string) => (stderr += s) },
  });
  return { status, stdout, stderr };
}

describe("a help flag on a subcommand prints help and does nothing else", () => {
  for (const args of [
    ["witness", "--help"],
    ["witness", "-h"],
    ["halt", "--help"],
    ["resume", "--help"],
    ["unlock", "--help"],
    ["demo", "--help"],
    ["approve", "--help"],
    ["operator", "--help"],
    ["init", "--help"],
    ["install", "--help"],
    ["uninstall", "--help"],
    ["uninstall", "--keep-state", "--help"],
    ["serve", "--help"],
    ["doctor", "--help"],
    ["reconcile", "--help"],
    ["desktop", "--help"],
    ["downstream", "--help"],
    ["memory", "--help"],
  ]) {
    it(`verax ${args.join(" ")}`, async () => {
      const ran = await run(args);
      assert.equal(ran.status, 0, ran.stderr);
      assert.match(ran.stdout, /^verax - /);
    });
  }

  it("verify, anchor and watch keep their own usage", async () => {
    for (const [command, usage] of [
      ["verify", /^usage: verax verify /],
      ["anchor", /^usage: verax anchor /],
      ["watch", /^usage: verax watch /],
    ] as const) {
      const ran = await run([command, "--help"]);
      assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
      assert.match(ran.stdout, usage);
    }
  });

  it("verax witness --help as a process returns and leaves nothing behind", () => {
    const cwd = mkdtempSync(join(tmpdir(), "verax-cli-help-"));
    try {
      const ran = spawnSync(process.execPath, ["--experimental-strip-types", cli, "witness", "--help"], {
        cwd,
        encoding: "utf8",
        timeout: 20_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
      assert.equal(ran.status, 0, `${ran.stderr}${ran.signal ?? ""}`);
      assert.match(ran.stdout, /^verax - /);
      assert.deepEqual(readdirSync(cwd), []);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
});

describe("an option is not read as a state directory", () => {
  for (const args of [
    ["witness", "--nope"],
    ["halt", "--nope"],
    ["resume", "--nope"],
    ["unlock", "--nope"],
    ["unlock", "--force", "--nope"],
  ]) {
    it(`verax ${args.join(" ")}`, async () => {
      const ran = await run(args);
      assert.equal(ran.status, 64, ran.stderr);
      assert.match(ran.stderr, /unknown option: --nope/);
    });
  }
});
