// npm starts the CLI through a symbolic link. The linked start must run the command, not exit 0 silently.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

describe("CLI entry", () => {
  it("runs a command when started through a symbolic link", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "verax-cli-link-"));
    try {
      const link = join(dir, "verax.ts");
      try {
        symlinkSync(cli, link, "file");
      } catch {
        t.skip("this account cannot create a symbolic link");
        return;
      }
      const direct = spawnSync(process.execPath, ["--experimental-strip-types", cli, "--help"], { encoding: "utf8" });
      const linked = spawnSync(process.execPath, ["--experimental-strip-types", link, "--help"], { encoding: "utf8" });
      assert.match(direct.stdout, /Usage: verax/);
      assert.equal(linked.status, direct.status, linked.stderr);
      assert.match(linked.stdout, /Usage: verax/, "a linked start printed nothing");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
