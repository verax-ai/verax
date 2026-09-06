import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

describe("S3 verax halt CLI", () => {
  it("writes <stateDir>/halted and exits 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-halt-cli-"));
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "halt", dir], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 0);
    assert.match(stderr, /halted/);
    assert.equal(existsSync(join(dir, "halted")), true);
    assert.equal(readFileSync(join(dir, "halted"), "utf8"), "");
  });

  it("missing stateDir exits 78", async () => {
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "halt"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 78);
  });
});
