import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

describe("serve --log-file", () => {
  it("serve with a bad env writes the config error into the log file", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-serve-log-"));
    const log = join(dir, "body.log");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("VERAX_"))) as NodeJS.ProcessEnv;
    try {
      const ran = spawnSync(process.execPath, ["--experimental-strip-types", cli, "serve", "--log-file", log], {
        encoding: "utf8",
        env,
      });
      assert.equal(ran.status, 78, ran.stderr);
      const text = readFileSync(log, "utf8");
      assert.match(text, /missing VERAX_ISSUER, VERAX_JWKS_URL, or VERAX_AUDIENCE/);
      if (process.platform !== "win32") assert.equal(statSync(log).mode & 0o777, 0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
