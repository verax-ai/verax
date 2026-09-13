import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "browser-left-open.fixture.ts");

/**
 * The browser suites launch Chromium inside the test body. When a test fails
 * before it closes the browser, the after-hook is all that stands between a
 * red test and a runner that never exits: Chromium holds the process open, the
 * log goes silent and CI waits for its cap. This runs such a test in a child
 * and asks only whether the child ends on its own, red.
 */
describe("browser cleanup", () => {
  it("a test that fails with its browser open still lets the runner exit", { timeout: 120_000 }, () => {
    // Without this the child sees it runs inside a test and skips the file.
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const ran = spawnSync(process.execPath, ["--experimental-strip-types", "--test", fixture], {
      env,
      encoding: "utf8",
      timeout: 90_000,
      windowsHide: true,
    });
    const tail = `${ran.stdout}${ran.stderr}`.slice(-1500);
    assert.notEqual(ran.error?.message.includes("ETIMEDOUT"), true, `runner still alive after 90 s\n${tail}`);
    assert.equal(ran.signal, null, `runner was killed (${ran.signal}), it did not exit\n${tail}`);
    assert.equal(ran.status, 1, `expected the fixture to fail and exit\n${tail}`);
    assert.match(tail, /left-open/);
  });
});
