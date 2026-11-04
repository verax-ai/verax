import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { runWatch } from "../packages/body/src/watch.ts";

async function watchOnce(dir: string) {
  let stdout = "";
  let stderr = "";
  const status = await runWatch([dir, "--once"], {
    stdout: { write: (s: string) => (stdout += s) },
    stderr: { write: (s: string) => (stderr += s) },
  });
  return { status, stderr, event: JSON.parse(stdout.trim()) as { actionResult: string } };
}

describe("verax watch halts only a directory a body reads", () => {
  it("a missing path: halt-failed, names the path, creates nothing", async () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-watch-missing-"));
    const target = join(parent, "typo", "state");
    const ran = await watchOnce(target);
    assert.equal(ran.status, 3);
    assert.equal(ran.event.actionResult, "halt-failed");
    assert.match(ran.stderr, /not-a-state-dir/);
    assert.ok(ran.stderr.includes(target), ran.stderr);
    assert.equal(existsSync(join(parent, "typo")), false);
  });

  it("the parent of a state directory: halt-failed, no switch", async () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-watch-parent-"));
    mkdirSync(join(parent, "state"));
    writeFileSync(join(parent, "notes.txt"), "x");
    const ran = await watchOnce(parent);
    assert.equal(ran.status, 3);
    assert.equal(ran.event.actionResult, "halt-failed");
    assert.equal(existsSync(join(parent, "halted")), false);
  });

  it("a state directory with a stale beat: halted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-watch-state-"));
    writeFileSync(join(dir, "heartbeat.json"), JSON.stringify({ atMs: 1_000 }));
    const ran = await watchOnce(dir);
    assert.equal(ran.status, 3);
    assert.equal(ran.event.actionResult, "halted");
    assert.equal(existsSync(join(dir, "halted")), true);
  });
});
