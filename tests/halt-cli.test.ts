import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runHalt, runResume } from "../packages/body/src/halt.ts";
import { refusedAsElevated } from "./elevated-refusal.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

describe("verax halt and resume refuse a path no body reads", () => {
  const capture = () => {
    const lines: string[] = [];
    return { write: (s: string) => void lines.push(s), text: () => lines.join("") };
  };

  it("halt on a missing path: exit 1, names the path, creates nothing", () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-halt-missing-"));
    const target = join(parent, "typo", "state");
    const err = capture();
    assert.equal(runHalt(target, err.write), 1);
    assert.match(err.text(), /^halt-failed: not-a-state-dir: /);
    assert.ok(err.text().includes(target), err.text());
    assert.doesNotMatch(err.text(), /^halted/m);
    assert.equal(existsSync(join(parent, "typo")), false);
  });

  it("halt on the parent of a state directory: exit 1, no switch", () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-halt-parent-"));
    mkdirSync(join(parent, "state"));
    writeFileSync(join(parent, "notes.txt"), "x");
    const err = capture();
    assert.equal(runHalt(parent, err.write), 1);
    assert.match(err.text(), /not-a-state-dir/);
    assert.equal(existsSync(join(parent, "halted")), false);
    assert.equal(existsSync(join(parent, "halt-history.jsonl")), false);
  });

  it("halt on a directory a body has written: writes the switch", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-halt-ledger-"));
    writeFileSync(join(dir, "decisions.jsonl"), "");
    const err = capture();
    assert.equal(runHalt(dir, err.write), 0);
    assert.equal(err.text(), "halted\n");
    assert.equal(existsSync(join(dir, "halted")), true);
  });

  it("halt on an empty directory: writes the switch and says no body has written there", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-halt-empty-"));
    const err = capture();
    assert.equal(runHalt(dir, err.write), 0);
    assert.match(err.text(), /^halted\n/);
    assert.match(err.text(), /no body has written here yet/);
    assert.equal(existsSync(join(dir, "halted")), true);
  });

  it("resume on a missing path: exit 1 instead of 'not halted'", () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-resume-missing-"));
    const err = capture();
    assert.equal(runResume(join(parent, "typo"), err.write), 1);
    assert.match(err.text(), /^resume-failed: not-a-state-dir: /);
    assert.doesNotMatch(err.text(), /not halted/);
  });

  it("resume on a state directory that is not halted still answers 'not halted'", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-resume-ledger-"));
    writeFileSync(join(dir, "decisions.jsonl"), "");
    const err = capture();
    assert.equal(runResume(dir, err.write), 0);
    assert.equal(err.text(), "not halted\n");
  });
});

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
    if (refusedAsElevated(code, stderr)) return;
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
