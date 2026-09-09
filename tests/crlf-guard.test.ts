import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  BINARY_EXCEPTIONS,
  countCarriageReturns,
  findCarriageReturns,
  findStrayControls,
  isBinaryPath,
} from "../scripts/crlf-guard.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("crlf-guard", () => {
  it("exceptions, when present, name a file and a reason", () => {
    for (const ex of BINARY_EXCEPTIONS) {
      assert.ok(ex.file.length > 0);
      assert.ok(ex.reason.length > 20, `${ex.file}: reason is too short`);
      assert.equal(isBinaryPath(ex.file), true);
    }
  });

  it("vendor tarballs are treated as binary paths", () => {
    assert.equal(isBinaryPath("vendor/cedulon-core-da7bf9b.tgz"), true);
  });

  it("RED then GREEN: a CRLF text blob is rejected, then the tree is clean", () => {
    const probe = Buffer.from("hello\r\nworld\n", "utf8");
    assert.ok(countCarriageReturns(probe) > 0);
    const red = findCarriageReturns(root, [{ file: "tests/.crlf-guard-probe.txt", bytes: probe }]);
    assert.ok(
      red.some((h) => h.file === "tests/.crlf-guard-probe.txt" && h.count > 0),
      `expected a hit on the CRLF probe, got ${JSON.stringify(red)}`,
    );
    const green = findCarriageReturns(root);
    assert.deepEqual(green, [], green.map((h) => `${h.file}:${h.count}`).join("\n"));
  });

  it("RED then GREEN: a stray control byte is rejected, then the tree is clean", () => {
    // A backspace inside a source line is invisible in a diff and turns the
    // pattern it sits in into one that matches nothing. That is how a guard in
    // this repo came to measure nothing while staying green.
    const probe = Buffer.from("const re = /x" + String.fromCharCode(8) + "/;\n", "utf8");
    const red = findStrayControls(root, [
      { file: "tests/.control-guard-probe.ts", bytes: probe },
    ]);
    assert.ok(
      red.some(
        (h) => h.file === "tests/.control-guard-probe.ts" && h.codePoints.includes("0x8"),
      ),
      "expected a hit on the control probe, got " + JSON.stringify(red),
    );
    const replacement = Buffer.from("x " + String.fromCharCode(0xfffd) + "\n", "utf8");
    const redToo = findStrayControls(root, [
      { file: "tests/.replacement-probe.ts", bytes: replacement },
    ]);
    assert.ok(
      redToo.some((h) => h.file === "tests/.replacement-probe.ts"),
      "expected a hit on the replacement probe, got " + JSON.stringify(redToo),
    );
    const green = findStrayControls(root);
    assert.deepEqual(green, [], green.map((h) => h.file + ":" + h.codePoints.join(",")).join("\n"));
  });

  it("the gate script is the same scan (exit 0)", () => {
    const stdout = execFileSync(
      process.execPath,
      ["--experimental-strip-types", "scripts/crlf-guard.ts"],
      { cwd: root, encoding: "utf8" },
    );
    assert.match(stdout, /crlf-guard: no CR and no stray control byte in tracked text blobs/);
  });
});
