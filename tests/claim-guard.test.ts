import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { matchBanned, scanClaims } from "../scripts/claim-guard.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("claim-guard", () => {
  it("exceptions start empty and, when added, carry a reason", () => {
    const { exceptions } = scanClaims(root);
    assert.equal(exceptions.length, 0);
    for (const ex of exceptions) {
      assert.ok(ex.reason.length > 20, `${ex.file}: exception reason is too short to stand alone`);
    }
  });

  it("published surfaces do not carry banned claims", () => {
    const { hits } = scanClaims(root);
    assert.deepEqual(
      hits,
      [],
      hits.map((h) => `${h.file}:${h.line}: ${h.text}`).join("\n"),
    );
  });

  it("detects the extra banned phrases and sentence-initial works", () => {
    assert.equal(matchBanned("This path is proven."), "proven");
    assert.equal(matchBanned("The product guarantees uptime."), "guarantees");
    assert.equal(matchBanned("secure by design from day one"), "secure by design");
    assert.equal(matchBanned("secure by default once configured"), "secure by default");
    assert.equal(matchBanned("production-ready after review"), "production-ready");
    assert.equal(matchBanned("holds 60 fps on a laptop"), "60 fps");
    assert.equal(matchBanned("Works out of the box."), "works (sentence-initial)");
    assert.equal(matchBanned("The network works when configured."), null);
    assert.equal(matchBanned("114 passing tests on CI"), "suite-size");
  });

  it("the gate script is the same scan (exit 0)", () => {
    const stdout = execFileSync(
      process.execPath,
      ["--experimental-strip-types", "scripts/claim-guard.ts"],
      { cwd: root, encoding: "utf8" },
    );
    assert.match(stdout, /claim-guard: no banned claims on published surfaces/);
  });
});
