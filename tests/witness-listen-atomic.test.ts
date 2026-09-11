import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { writeListenForTest } from "../packages/body/src/witness.ts";

/**
 * The witness announces itself by writing a file another process reads. That
 * makes how it is written part of the contract: a reader that opens the file
 * between the truncate and the flush gets bytes that do not parse, and
 * readWitnessListen turns that into `null` - which its caller cannot tell from
 * "no witness is running".
 *
 * The race is not theoretical and it is not rare. Written in place, a reader
 * polling every 20 ms while the file was rewritten 60 times got 12 unparseable
 * reads; written through a temporary file and a rename, zero. This spawns that
 * reader and asks for zero.
 */
describe("the witness listen file is never half written", () => {
  it("a reader polling through 40 rewrites never parses a torn file", { timeout: 60_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-listen-atomic-"));
    const path = join(dir, "witness.listen.json");
    // Big enough that a single writeFileSync cannot land in one go. The real
    // file is small; the size here is what makes an unfixed write observable
    // instead of merely possible.
    const payload = JSON.stringify({
      pid: 1,
      port: 2,
      token: "t".repeat(200_000),
      publicKeyPem: "p",
    });

    const reader = spawn(
      process.execPath,
      [
        "-e",
        `const { readFileSync } = require("node:fs");
         let torn = 0, ok = 0;
         const until = Date.now() + 4000;
         const tick = () => {
           try { JSON.parse(readFileSync(${JSON.stringify(path)}, "utf8")); ok += 1; }
           catch (e) { if (e.code !== "ENOENT") torn += 1; }
           if (Date.now() < until) setTimeout(tick, 20);
           else process.stdout.write(JSON.stringify({ ok, torn }));
         };
         tick();`,
      ],
      { stdio: ["ignore", "pipe", "inherit"], windowsHide: true },
    );
    let out = "";
    reader.stdout.on("data", (chunk) => {
      out += String(chunk);
    });
    const closed = new Promise<void>((resolve) => reader.on("close", () => resolve()));

    try {
      await new Promise((resolve) => setTimeout(resolve, 200));
      for (let i = 0; i < 40; i += 1) {
        writeListenForTest(path, payload);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      await closed;
      const seen = JSON.parse(out || '{"ok":0,"torn":0}') as { ok: number; torn: number };
      assert.ok(seen.ok > 0, `the reader never saw the file at all: ${out}`);
      assert.equal(seen.torn, 0, `reader parsed ${seen.torn} torn files out of ${seen.ok + seen.torn}`);
    } finally {
      reader.kill();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
