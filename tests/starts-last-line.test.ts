import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { lastLine } from "../packages/body/src/heartbeat.ts";

/**
 * A signed start chains to the line before it, and to find that line the
 * body read the whole of `starts.jsonl` into one string on every start.
 * Measured before this change: a 300 MiB file took 874 ms and grew the
 * process from 64 to 608 MiB; at 700 MiB the read threw and the body did
 * not start. Only the end of the file is read now. These cases hold the
 * window logic to what the whole-file read returned.
 */

/** What the whole-file read returned. */
function whole(text: string): string | null {
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  return lines.length === 0 ? null : lines[lines.length - 1]!;
}

function check(text: string, window: number): void {
  const dir = mkdtempSync(join(tmpdir(), "verax-last-line-"));
  try {
    const file = join(dir, "starts.jsonl");
    writeFileSync(file, text, "utf8");
    assert.equal(lastLine(file, window), whole(text), `window ${window}, text ${JSON.stringify(text.slice(-60))}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const row = (n: number) => JSON.stringify({ action: "start", atMs: n, prevBeatAtMs: null, gapMs: null, pid: 1, note: "é".repeat(n % 7) });

describe("the last line of starts.jsonl, read from the end", () => {
  it("returns what a whole-file read returned, at every window size", () => {
    const many = `${Array.from({ length: 200 }, (_, i) => row(i)).join("\n")}\n`;
    const texts = [
      "",
      "\n\n",
      `${row(1)}\n`,
      row(1),
      `${row(1)}\n${row(2)}\n`,
      `${row(1)}\n${row(2)}`,
      `${row(1)}\n${row(2)}\n\n   \n`,
      `${row(1)}\r\n${row(2)}\r\n`,
      many,
      `${many}${"x".repeat(5000)}\n`,
      `${"y".repeat(5000)}\n${row(3)}\n`,
    ];
    for (const text of texts) for (const window of [1, 2, 7, 64, 300, 4096, 65536]) check(text, window);
  });

  it("a file that is not there has no last line", () => {
    assert.equal(lastLine(join(tmpdir(), "verax-no-such-dir", "starts.jsonl")), null);
  });

  it("a window boundary inside a multi-byte character does not change the line", () => {
    const text = `${"é".repeat(40)}\n${"ü".repeat(33)}\n`;
    for (let window = 1; window <= 80; window += 1) check(text, window);
  });
});
