// Tracked text must not carry a code point that draws nothing or turns a line
// around. An edit tool here wrote `\u202e`-style escapes as the raw code point
// 30 times in one evening; the guard looked only at C0 and stayed green. The
// guard takes DISPLAY_ESCAPE_CLASS from the policy source, so the class the
// screens escape and the class the tree refuses are one definition.
// Probes are built with String.fromCodePoint so this file stays ASCII.

import { strict as assert } from "node:assert";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { DISPLAY_ESCAPE_CLASS } from "../packages/proxy/src/policy.ts";
import { findStrayControls } from "../scripts/crlf-guard.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cp = (...points: number[]) => String.fromCodePoint(...points);
const hexOf = (point: number) => `0x${point.toString(16)}`;

function hitsFor(text: string): string[] {
  const file = "tests/.invisible-guard-probe.ts";
  const found = findStrayControls(root, [{ file, bytes: Buffer.from(text, "utf8") }]);
  return found.find((h) => h.file === file)?.codePoints ?? [];
}

describe("crlf-guard refuses code points that draw nothing", () => {
  const named: Array<[number, string]> = [
    [0x202e, "right-to-left override"], [0x2066, "left-to-right isolate"], [0x200b, "zero width space"],
    [0x2028, "line separator"], [0x2029, "paragraph separator"], [0xfeff, "byte order mark"],
    [0x0338, "combining long solidus overlay"], [0xfe0f, "variation selector 16"], [0xe0001, "language tag"],
    [0xe0101, "variation selector 18"], [0x00a0, "no-break space"], [0x3000, "ideographic space"],
    [0x3164, "hangul filler"], [0x2800, "braille blank"], [0x0085, "next line (C1)"], [0x009b, "CSI (C1)"],
    [0xe000, "private use"], [0x1cbb, "unassigned"],
  ];
  for (const [point, label] of named) {
    it(`refuses ${label} (U+${point.toString(16).padStart(4, "0")})`, () => {
      assert.ok(hitsFor(`const s = "a${cp(point)}b";\n`).includes(hexOf(point)), `U+${point.toString(16)} passed`);
    });
  }

  it("leaves letters of any script, an emoji, a tab and ordinary text alone", () => {
    const text = `const s = "${cp(0xdc)}nl${cp(0xfc)} ${cp(0x131)}${cp(0x15f)}${cp(0x131)}k ${cp(0x5d0, 0x5d1, 0x5d2)} ${cp(0x627, 0x644)} ${cp(0x4e2d)} ${cp(0x1f642)}";\n\tok\n`;
    assert.deepEqual(hitsFor(text), []);
  });

  it("refuses every code point of DISPLAY_ESCAPE_CLASS except tab, newline and CR", () => {
    const klass = new RegExp(`^[${DISPLAY_ESCAPE_CLASS}]$`, "u");
    const expected: string[] = [];
    let probe = "";
    for (let point = 0; point <= 0x10ffff; point += 1) {
      if (point >= 0xd800 && point <= 0xdfff) continue;
      if (point === 0x09 || point === 0x0a || point === 0x0d) continue;
      const ch = cp(point);
      if (!klass.test(ch)) continue;
      expected.push(hexOf(point));
      probe += ch;
    }
    const found = new Set(hitsFor(probe));
    const missing = expected.filter((h) => !found.has(h));
    assert.equal(missing.length, 0, `not refused: ${missing.slice(0, 20).join(", ")} (${missing.length} in all)`);
  });

  it("the tracked tree is clean", () => {
    const hits = findStrayControls(root);
    assert.deepEqual(hits, [], hits.map((h) => `${h.file}:${h.codePoints.join(",")}`).join("\n"));
  });
});
