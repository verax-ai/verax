// `verax verify` reads a ledger someone else may have written. Measured on
// 57df933: a ref placed in the unsigned index.jsonl reached the problems list
// and the terminal as ESC ]0;...BEL, ESC [2J and U+202E. The printed result
// writes those as escapes; the --json result stays JSON with the same values.
// Built with String.fromCodePoint so this file stays ASCII.

import { strict as assert } from "node:assert";
import { appendFileSync, cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { DISPLAY_ESCAPE_CLASS } from "@verax-ai/proxy";
import { runVerify } from "../packages/body/src/verify-cli.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cp = (...points: number[]) => String.fromCodePoint(...points);
const HOSTILE_REF = `x${cp(0x1b)}]0;pwned${cp(0x07)}${cp(0x1b)}[2J${cp(0x9b)}2J${cp(0x202e)}KO${cp(0x2028)}y`;
const DRAWS_NOTHING = new RegExp(`[${DISPLAY_ESCAPE_CLASS}]`, "u");

const dirs: string[] = [];
after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function tamperedLedger(ref: string = HOSTILE_REF): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-a1-verify-"));
  dirs.push(dir);
  cpSync(join(root, "test-vectors", "v1", "valid-full", "ledger"), dir, { recursive: true });
  const first = JSON.parse(readFileSync(join(dir, "index.jsonl"), "utf8").split("\n")[0]!) as Record<string, unknown>;
  appendFileSync(join(dir, "index.jsonl"), `${JSON.stringify({ ...first, ref, hasEffect: true })}\n`, "utf8");
  return dir;
}

function rawIn(text: string): string[] {
  const found: string[] = [];
  for (const line of text.split("\n")) {
    for (const ch of line) {
      if (DRAWS_NOTHING.test(ch)) found.push(`U+${(ch.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}`);
    }
  }
  return found;
}

describe("verax verify on a ledger whose index names a ref with controls", () => {
  it("prints the ref escaped", async () => {
    const lines: string[] = [];
    const code = await runVerify([tamperedLedger()], (s) => lines.push(s));
    const out = lines.join("\n");
    assert.notEqual(code, 0);
    assert.ok(out.includes("index says ref x"), out.slice(0, 400));
    assert.deepEqual(rawIn(out), [], `raw on the terminal: ${JSON.stringify(out.slice(0, 400))}`);
    for (const esc of ["\\u001b", "\\u0007", "\\u009b", "\\u202e", "\\u2028"]) assert.ok(out.includes(esc), `${esc} missing`);
  });

  it("a line break in the ref does not start a line of its own (no forged VERIFIED)", async () => {
    const lines: string[] = [];
    const code = await runVerify([tamperedLedger("x\n\nVERIFIED\n")], (s) => lines.push(s));
    const printed = lines.join("\n").split("\n");
    assert.notEqual(code, 0);
    assert.equal(printed.filter((line) => line === "VERIFIED").length, 0, `a forged line: ${JSON.stringify(printed.slice(-12))}`);
    assert.equal(printed.filter((line) => line.trim() === "").length <= 2, true, `blank lines from the ref: ${JSON.stringify(printed.slice(-12))}`);
    assert.ok(printed.some((line) => line.includes("index says ref x\\u000a\\u000aVERIFIED\\u000a")), JSON.stringify(printed.slice(-12)));
  });

  it("--json prints JSON that parses to the same ref, with nothing raw in it", async () => {
    const lines: string[] = [];
    await runVerify([tamperedLedger(), "--json"], (s) => lines.push(s));
    const out = lines.join("\n");
    assert.deepEqual(rawIn(out), [], `raw on the terminal: ${JSON.stringify(out.slice(0, 400))}`);
    const parsed = JSON.parse(out) as { problems: string[] };
    assert.ok(parsed.problems.some((p) => p.includes(HOSTILE_REF)), "the parsed problem does not carry the ref as written");
  });
});
