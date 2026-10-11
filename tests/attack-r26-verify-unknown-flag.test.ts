import { strict as assert } from "node:assert";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runVerify } from "../packages/body/src/verify-cli.ts";

/**
 * R26 (E-6). `verax verify` reads the flags it knows and takes the first
 * argument that does not start with `-` as the directory. A flag it does not
 * know is dropped without a word. `--require-anchored` is the flag that turns
 * a deleted receipt into a named problem; written one letter off, or as
 * `--require-anchored=true`, the run prints VERIFIED and exits 0 over a
 * checkpoint with no receipt. This is the forgetful operator #169 closed for
 * policy keys: a misspelt control must not leave the check weaker than the
 * command line reads.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ledger = join(root, "test-vectors", "v1", "valid-full", "ledger");
const credentials = join(root, "test-vectors", "v1", "valid-full", "pins", "operator-credentials.json");
const serviceKey = readFileSync(join(root, "tests", "fixtures", "anchor-capsule", "service-key.pem"), "utf8");

/** valid-full: one checkpoint whose window ended on 2 October 2026, and no receipt for it. */
function unanchoredLedger(): { dir: string; keyFile: string } {
  const dir = mkdtempSync(join(tmpdir(), "verax-r26-verify-flag-"));
  for (const name of readdirSync(ledger)) copyFileSync(join(ledger, name), join(dir, name));
  const keyFile = join(dir, "service.pem");
  writeFileSync(keyFile, serviceKey, "utf8");
  return { dir, keyFile };
}

async function verify(args: string[]): Promise<{ code: number; text: string }> {
  const out: string[] = [];
  // The vector's approval is signed; without its credential file verify fails for that reason alone.
  const code = await runVerify([...args, "--operator-credentials", credentials], (s) => out.push(s));
  return { code, text: out.join("\n") };
}

describe("R26 verify and a flag it does not know", () => {
  it("control: --require-anchored names the checkpoint with no receipt", async () => {
    const { dir, keyFile } = unanchoredLedger();
    try {
      const plain = await verify([dir, "--anchor-key", keyFile]);
      assert.equal(plain.code, 0, plain.text);
      const ran = await verify([dir, "--anchor-key", keyFile, "--require-anchored"]);
      assert.equal(ran.code, 1);
      assert.match(ran.text, /checkpoint-not-anchored /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("names the option it does not know", async () => {
    const { dir, keyFile } = unanchoredLedger();
    try {
      const ran = await verify([dir, "--anchor-key", keyFile, "--require-anchord"]);
      assert.equal(ran.code, 1);
      assert.match(ran.text, /^verify: unknown option --require-anchord$/m);
      assert.doesNotMatch(ran.text, /VERIFIED/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a second directory instead of verifying only the first", async () => {
    const { dir, keyFile } = unanchoredLedger();
    try {
      const ran = await verify([dir, dir, "--anchor-key", keyFile]);
      assert.equal(ran.code, 1);
      assert.match(ran.text, /one ledger directory at a time/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still takes --json, before or after the directory", async () => {
    const { dir, keyFile } = unanchoredLedger();
    try {
      for (const args of [[dir, "--json", "--anchor-key", keyFile], ["--json", dir, "--anchor-key", keyFile]]) {
        const ran = await verify(args);
        assert.equal(ran.code, 0, ran.text);
        assert.equal(JSON.parse(ran.text).ok, true);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  for (const flag of ["--require-anchord", "--require-anchored=true", "--requireAnchored"]) {
    it(`${flag} is refused, not dropped`, async () => {
      const { dir, keyFile } = unanchoredLedger();
      try {
        const ran = await verify([dir, "--anchor-key", keyFile, flag]);
        assert.notEqual(
          ran.code,
          0,
          `verify exited 0 with ${flag}; last line "${ran.text.trim().split("\n").pop()}", checkpoint-not-anchored named: ${/checkpoint-not-anchored/.test(ran.text)}`,
        );
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});
