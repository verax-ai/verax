import { strict as assert } from "node:assert";
import { copyFileSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { registerCheckpoint, runAnchor } from "../packages/body/src/anchor-cli.ts";

/**
 * R26 (E-11). The Transparency Service is run by someone else, and its answer is
 * input. `registerCheckpoint` parses the answer inside a `try`, then
 * destructures it outside. A service that answers the JSON value `null` with
 * 200 makes that destructuring throw a TypeError: the function that returns
 * `{ ok: false, reason }` for every other bad answer rejects instead.
 * `verax anchor` ends on an unhandled exception, and in `verax witness` the
 * run stops at that checkpoint, so the pending ones after it are not tried and
 * the status row says `exception` with no checkpoint hash.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ledger = join(root, "test-vectors", "v1", "valid-full", "ledger");

const answering = (body: string): typeof fetch =>
  (async () => new Response(body, { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch;

describe("R26 a transparency service that answers null", () => {
  it("registerCheckpoint returns a refusal, as it does for [] and {}", async () => {
    const hash = "ab".repeat(32);
    const empty = await registerCheckpoint("http://127.0.0.1:9", hash, null, answering("{}"));
    assert.equal(empty.ok, false);
    let outcome: string;
    try {
      const got = await registerCheckpoint("http://127.0.0.1:9", hash, null, answering("null"));
      outcome = got.ok ? "ok" : `refused:${got.reason}`;
    } catch (err) {
      outcome = `threw ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`;
    }
    assert.match(outcome, /^refused:/, `registerCheckpoint ${outcome}`);
  });

  it("verax anchor reports it and exits 1 instead of throwing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r26-anchor-null-"));
    for (const name of readdirSync(ledger)) copyFileSync(join(ledger, name), join(dir, name));
    const out: string[] = [];
    try {
      let outcome: string;
      try {
        outcome = `exit ${await runAnchor([dir, "--service", "http://127.0.0.1:9"], (s) => out.push(s), answering("null"))}`;
      } catch (err) {
        outcome = `threw ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`;
      }
      assert.equal(outcome, "exit 1", `verax anchor ${outcome}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
