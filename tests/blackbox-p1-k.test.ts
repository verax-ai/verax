// P1-k: a halt that lands between the allow and the run is on the signed
// record and leaves no start mark; a halt held only in a running process is
// not reported as "not halted" by a CLI resume elsewhere; an authorised
// resume is not written back by an old flag.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { haltBody } from "../packages/body/src/halt.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { clearProcessHalted, isProcessHalted, isProxyHalted } from "../packages/proxy/src/process-halt.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const policy = loadPolicy(readFileSync(join(here, "..", "packages", "proxy", "policy", "default.json"), "utf8"));
const haltModule = pathToFileURL(join(here, "..", "packages", "body", "src", "halt.ts")).href;
const reader = { brain: "brain-k", scopes: new Set(["verax:read", "verax:memory"]) };

function resumeInChild(state: string): { status: number | null; stderr: string } {
  const child = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--no-warnings",
      "--input-type=module",
      "-e",
      `const m = await import(${JSON.stringify(haltModule)}); process.exitCode = m.runResume(${JSON.stringify(state)});`,
    ],
    { encoding: "utf8", timeout: 60_000 },
  );
  return { status: child.status, stderr: child.stderr };
}

/** The ledger, with one hook: the moment the allow lands, the halt switch appears. */
function haltOnAllow(inner: FileLedger, state: string, armed: { on: boolean }): FileLedger {
  return new Proxy(inner, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target) as unknown;
      if (prop === "appendDecisionChained" && typeof value === "function") {
        return async (...args: unknown[]) => {
          const out = await (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
          if (armed.on) {
            armed.on = false;
            writeFileSync(join(state, "halted"), "");
          }
          return out;
        };
      }
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

describe("black box P1-k: halt between allow and run, honest CLI resume, resume stays", { concurrency: 1 }, () => {
  it("K1: a halt after the allow and before the run is recorded and leaves no start mark", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1k-"));
    try {
      const armed = { on: false };
      const ledger = haltOnAllow(new FileLedger(state), state, armed);
      let innerCalls = 0;
      let n = 0;
      const proxy = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => Date.now(),
        nonce: () => `k1-${Date.now()}-${++n}`,
        inner: async () => {
          innerCalls += 1;
          return { content: [{ type: "text", text: "ran" }], isError: false };
        },
      });
      const call = { name: "memory.get", arguments: { id: "x", _ref: "k1-ref" } };
      armed.on = true;
      const first = await proxy.call(call, reader);
      const firstText = first.content.map((c) => c.text).join("");
      assert.equal(innerCalls, 0, "the tool must not run once the halt is there");
      assert.match(firstText, /denied:halted/);

      const allows = (await ledger.decisions()).filter((d) => d.claims.decision === "allow");
      assert.equal(allows.length, 1, "the allow landed before the halt");
      const allowRef = allows[0]!.claims.ref;
      const effects = await ledger.effects();
      const decisions = await ledger.decisions();
      const effectSays = effects.some((e) => e.row.ref === allowRef && /halted/.test(e.row.effectClass));
      const denySays = decisions.some(
        (d) => d.claims.decision === "deny" && d.claims.reasonCode === "halted" && d.claims.timestampMs >= allows[0]!.claims.timestampMs,
      );
      assert.ok(effectSays || denySays, "the not-run outcome of the allowed call is on the signed record");

      const marks = existsSync(join(state, "in-flight")) ? readdirSync(join(state, "in-flight")) : [];
      assert.deepEqual(marks, [], "no start mark is left for a run that never started");

      rmSync(join(state, "halted"), { force: true });
      const again = await proxy.call(call, reader);
      const againText = again.content.map((c) => c.text).join("");
      assert.doesNotMatch(againText, /outcome-unknown/, `retry after resume: ${againText.slice(0, 160)}`);
      assert.ok(innerCalls <= 1, `the tool ran ${innerCalls} times`);

      const verified = await verifyLedger(state);
      assert.equal(verified.ok, true, JSON.stringify(verified).slice(0, 300));
    } finally {
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("K2: a halt held only in a running process is not reported as not halted by a CLI resume elsewhere", () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1k-"));
    try {
      mkdirSync(join(state, "halted"));
      haltBody(state, "operator-k2", "cli");
      assert.equal(isProcessHalted(state), true, "the switch is blocked, so this process holds the halt");
      const out = resumeInChild(state);
      assert.doesNotMatch(out.stderr, /(?:^|\n)not halted(?:\n|$)/, `CLI resume elsewhere: ${out.stderr.slice(0, 200)}`);
      assert.notEqual(out.status, 0, `CLI resume elsewhere exit ${out.status}: ${out.stderr.slice(0, 200)}`);
    } finally {
      clearProcessHalted(state);
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("K3: once the switch is written, an old process flag cannot undo a resume from another process", () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1k-"));
    try {
      mkdirSync(join(state, "halted"));
      haltBody(state, "operator-k3", "cli");
      assert.equal(isProcessHalted(state), true);
      rmSync(join(state, "halted"), { recursive: true, force: true });
      haltBody(state, "operator-k3", "cli");
      assert.equal(existsSync(join(state, "halted")), true, "the second halt wrote the switch");
      const out = resumeInChild(state);
      assert.equal(out.status, 0, out.stderr.slice(0, 200));
      assert.equal(existsSync(join(state, "halted")), false);
      assert.equal(isProxyHalted(state), false, "the running process honours the resume");
      assert.equal(existsSync(join(state, "halted")), false, "and does not write the switch back");
    } finally {
      clearProcessHalted(state);
      rmSync(state, { recursive: true, force: true });
    }
  });
});
