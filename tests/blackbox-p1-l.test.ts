// P1-l: every consumer reads a :halted (not-run) row the same way.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { haltBody } from "../packages/body/src/halt.ts";
import { explain } from "../packages/proxy/src/explain.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { clearProcessHalted, isProcessHalted, isProxyHalted } from "../packages/proxy/src/process-halt.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const policy = loadPolicy(readFileSync(join(here, "..", "packages", "proxy", "policy", "default.json"), "utf8"));
const haltModule = pathToFileURL(join(here, "..", "packages", "body", "src", "halt.ts")).href;
const reader = { brain: "brain-l", scopes: new Set(["verax:read", "verax:memory"]) };
const pins = {
  publicKeyPem: RECORD_SIGNER.publicKeyPem,
  effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
};

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

function allowMemory() {
  return loadPolicy({
    version: 1,
    default: "deny",
    rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
  });
}

describe("black box P1-l: :halted is one contract", { concurrency: 1 }, () => {
  it("S2: verifyLedger and explain give the same verdict on a :threw ledger", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1l-threw-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: allowMemory(),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => Date.now(),
        nonce: () => "l-threw",
        inner: async () => {
          throw new Error("tool threw");
        },
      });
      await assert.rejects(() =>
        proxy.call({ name: "memory.get", arguments: { id: "x", _ref: "l-threw" } }, reader),
      );
      const allow = (await ledger.decisions()).find((d) => d.claims.decision === "allow");
      assert.ok(allow, "the throw still leaves the allow");
      const threwRef = allow.claims.ref;
      assert.ok(threwRef);
      const verified = await verifyLedger(dir, pins);
      const explained = await explain(ledger, threwRef);
      assert.equal(
        explained.balanced,
        verified.ok,
        `threw: verify ok=${verified.ok} problems=${JSON.stringify(verified.problems).slice(0, 240)} explain balanced=${explained.balanced} finding=${explained.finding.code}`,
      );
      assert.equal(verified.ok, true, JSON.stringify(verified.problems).slice(0, 240));
      assert.equal(explained.balanced, true, `${explained.finding.code} ${explained.finding.summary}`);
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("S2: verifyLedger and explain give the same verdict on a :halted ledger", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1l-halted-"));
    const armed = { on: false };
    const ledger = haltOnAllow(new FileLedger(dir), dir, armed);
    try {
      let n = 0;
      const proxy = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => Date.now(),
        nonce: () => `l-halt-${++n}`,
        inner: async () => ({ content: [{ type: "text", text: "ran" }], isError: false }),
      });
      armed.on = true;
      const first = await proxy.call({ name: "memory.get", arguments: { id: "x", _ref: "l-halt" } }, reader);
      assert.match(first.content.map((c) => c.text).join(""), /denied:halted/);
      const allow = (await ledger.decisions()).find((d) => d.claims.decision === "allow");
      assert.ok(allow, "the allow landed before the halt");
      const haltedRef = allow.claims.ref;
      assert.ok(haltedRef);
      const effect = (await ledger.effects()).find((e) => e.row.ref === haltedRef);
      assert.equal(effect?.row.effectClass, "memory.get:halted");
      const verified = await verifyLedger(dir, pins);
      const explained = await explain(ledger, haltedRef);
      assert.equal(
        explained.balanced,
        verified.ok,
        `halted: verify ok=${verified.ok} problems=${JSON.stringify(verified.problems).slice(0, 240)} explain balanced=${explained.balanced} finding=${explained.finding.code}`,
      );
      assert.equal(verified.ok, true, JSON.stringify(verified.problems).slice(0, 240));
      assert.equal(explained.balanced, true, `${explained.finding.code} ${explained.finding.summary}`);
    } finally {
      (ledger as FileLedger).close?.();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("S4: a written switch drops the process flag even when history cannot be appended", () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1l-s4-"));
    try {
      mkdirSync(join(state, "halted"));
      haltBody(state, "operator-l-s4", "cli");
      assert.equal(isProcessHalted(state), true, "blocked switch leaves a process flag");

      rmSync(join(state, "halted"), { recursive: true, force: true });
      mkdirSync(join(state, "halt-history.jsonl"));
      assert.throws(() => haltBody(state, "operator-l-s4", "cli"));
      assert.equal(statSync(join(state, "halted")).isFile(), true, "the second halt wrote the switch");
      assert.equal(isProcessHalted(state), false, "the flag drops once the switch exists");

      rmSync(join(state, "halt-history.jsonl"), { recursive: true, force: true });
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

  it("NIT: a replay of the same _ref says the previous attempt did not run", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1l-nit-"));
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
        nonce: () => `l-nit-${Date.now()}-${++n}`,
        inner: async () => {
          innerCalls += 1;
          return { content: [{ type: "text", text: "ran" }], isError: false };
        },
      });
      const call = { name: "memory.get", arguments: { id: "x", _ref: "l-nit-ref" } };
      armed.on = true;
      const first = await proxy.call(call, reader);
      const firstText = first.content.map((c) => c.text).join("");
      assert.equal(innerCalls, 0);
      assert.match(firstText, /denied:halted/);

      rmSync(join(state, "halted"), { force: true });
      const again = await proxy.call(call, reader);
      const againText = again.content.map((c) => c.text).join("");
      assert.match(againText, /denied:not-run-halted:/, `replay after resume: ${againText.slice(0, 160)}`);
      assert.equal(innerCalls, 0, "the tool must not run on the replay");
      const marks = existsSync(join(state, "in-flight")) ? readdirSync(join(state, "in-flight")) : [];
      assert.deepEqual(marks, []);
    } finally {
      rmSync(state, { recursive: true, force: true });
    }
  });
});
