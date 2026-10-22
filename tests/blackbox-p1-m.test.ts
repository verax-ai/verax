// P1-m: a :halted row binds only on the same allow (ref, hash, class+":halted").
import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { signEffectExtract, type EffectRow } from "@cedulon/effect-extract";

import { explain } from "../packages/proxy/src/explain.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const policy = loadPolicy(readFileSync(join(here, "..", "packages", "proxy", "policy", "default.json"), "utf8"));
const denyAll = loadPolicy({ version: 1, default: "deny", rules: [] });
const reader = { brain: "brain-m", scopes: new Set(["verax:read", "verax:memory"]) };
const pins = {
  publicKeyPem: RECORD_SIGNER.publicKeyPem,
  effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem,
};

/** Halt the moment the allow lands; optionally rewrite the signed :halted row before it is stored. */
function haltOnAllow(
  inner: FileLedger,
  state: string,
  armed: { on: boolean },
  rewrite?: (row: EffectRow) => EffectRow,
): FileLedger {
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
      if (prop === "appendEffect" && typeof value === "function" && rewrite) {
        return async (row: EffectRow, ...rest: unknown[]) => {
          const next =
            typeof row.effectClass === "string" && row.effectClass.endsWith(":halted") ? rewrite(row) : row;
          return (value as (...a: unknown[]) => unknown).apply(target, [next, ...rest]);
        };
      }
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

async function callHalted(
  dir: string,
  rewrite?: (row: EffectRow) => EffectRow,
): Promise<{ ledger: FileLedger; ref: string }> {
  const armed = { on: false };
  const inner = new FileLedger(dir);
  const ledger = haltOnAllow(inner, dir, armed, rewrite);
  let n = 0;
  const proxy = createProxy({
    policy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: () => Date.now(),
    nonce: () => `m-halt-${++n}`,
    inner: async () => ({ content: [{ type: "text", text: "ran" }], isError: false }),
  });
  armed.on = true;
  const first = await proxy.call({ name: "memory.get", arguments: { id: "x", _ref: "m-halt" } }, reader);
  assert.match(first.content.map((c) => c.text).join(""), /denied:halted/);
  const allow = (await ledger.decisions()).find((d) => d.claims.decision === "allow");
  assert.ok(allow, "the allow landed before the halt");
  const ref = allow.claims.ref;
  assert.ok(ref);
  return { ledger: inner, ref };
}

function bothFailed(verified: { ok: boolean; problems: string[] }, explained: { balanced: boolean; finding: { code: string | null } }, label: string): void {
  assert.equal(verified.ok, false, `${label}: verify ok=${verified.ok} problems=${JSON.stringify(verified.problems).slice(0, 240)}`);
  assert.equal(explained.balanced, false, `${label}: explain balanced=${explained.balanced} finding=${explained.finding.code}`);
}

describe("black box P1-m: :halted binds on the same allow only", { concurrency: 1 }, () => {
  it("a signed :halted with the wrong hash fails verifyLedger and explain", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-hash-"));
    let ledger: FileLedger | undefined;
    try {
      const out = await callHalted(dir, (row) => ({ ...row, effectHash: "f".repeat(64) }));
      ledger = out.ledger;
      const effect = (await ledger.effects()).find((e) => e.row.ref === out.ref);
      assert.equal(effect?.row.effectClass, "memory.get:halted");
      assert.equal(effect?.row.effectHash, "f".repeat(64));
      const verified = await verifyLedger(dir, pins);
      const explained = await explain(ledger, out.ref);
      bothFailed(verified, explained, "wrong-hash");
    } finally {
      ledger?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a signed :halted with the wrong class fails verifyLedger and explain", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-class-"));
    let ledger: FileLedger | undefined;
    try {
      const out = await callHalted(dir, (row) => ({ ...row, effectClass: "spend:halted" }));
      ledger = out.ledger;
      const effect = (await ledger.effects()).find((e) => e.row.ref === out.ref);
      assert.equal(effect?.row.effectClass, "spend:halted");
      const verified = await verifyLedger(dir, pins);
      const explained = await explain(ledger, out.ref);
      bothFailed(verified, explained, "wrong-class");
    } finally {
      ledger?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a :halted on a deny fails verifyLedger and explain", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-deny-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: denyAll,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => Date.now(),
        nonce: () => "m-deny",
        inner: async () => ({ content: [{ type: "text", text: "ran" }], isError: false }),
      });
      await proxy.call({ name: "memory.get", arguments: { id: "x", _ref: "m-deny" } }, reader);
      const deny = (await ledger.decisions()).find((d) => d.claims.decision === "deny");
      assert.ok(deny);
      const ref = deny.claims.ref;
      assert.ok(ref);
      await ledger.appendEffect({
        ref,
        effectHash: "ab".repeat(32),
        effectClass: "memory.get:halted",
        timestampMs: 99,
        actor: "brain-m",
      });
      const verified = await verifyLedger(dir, pins);
      const explained = await explain(ledger, ref);
      bothFailed(verified, explained, "deny+halted");
    } finally {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a :halted ledger plus a mismatched normal opts.extract fails verifyLedger and explain", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-extract-"));
    let ledger: FileLedger | undefined;
    try {
      const out = await callHalted(dir);
      ledger = out.ledger;
      const effect = (await ledger.effects()).find((e) => e.row.ref === out.ref);
      assert.equal(effect?.row.effectClass, "memory.get:halted");
      const extract = signEffectExtract(
        {
          deciderId: "verax-proxy",
          channelId: "verax-body",
          windowStartMs: 1,
          windowEndMs: 2,
          effects: [
            {
              ref: out.ref,
              effectHash: "e".repeat(64),
              effectClass: "memory.get",
              timestampMs: 1,
              actor: "brain-m",
            },
          ],
        },
        EFFECT_SIGNER.privateKeyPem,
        EFFECT_SIGNER.publicKeyPem,
      );
      const explained = await explain(ledger, out.ref, { extract });
      assert.equal(
        explained.balanced,
        false,
        `extract: explain balanced=${explained.balanced} finding=${explained.finding.code}`,
      );
      // verifyLedger does not take an extract. The same mismatched normal row
      // as the primary settlement must not bind.
      const overwritten = mkdtempSync(join(tmpdir(), "verax-bbp1m-extract-row-"));
      let other: FileLedger | undefined;
      try {
        const row = await callHalted(overwritten, (effectRow) => ({
          ...effectRow,
          effectHash: "e".repeat(64),
          effectClass: "memory.get",
        }));
        other = row.ledger;
        const verified = await verifyLedger(overwritten, pins);
        const explainedRow = await explain(other, row.ref);
        bothFailed(verified, explainedRow, "extract-as-row");
      } finally {
        other?.close();
        rmSync(overwritten, { recursive: true, force: true });
      }
    } finally {
      ledger?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a bound :halted ledger row does not excuse a stored receipt with the right hash and another class", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-receipt-"));
    let ledger: FileLedger | undefined;
    try {
      const out = await callHalted(dir);
      ledger = out.ledger;
      const effect = (await ledger.effects()).find((e) => e.row.ref === out.ref);
      assert.equal(effect?.row.effectClass, "memory.get:halted");
      const forged = signEffectExtract(
        {
          deciderId: "verax-proxy",
          channelId: "verax-body",
          windowStartMs: 1,
          windowEndMs: 2,
          effects: [{ ref: out.ref, effectHash: effect!.row.effectHash, effectClass: "memory.get:other", timestampMs: 1, actor: "brain-m" }],
        },
        EFFECT_SIGNER.privateKeyPem,
        EFFECT_SIGNER.publicKeyPem,
      );
      const real = ledger;
      const withReceipt = new Proxy(real, {
        get(target, prop) {
          if (prop === "effects") {
            return async () =>
              (await target.effects()).map((e) => (e.row.ref === out.ref ? { ...e, receipt: forged } : e));
          }
          const value = Reflect.get(target, prop, target) as unknown;
          return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
        },
      });
      const explained = await explain(withReceipt, out.ref);
      assert.equal(
        explained.balanced,
        false,
        `the audited row is the stored receipt: balanced=${explained.balanced} finding=${explained.finding.code}`,
      );
    } finally {
      ledger?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an extract with a bound :halted row and a second row for the ref is not excused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-two-rows-"));
    let ledger: FileLedger | undefined;
    try {
      const out = await callHalted(dir);
      ledger = out.ledger;
      const effect = (await ledger.effects()).find((e) => e.row.ref === out.ref);
      assert.equal(effect?.row.effectClass, "memory.get:halted");
      const row = effect!.row;
      const extract = signEffectExtract(
        {
          deciderId: "verax-proxy",
          channelId: "verax-body",
          windowStartMs: 1,
          windowEndMs: 2,
          effects: [
            { ref: out.ref, effectHash: row.effectHash, effectClass: "memory.get:halted", timestampMs: 1, actor: "brain-m" },
            { ref: out.ref, effectHash: row.effectHash, effectClass: "memory.get:other", timestampMs: 1, actor: "brain-m" },
          ],
        },
        EFFECT_SIGNER.privateKeyPem,
        EFFECT_SIGNER.publicKeyPem,
      );
      const explained = await explain(ledger, out.ref, { extract });
      assert.equal(
        explained.balanced,
        false,
        `two rows for one ref: balanced=${explained.balanced} finding=${explained.finding.code}`,
      );
    } finally {
      ledger?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a bound :halted ledger row does not excuse a presented extract with the right hash and another class", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1m-extract-class-"));
    let ledger: FileLedger | undefined;
    try {
      const out = await callHalted(dir);
      ledger = out.ledger;
      const effect = (await ledger.effects()).find((e) => e.row.ref === out.ref);
      assert.equal(effect?.row.effectClass, "memory.get:halted");
      const extract = signEffectExtract(
        {
          deciderId: "verax-proxy",
          channelId: "verax-body",
          windowStartMs: 1,
          windowEndMs: 2,
          effects: [
            {
              ref: out.ref,
              effectHash: effect!.row.effectHash,
              effectClass: "memory.get:other",
              timestampMs: 1,
              actor: "brain-m",
            },
          ],
        },
        EFFECT_SIGNER.privateKeyPem,
        EFFECT_SIGNER.publicKeyPem,
      );
      const explained = await explain(ledger, out.ref, { extract });
      assert.equal(
        explained.balanced,
        false,
        `the audited row is the extract: balanced=${explained.balanced} finding=${explained.finding.code}`,
      );
    } finally {
      ledger?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
