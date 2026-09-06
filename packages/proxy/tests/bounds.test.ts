import { strict as assert } from "node:assert";
import { mkdtempSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy, LedgerDenyUnrecorded } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";
import { diskProbe } from "../src/disk.ts";

const BASE_RULES = [
  { id: "get", tool: "memory.get", requires: ["verax:read"], text: "Reads need the read scope." },
];

const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

function policyOf(limits: Record<string, unknown>) {
  return loadPolicy({ version: 1, default: "deny", limits, rules: BASE_RULES });
}

describe("S3 damage limits", () => {
  it("rate-limited: only allow and defer count; a deny does not", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy: policyOf({ ratePerMinute: 1 }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_700_000_000_000, 10),
      nonce: queuedNonce(["r1", "r2", "r3"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const denied = await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
    assert.match(denied.content[0]?.text ?? "", /denied:scope-missing:/);
    const first = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
    assert.equal(first.isError, false);
    const second = await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
    assert.match(second.content[0]?.text ?? "", /denied:rate-limited:r3/);
    const recs = await ledger.decisions();
    assert.equal(recs.filter((d) => d.claims.reasonCode === "rate-limited").length, 1);
    assert.equal(recs.filter((d) => d.claims.decision === "deny" && d.claims.reasonCode === "scope-missing").length, 1);
  });

  it("unreadable FileLedger counts fail closed as rate-limited", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-counts-"));
    writeFileSync(join(dir, "decisions.jsonl"), "{not-json\n", { encoding: "utf8" });
    const ledger = new FileLedger(dir);
    assert.equal(ledger.countsReadable, false);
    const proxy = createProxy({
      policy: policyOf({ ratePerMinute: 100 }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["u-file"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const out = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.match(out.content[0]?.text ?? "", /denied:rate-limited:u-file/);
    } finally {
      ledger.close();
    }
  });

  it("unreadable ledger counts fail closed as rate-limited", async () => {
    const ledger = new MemoryLedger();
    (ledger as { countsReadable?: boolean }).countsReadable = false;
    const proxy = createProxy({
      policy: policyOf({ ratePerMinute: 100 }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["u1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
    assert.match(out.content[0]?.text ?? "", /denied:rate-limited:u1/);
  });

  it("daily-limited is a signed deny", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy: policyOf({ dailyMax: 1 }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_700_000_000_000, 10),
      nonce: queuedNonce(["d1", "d2"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    assert.equal((await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader)).isError, false);
    const second = await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
    assert.match(second.content[0]?.text ?? "", /denied:daily-limited:d2/);
  });

  it("ledger-disk-low is a signed deny when the probe is low", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-disk-"));
    const ledger = new FileLedger(dir);
    const orig = diskProbe.freeBytes;
    diskProbe.freeBytes = (probeDir) => (probeDir === dir ? 1024 : orig(probeDir));
    const proxy = createProxy({
      policy: policyOf({ diskFreeBytes: 64 * 1024 * 1024 }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["disk-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const out = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.match(out.content[0]?.text ?? "", /denied:ledger-disk-low:disk-1/);
      const rec = (await ledger.decisions())[0]!;
      assert.equal(rec.claims.reasonCode, "ledger-disk-low");
    } finally {
      diskProbe.freeBytes = orig;
      ledger.close();
    }
  });

  it("unrecorded disk deny throws LedgerDenyUnrecorded and does not drop silently", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-disk-507-"));
    const ledger = new FileLedger(dir);
    const orig = diskProbe.freeBytes;
    diskProbe.freeBytes = (probeDir) => (probeDir === dir ? 0 : orig(probeDir));
    const origAppend = ledger.appendDecisionChained.bind(ledger);
    ledger.appendDecisionChained = async () => {
      throw new Error("ENOSPC");
    };
    const proxy = createProxy({
      policy: policyOf({}),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["disk-507"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      await assert.rejects(
        () => proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader),
        (err: unknown) => {
          assert.ok(err instanceof LedgerDenyUnrecorded);
          assert.equal(err.reasonCode, "ledger-disk-low");
          return true;
        },
      );
      assert.equal((await ledger.decisions()).length, 0);
    } finally {
      ledger.appendDecisionChained = origAppend;
      diskProbe.freeBytes = orig;
      ledger.close();
    }
  });

  it("halted still appends a signed deny", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-halt-"));
    writeFileSync(join(dir, "halted"), "", { encoding: "utf8" });
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: policyOf({}),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["halt-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const out = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.match(out.content[0]?.text ?? "", /denied:halted:halt-1/);
      const rec = (await ledger.decisions())[0]!;
      assert.equal(rec.claims.decision, "deny");
      assert.equal(rec.claims.reasonCode, "halted");
      assert.equal(typeof rec.coseHex, "string");
    } finally {
      ledger.close();
    }
  });

  it("clearing halted resumes work", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-halt-resume-"));
    const haltPath = join(dir, "halted");
    writeFileSync(haltPath, "", { encoding: "utf8" });
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: policyOf({}),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["halt-r1", "halt-r2"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const stopped = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.match(stopped.content[0]?.text ?? "", /denied:halted:halt-r1/);
      unlinkSync(haltPath);
      const resumed = await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.equal(resumed.isError, false);
    } finally {
      ledger.close();
    }
  });
});
