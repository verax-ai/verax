import { strict as assert } from "node:assert";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { signDecisionRecord } from "@cedulon/core";

import { effectDescriptor, sha256Canonical } from "../src/hash.ts";
import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import type { DecisionInputs } from "../src/types.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, tickingNow } from "./helpers.ts";

const policy = loadPolicy({
  version: 1,
  default: "deny",
  rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
});

const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

function historyLine(action: "halt" | "resume", atMs: number, by = "op", via: "cli" | "http" = "cli"): string {
  return JSON.stringify({ action, atMs, by, via });
}

function writeHistory(dir: string, line: string): void {
  appendFileSync(join(dir, "halt-history.jsonl"), `${line}\n`, "utf8");
}

function inputsFor(dir: string, ref: string): DecisionInputs {
  const text = readFileSync(join(dir, "inputs.jsonl"), "utf8");
  let found: DecisionInputs | undefined;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: DecisionInputs };
    if (row.ref === ref && row.inputs) found = row.inputs;
  }
  if (!found) throw new Error(`inputs-missing:${ref}`);
  return found;
}

async function openProxy(dir: string) {
  const ledger = new FileLedger(dir);
  let n = 0;
  let innerCalls = 0;
  const proxy = createProxy({
    policy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(1_700_000_000_000, 10),
    nonce: () => `n-${++n}`,
    inner: async () => {
      innerCalls += 1;
      return { content: [{ type: "text", text: "ok" }], isError: false };
    },
  });
  return {
    ledger,
    proxy,
    innerCalls: () => innerCalls,
  };
}

describe("signed halt and resume", () => {
  it("T1 CLI halt then a call records allow verax.halt before deny halted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t1-"));
    const line = historyLine("halt", 1000);
    writeFileSync(join(dir, "halted"), "", "utf8");
    writeHistory(dir, line);
    const { ledger, proxy, innerCalls } = await openProxy(dir);
    try {
      const result = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.equal(innerCalls(), 0);
      assert.equal(result.isError, true);
      assert.match(result.content[0]?.text ?? "", /^denied:halted:/);
      const decisions = await ledger.decisions();
      assert.deepEqual(
        decisions.map((d) => [d.claims.decision, d.claims.subject, d.claims.reasonCode]),
        [
          ["allow", "verax.halt", "operator-halt"],
          ["deny", "memory.get", "halted"],
        ],
      );
      const halt = decisions[0]!;
      const bound = sha256Canonical({ action: "halt", atMs: 1000, by: "op", via: "cli", line: 0 });
      assert.equal(halt.claims.effectClass, "verax.control");
      assert.equal(halt.claims.effectHash, bound);
      assert.equal(halt.claims.requestHash, bound);
      const inputs = inputsFor(dir, halt.claims.ref ?? "");
      assert.equal(inputs.control?.line, 0);
      assert.equal(inputs.control?.lineHash, sha256Canonical(line));
      assert.equal(halt.claims.inputsHash, sha256Canonical(inputs));
      const effect = (await ledger.effects()).find((e) => e.row.ref === halt.claims.ref);
      assert.equal(effect?.row.effectClass, "verax.control");
      assert.equal(effect?.row.effectHash, bound);
    } finally {
      ledger.close();
    }
  });

  it("T2 halt and resume in history before any call record both then the call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t2-"));
    writeHistory(dir, historyLine("halt", 1000));
    writeHistory(dir, historyLine("resume", 2000));
    const { ledger, proxy, innerCalls } = await openProxy(dir);
    try {
      const result = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.equal(result.isError, false);
      assert.equal(innerCalls(), 1);
      const decisions = await ledger.decisions();
      assert.deepEqual(
        decisions.map((d) => [d.claims.decision, d.claims.subject, d.claims.reasonCode]),
        [
          ["allow", "verax.halt", "operator-halt"],
          ["allow", "verax.resume", "operator-resume"],
          ["allow", "memory.get", "allow"],
        ],
      );
    } finally {
      ledger.close();
    }
  });

  it("T4 two calls and a reopened body record a single halt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t4-"));
    writeFileSync(join(dir, "halted"), "", "utf8");
    writeHistory(dir, historyLine("halt", 1000));
    let ledger = new FileLedger(dir);
    try {
      let n = 0;
      const make = () =>
        createProxy({
          policy,
          recordSigner: RECORD_SIGNER,
          effectSigner: EFFECT_SIGNER,
          ledger,
          now: tickingNow(1_700_000_000_000, 10),
          nonce: () => `n-${++n}`,
          inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
        });
      const first = make();
      await first.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      await first.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.equal((await ledger.decisions()).filter((d) => d.claims.subject === "verax.halt").length, 1);
      ledger.close();
      ledger = new FileLedger(dir);
      n = 100;
      const reopened = make();
      await reopened.syncControlRecords();
      await reopened.call({ name: "memory.get", arguments: { id: "c" } }, reader);
      assert.equal((await ledger.decisions()).filter((d) => d.claims.subject === "verax.halt").length, 1);
    } finally {
      ledger.close();
    }
  });

  it("T4 two overlapping calls record a single halt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t4b-"));
    writeFileSync(join(dir, "halted"), "", "utf8");
    writeHistory(dir, historyLine("halt", 1000));
    const { ledger, proxy } = await openProxy(dir);
    try {
      await Promise.all([
        proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader),
        proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader),
      ]);
      const decisions = await ledger.decisions();
      assert.equal(decisions.filter((d) => d.claims.subject === "verax.halt").length, 1);
      assert.equal(decisions.filter((d) => d.claims.reasonCode === "halted").length, 2);
    } finally {
      ledger.close();
    }
  });

  it("T5 a halted file with no history records one via file halt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t5-"));
    writeFileSync(join(dir, "halted"), "", "utf8");
    const { ledger, proxy } = await openProxy(dir);
    try {
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      const halts = (await ledger.decisions()).filter((d) => d.claims.subject === "verax.halt");
      assert.equal(halts.length, 1);
      const inputs = inputsFor(dir, halts[0]!.claims.ref ?? "");
      assert.equal(inputs.control?.via, "file");
      assert.equal(inputs.control?.by, "unknown");
      assert.equal(inputs.control?.line, -1);
      assert.equal(inputs.control?.action, "halt");
    } finally {
      ledger.close();
    }
  });

  it("T6 a shortened history records one halt-history-mismatch and the body keeps running", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t6-"));
    const halt = historyLine("halt", 1000);
    writeHistory(dir, halt);
    writeHistory(dir, historyLine("resume", 2000));
    const { ledger, proxy, innerCalls } = await openProxy(dir);
    try {
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      writeFileSync(join(dir, "halt-history.jsonl"), `${halt}\n`, "utf8");
      const again = await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.equal(again.isError, false);
      assert.equal(innerCalls(), 2);
      await proxy.call({ name: "memory.get", arguments: { id: "c" } }, reader);
      const mismatches = (await ledger.decisions()).filter((d) => d.claims.reasonCode === "halt-history-mismatch");
      assert.equal(mismatches.length, 1);
      assert.equal(mismatches[0]!.claims.decision, "deny");
      assert.equal(mismatches[0]!.claims.subject, "verax.control");
    } finally {
      ledger.close();
    }
  });

  it("T7 verifyLedger flags allow-while-halted and accepts a clean window", async () => {
    const dirty = mkdtempSync(join(tmpdir(), "verax-signed-halt-t7-"));
    writeFileSync(join(dirty, "halted"), "", "utf8");
    writeHistory(dirty, historyLine("halt", 1000));
    const opened = await openProxy(dirty);
    try {
      await opened.proxy.syncControlRecords();
      const effectHash = sha256Canonical(effectDescriptor("memory.get", { id: "mid" }));
      const inputs = { principal: { brain: "brain-1", scopes: ["verax:read"] }, inputs: [] };
      await opened.ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.get",
            requestHash: sha256Canonical({ name: "memory.get", arguments: { id: "mid" } }),
            policyHash: policy.hash,
            inputsHash: sha256Canonical(inputs),
            decision: "allow",
            reasonCode: "allow",
            ref: "mid-allow",
            effectHash,
            effectClass: "memory.get",
            timestampMs: 40,
            nonce: "mid-allow",
            prevRecordHash: prev,
          },
          RECORD_SIGNER.privateKeyPem,
          RECORD_SIGNER.publicKeyPem,
        ),
      );
      await opened.ledger.appendEffect(
        {
          ref: "mid-allow",
          effectHash,
          effectClass: "memory.get",
          timestampMs: 41,
          actor: "brain-1",
        },
        "self",
        sha256Canonical({ ok: true }),
      );
      rmSync(join(dirty, "halted"));
      writeHistory(dirty, historyLine("resume", 2000));
      await opened.proxy.syncControlRecords();
      const violated = await verifyLedger(dirty);
      assert.equal(violated.ok, false);
      assert.ok(
        violated.problems.some((p) => p === "allow-while-halted mid-allow"),
        JSON.stringify(violated.problems),
      );
      assert.equal(violated.effectsOrphaned, 0, JSON.stringify(violated.problems));
    } finally {
      opened.ledger.close();
    }

    const clean = mkdtempSync(join(tmpdir(), "verax-signed-halt-t7c-"));
    writeHistory(clean, historyLine("halt", 1000));
    writeHistory(clean, historyLine("resume", 2000));
    const resumed = await openProxy(clean);
    try {
      await resumed.proxy.syncControlRecords();
      await resumed.proxy.call({ name: "memory.get", arguments: { id: "after" } }, reader);
      const result = await verifyLedger(clean);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.control.windows, 1);
      assert.deepEqual(result.control.warnings, []);
      assert.deepEqual(result.problems, []);
    } finally {
      resumed.ledger.close();
    }
  });

  it("T7 a deny halted outside a halt window warns and stays ok", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t7w-"));
    const ledger = new FileLedger(dir);
    try {
      const inputs = { principal: { brain: "brain-1", scopes: ["verax:read"] }, inputs: [] };
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.get",
            requestHash: sha256Canonical({ name: "memory.get", arguments: { id: "old" } }),
            policyHash: policy.hash,
            inputsHash: sha256Canonical(inputs),
            decision: "deny",
            reasonCode: "halted",
            ref: "old-halt",
            effectHash: null,
            effectClass: "memory.get",
            timestampMs: 10,
            nonce: "old-halt",
            prevRecordHash: prev,
          },
          RECORD_SIGNER.privateKeyPem,
          RECORD_SIGNER.publicKeyPem,
        ),
      );
      const result = await verifyLedger(dir);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.control.line, "control: no control records");
      assert.deepEqual(result.control.warnings, ["halted-deny-without-halt-record old-halt"]);
      assert.deepEqual(result.problems, []);
    } finally {
      ledger.close();
    }
  });

  it("T8 control-record effects are bound", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t8-"));
    writeFileSync(join(dir, "halted"), "", "utf8");
    writeHistory(dir, historyLine("halt", 1000));
    const { ledger, proxy } = await openProxy(dir);
    try {
      await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      const effects = await ledger.effects();
      const control = effects.find((e) => e.row.effectClass === "verax.control");
      assert.ok(control?.attestation?.coseHex);
      assert.ok(control?.receipt);
      const halt = (await ledger.decisions()).find((d) => d.claims.subject === "verax.halt");
      assert.equal(control?.row.effectHash, halt?.claims.effectHash);
      const result = await verifyLedger(dir);
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.effectsOrphaned, 0);
      assert.equal(result.effectsBound, 1);
      assert.equal(result.control.windows, 1);
    } finally {
      ledger.close();
    }
  });

  it("T9 twenty calls read decisions once and a CLI halt line is recorded without rereading", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t9-"));
    const ledger = new FileLedger(dir);
    let decisionReads = 0;
    const counting = new Proxy(ledger, {
      get(target, prop) {
        if (prop === "decisions") {
          return async () => {
            decisionReads += 1;
            return target.decisions();
          };
        }
        const value = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as FileLedger;
    let n = 0;
    const proxy = createProxy({
      policy,
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: counting,
      now: tickingNow(1_700_000_000_000, 10),
      nonce: () => `n-${++n}`,
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      for (let i = 0; i < 20; i += 1) {
        if (i === 10) writeHistory(dir, historyLine("halt", 3000));
        const result = await proxy.call({ name: "memory.get", arguments: { id: `t9-${i}` } }, reader);
        assert.equal(result.isError, false);
      }
      assert.equal(decisionReads, 1);
      const decisions = await ledger.decisions();
      const halts = decisions.filter((d) => d.claims.subject === "verax.halt");
      assert.equal(halts.length, 1);
      assert.equal(halts[0]!.claims.reasonCode, "operator-halt");
      const inputs = inputsFor(dir, halts[0]!.claims.ref ?? "");
      assert.equal(inputs.control?.action, "halt");
      assert.equal(inputs.control?.via, "cli");
      assert.equal(inputs.control?.line, 0);
      const haltAt = decisions.findIndex((d) => d.claims.subject === "verax.halt");
      assert.equal(haltAt, 10);
    } finally {
      ledger.close();
    }
  });

  it("T10 a deleted halted file records one via file resume and verify stays ok", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-halt-t10-"));
    const haltPath = join(dir, "halted");
    writeFileSync(haltPath, "", "utf8");
    const { ledger, proxy } = await openProxy(dir);
    try {
      const stopped = await proxy.call({ name: "memory.get", arguments: { id: "a" } }, reader);
      assert.match(stopped.content[0]?.text ?? "", /^denied:halted:/);
      rmSync(haltPath);
      const resumed = await proxy.call({ name: "memory.get", arguments: { id: "b" } }, reader);
      assert.equal(resumed.isError, false);
      const decisions = await ledger.decisions();
      assert.deepEqual(
        decisions.map((d) => [d.claims.decision, d.claims.subject, d.claims.reasonCode]),
        [
          ["allow", "verax.halt", "operator-halt"],
          ["deny", "memory.get", "halted"],
          ["allow", "verax.resume", "operator-resume"],
          ["allow", "memory.get", "allow"],
        ],
      );
      const halt = inputsFor(dir, decisions[0]!.claims.ref ?? "");
      const resume = inputsFor(dir, decisions[2]!.claims.ref ?? "");
      assert.equal(halt.control?.action, "halt");
      assert.equal(halt.control?.via, "file");
      assert.equal(halt.control?.by, "unknown");
      assert.equal(halt.control?.line, -1);
      assert.equal(resume.control?.action, "resume");
      assert.equal(resume.control?.via, "file");
      assert.equal(resume.control?.by, "unknown");
      assert.equal(resume.control?.line, -1);
      const verified = await verifyLedger(dir);
      assert.equal(verified.ok, true, JSON.stringify(verified.problems));
      assert.equal(
        verified.problems.some((problem) => problem.startsWith("allow-while-halted")),
        false,
        JSON.stringify(verified.problems),
      );
    } finally {
      ledger.close();
    }
  });
});
