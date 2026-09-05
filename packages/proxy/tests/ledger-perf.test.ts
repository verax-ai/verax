import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import type { SignedDecisionRecord } from "@cedulon/core";

import { FileLedger, ledgerFs } from "../src/ledger.ts";
import { createProxy } from "../src/proxy.ts";
import { loadPolicy } from "../src/policy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const worker = join(here, "ledger-perf-worker.ts");
const policy = loadPolicy(readFileSync(join(here, "..", "policy", "default.json"), "utf8"));

type HandleSync = {
  sync: (...args: unknown[]) => Promise<unknown>;
};

function cheapRecord(i: number, prev: string | null): SignedDecisionRecord {
  return {
    claims: {
      decider: "verax-proxy",
      subject: "memory.get",
      requestHash: "00".repeat(32),
      policyHash: "00".repeat(32),
      inputsHash: "00".repeat(32),
      decision: "allow",
      reasonCode: "allow",
      ref: `perf-${i}`,
      effectHash: "11".repeat(32),
      timestampMs: i,
      nonce: `perf-${i}`,
      prevRecordHash: prev,
    },
    publicKeyPem: "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----\n",
    encoding: "cose",
    coseHex: i.toString(16).padStart(128, "0"),
  };
}

describe("B8 FileLedger append cost and durability", () => {
  it("2000 chained appends reread decisions.jsonl zero times (wall-clock ratio is printed, not asserted)", () => {
    const ran = spawnSync(process.execPath, ["--experimental-strip-types", worker], {
      encoding: "utf8",
      timeout: 60_000,
    });
    const text = `${ran.stdout}${ran.stderr}`;
    const line = text.split(/\r?\n/).find((row) => row.startsWith("ledger-perf "));
    assert.ok(line, text);
    console.log(line);
    assert.equal(ran.status, 0, `${line}\n${text}`);
    const reads = Number(/decisionReads=([0-9]+)/.exec(line)?.[1]);
    assert.equal(reads, 0, line);
  });

  it("chained append does not reread decisions.jsonl", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-reread-"));
    const ledger = new FileLedger(dir);
    let reads = 0;
    const origRead = ledgerFs.readFile.bind(ledgerFs);
    const origReadSync = ledgerFs.readFileSync.bind(ledgerFs);
    ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
      if (String(path).endsWith("decisions.jsonl")) reads += 1;
      return origRead(path, ...(rest as []));
    }) as typeof ledgerFs.readFile;
    ledgerFs.readFileSync = ((path: Parameters<typeof origReadSync>[0], ...rest: unknown[]) => {
      if (String(path).endsWith("decisions.jsonl")) reads += 1;
      return origReadSync(path, ...(rest as []));
    }) as typeof ledgerFs.readFileSync;
    try {
      for (let i = 0; i < 200; i += 1) {
        await ledger.appendDecisionChained((prev) => cheapRecord(i, prev));
      }
      assert.equal(reads, 0, `decision rereads during append: ${reads}`);
    } finally {
      ledgerFs.readFile = origRead;
      ledgerFs.readFileSync = origReadSync;
      ledger.close();
    }
  });

  it("fsyncs once per append", async () => {
    const probeDir = mkdtempSync(join(tmpdir(), "verax-sync-probe-"));
    const probe = join(probeDir, "p");
    writeFileSync(probe, "");
    const probeFh = await fsp.open(probe, "r");
    const proto = Object.getPrototypeOf(probeFh) as HandleSync;
    await probeFh.close();
    let syncs = 0;
    const origSync = proto.sync;
    proto.sync = async function syncWrapped(this: unknown, ...args: unknown[]) {
      syncs += 1;
      return origSync.apply(this, args);
    };
    const dir = mkdtempSync(join(tmpdir(), "verax-fsync-"));
    const ledger = new FileLedger(dir);
    try {
      await ledger.appendDecision(cheapRecord(0, null));
      await ledger.appendDecision(cheapRecord(1, "aa".repeat(32)));
      await ledger.appendEffect(
        {
          ref: "e1",
          effectHash: "22".repeat(32),
          effectClass: "memory.get",
          timestampMs: 1,
        },
        "self",
        "33".repeat(32),
      );
      assert.equal(syncs, 3, `fsync count ${syncs} (want 1 per append)`);
    } finally {
      proto.sync = origSync;
      ledger.close();
    }
  });

  it("a deny proxy call fsyncs the inputs document and the decision", async () => {
    const probeDir = mkdtempSync(join(tmpdir(), "verax-inputs-sync-probe-"));
    const probe = join(probeDir, "p");
    writeFileSync(probe, "");
    const probeFh = await fsp.open(probe, "r");
    const proto = Object.getPrototypeOf(probeFh) as HandleSync;
    await probeFh.close();
    let syncs = 0;
    const origSync = proto.sync;
    proto.sync = async function syncWrapped(this: unknown, ...args: unknown[]) {
      syncs += 1;
      return origSync.apply(this, args);
    };
    const dir = mkdtempSync(join(tmpdir(), "verax-inputs-fsync-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["deny-fsync-1"]),
        inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
      });
      await proxy.call({ name: "memory.get", arguments: { id: "x" } }, { brain: "brain-1", scopes: new Set() });
      assert.equal(syncs, 2, `fsync count ${syncs} (want inputs + decision)`);
    } finally {
      proto.sync = origSync;
      ledger.close();
    }
  });
});
