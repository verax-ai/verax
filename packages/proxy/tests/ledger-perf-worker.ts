import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { SignedDecisionRecord } from "@cedulon/core";

import { FileLedger, ledgerFs } from "../src/ledger.ts";

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

const ledger = new FileLedger(mkdtempSync(join(tmpdir(), "verax-perf-")));
let decisionReads = 0;
const origRead = ledgerFs.readFile.bind(ledgerFs);
const origReadSync = ledgerFs.readFileSync.bind(ledgerFs);
ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
  if (String(path).endsWith("decisions.jsonl")) decisionReads += 1;
  return origRead(path, ...(rest as []));
}) as typeof ledgerFs.readFile;
ledgerFs.readFileSync = ((path: Parameters<typeof origReadSync>[0], ...rest: unknown[]) => {
  if (String(path).endsWith("decisions.jsonl")) decisionReads += 1;
  return origReadSync(path, ...(rest as []));
}) as typeof ledgerFs.readFileSync;

const times: number[] = [];
for (let i = 0; i < 2000; i += 1) {
  const t0 = performance.now();
  await ledger.appendDecisionChained((prev) => cheapRecord(i, prev));
  times.push(performance.now() - t0);
}
ledger.close();
ledgerFs.readFile = origRead;
ledgerFs.readFileSync = origReadSync;
const first = times.slice(0, 100).reduce((a, b) => a + b, 0);
const last = times.slice(1900, 2000).reduce((a, b) => a + b, 0);
const ratio = last / first;
process.stdout.write(
  `ledger-perf last/first=${ratio.toFixed(3)} firstMs=${first.toFixed(1)} lastMs=${last.toFixed(1)} decisionReads=${decisionReads}\n`,
);
process.exit(decisionReads === 0 ? 0 : 1);
