// GET /api/ledger?from&to answers a time window of the ledger. Measured on
// 17 Sep 2026 with 100k decisions, the 24-hour window cost 1.5 s: the body
// read the whole of decisions.jsonl, effects.jsonl and inputs.jsonl and
// filtered in memory, so a window of 3% of the rows cost 40% of reading them
// all. The files are append-only and time-ordered; the window is at the end.
//
// This guard builds a ledger of 1200 decisions, asks for the last ten, and
// checks two things through the ledgerFs seam of the built proxy: none of
// the three files is read whole, and the bytes read stay near one chunk per
// file. It also checks the answer against what a full read would filter to,
// and that `limit` cuts the window from the newest end and says so.

import { strict as assert } from "node:assert";
import { mkdtempSync, statSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import type { SignedDecisionRecord } from "@cedulon/core";

import { listen } from "../packages/body/src/server.ts";
import { ledgerFs as builtLedgerFs } from "../packages/proxy/dist/ledger.js";
import { sha256Canonical } from "../packages/proxy/src/hash.ts";
import { inputsLogFor } from "../packages/proxy/src/inputs.ts";
import { FileLedger, ledgerFs } from "../packages/proxy/src/ledger.ts";
import type { DecisionInputs } from "../packages/proxy/src/types.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const N = 1200;
const BASE_MS = 1_700_000_000_000;
const tsOf = (i: number) => BASE_MS + i * 1000;
const refOf = (i: number) => `w-${i}`;

function inputsOf(i: number): DecisionInputs {
  return {
    principal: { brain: "fixture", scopes: ["verax:read"] },
    inputs: [{ id: `k${i}`, versionHash: "00".repeat(32), validFromMs: 0, validUntilMs: 9_000_000_000_000 }],
  };
}

function record(i: number, prev: string | null): SignedDecisionRecord {
  return {
    claims: {
      decider: "verax-proxy",
      subject: "memory.get",
      requestHash: "00".repeat(32),
      policyHash: "00".repeat(32),
      inputsHash: sha256Canonical(inputsOf(i)),
      decision: "allow",
      reasonCode: "allow",
      ref: refOf(i),
      effectClass: "memory.get",
      effectHash: "11".repeat(32),
      timestampMs: tsOf(i),
      nonce: `n-${i}`,
      prevRecordHash: prev,
    },
    publicKeyPem: "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----\n",
    encoding: "cose",
    coseHex: i.toString(16).padStart(128, "0"),
  };
}

/** A ledger of N decisions, one inputs row each, an effect for every even one. Written without fsync. */
async function buildLedger(dir: string): Promise<void> {
  const realOpen = ledgerFs.open;
  ledgerFs.open = (async (path: string, flags: string) => {
    const fh = await open(path, flags);
    return { write: (data: string) => fh.write(data), sync: async () => undefined, close: () => fh.close() };
  }) as unknown as typeof open;
  const ledger = new FileLedger(dir);
  const inputs = inputsLogFor(ledger);
  try {
    for (let i = 0; i < N; i += 1) {
      await inputs.append(refOf(i), inputsOf(i));
      await ledger.appendDecisionChained((prev) => record(i, prev));
      if (i % 2 === 0) {
        await ledger.appendEffect({ ref: refOf(i), effectHash: "22".repeat(32), effectClass: "memory.get", timestampMs: tsOf(i) + 5 });
      }
    }
  } finally {
    ledger.close();
    ledgerFs.open = realOpen;
  }
}

type LedgerAnswer = {
  decisions: { claims: { ref: string } }[];
  effects: { row: { ref: string } }[];
  inputs: Record<string, unknown>;
  more?: boolean;
};

describe("api/ledger window", () => {
  it("answers the window from the end of the files, and limit cuts it from the newest end", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-ledger-window-"));
    await buildLedger(stateDir);
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      tlsTerminated: false,
    });
    const bodyPort = (server.address() as { port: number }).port;
    const origOpen = builtLedgerFs.open;
    const origRead = builtLedgerFs.readFile;
    const ledgerFile = (path: unknown): string | null => {
      const name = String(path).split(/[\\/]/).pop() ?? "";
      return name === "decisions.jsonl" || name === "effects.jsonl" || name === "inputs.jsonl" ? name : null;
    };
    let bytesRead = 0;
    const wholeReads: string[] = [];
    builtLedgerFs.open = (async (...args: unknown[]) => {
      const fh = await (origOpen as (...a: unknown[]) => ReturnType<typeof open>)(...args);
      if (ledgerFile(args[0])) {
        const read = fh.read.bind(fh);
        (fh as { read: unknown }).read = async (...readArgs: unknown[]) => {
          const out = await (read as (...a: unknown[]) => Promise<{ bytesRead: number }>)(...readArgs);
          bytesRead += out.bytesRead;
          return out;
        };
      }
      return fh;
    }) as typeof builtLedgerFs.open;
    builtLedgerFs.readFile = (async (...args: unknown[]) => {
      const name = ledgerFile(args[0]);
      if (name) wholeReads.push(name);
      return (origRead as (...a: unknown[]) => Promise<unknown>)(...args);
    }) as typeof builtLedgerFs.readFile;
    try {
      const audit = await issuer.sign({ scope: "verax:read verax:audit" });
      const ask = async (query: string): Promise<LedgerAnswer> => {
        const res = await fetch(`http://127.0.0.1:${bodyPort}/api/ledger?${query}`, {
          headers: { authorization: `Bearer ${audit}` },
        });
        assert.equal(res.status, 200);
        return (await res.json()) as LedgerAnswer;
      };

      // The last ten decisions by time.
      const tail = await ask(`from=${tsOf(N - 10)}&to=9999999999999`);
      assert.deepEqual(
        tail.decisions.map((d) => d.claims.ref),
        Array.from({ length: 10 }, (_, k) => refOf(N - 10 + k)),
      );
      assert.deepEqual(
        tail.effects.map((e) => e.row.ref),
        Array.from({ length: 10 }, (_, k) => N - 10 + k).filter((i) => i % 2 === 0).map(refOf),
      );
      assert.deepEqual(Object.keys(tail.inputs).sort(), Array.from({ length: 10 }, (_, k) => refOf(N - 10 + k)).sort());

      const fileBytes = ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]
        .map((n) => statSync(join(stateDir, n)).size)
        .reduce((a, b) => a + b, 0);
      assert.ok(fileBytes > 600 * 1024, `fixture too small to prove anything: ${fileBytes} bytes`);
      assert.deepEqual(wholeReads, [], `a ledger file was read whole: ${wholeReads.join(", ")}`);
      // The reader steps 64 KiB at a time; ten rows need one step per file,
      // two when the oldest of them straddles a step.
      assert.ok(bytesRead <= 6 * 64 * 1024, `read ${bytesRead} bytes for ten rows out of ${fileBytes}`);
      assert.equal(tail.more, false);

      // limit takes the newest rows and says there are more.
      const limited = await ask(`from=0&to=9999999999999&limit=5`);
      assert.deepEqual(
        limited.decisions.map((d) => d.claims.ref),
        Array.from({ length: 5 }, (_, k) => refOf(N - 5 + k)),
      );
      assert.deepEqual(limited.effects.map((e) => e.row.ref), [refOf(N - 4), refOf(N - 2)]);
      assert.equal(limited.more, true);

      // No limit and from=0 is what the panel asks today: everything, still.
      const all = await ask(`from=0&to=9999999999999`);
      assert.equal(all.decisions.length, N);
      assert.equal(all.effects.length, N / 2);
      assert.equal(all.more, false);
    } finally {
      builtLedgerFs.open = origOpen;
      builtLedgerFs.readFile = origRead;
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
