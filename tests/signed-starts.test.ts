import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { readStartSummary, recordBodyStart } from "../packages/body/src/heartbeat.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function temp(): string {
  return mkdtempSync(join(tmpdir(), "verax-signed-starts-"));
}

function lines(dir: string): string[] {
  return readFileSync(join(dir, "starts.jsonl"), "utf8").split("\n").filter((l) => l !== "");
}

function write(dir: string, rows: string[]): void {
  writeFileSync(join(dir, "starts.jsonl"), `${rows.join("\n")}\n`, "utf8");
}

/**
 * A start row says how long the body was gone. Signed by the record key and
 * chained to the row before it, a changed gap or a row taken from the middle
 * is named by verify instead of being read as written.
 */
describe("signed start rows", () => {
  it("are v2, signed, chained, and verify under the record key", () => {
    const dir = temp();
    const k = keys();
    try {
      recordBodyStart(dir, 1_000, k);
      recordBodyStart(dir, 2_000, k);
      const rows = lines(dir).map((l) => JSON.parse(l) as { v?: number; sig?: string; prevStartHash?: string | null });
      assert.equal(rows.length, 2);
      assert.equal(rows[0]!.v, 2);
      assert.equal(typeof rows[0]!.sig, "string");
      assert.equal(rows[0]!.prevStartHash, null);
      assert.match(String(rows[1]!.prevStartHash), /^[0-9a-f]{64}$/);
      const summary = readStartSummary(dir, k.publicKeyPem, "pinned");
      assert.deepEqual(summary.problems, []);
      assert.equal(summary.signed, 2);
      assert.equal(summary.signedVerified, 2);
      assert.equal(summary.unsigned, false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a changed gap no longer verifies", () => {
    const dir = temp();
    const k = keys();
    try {
      recordBodyStart(dir, 1_000, k);
      const row = JSON.parse(lines(dir)[0]!) as { gapMs: number | null; prevBeatAtMs: number | null };
      row.prevBeatAtMs = 999;
      row.gapMs = 1;
      write(dir, [JSON.stringify(row)]);
      const summary = readStartSummary(dir, k.publicKeyPem, "pinned");
      assert.ok(summary.problems.some((p) => p.startsWith("start signature does not verify")), JSON.stringify(summary));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a row taken from the middle breaks the chain", () => {
    const dir = temp();
    const k = keys();
    try {
      recordBodyStart(dir, 1_000, k);
      recordBodyStart(dir, 2_000, k);
      recordBodyStart(dir, 3_000, k);
      const all = lines(dir);
      write(dir, [all[0]!, all[2]!]);
      const summary = readStartSummary(dir, k.publicKeyPem, "pinned");
      assert.ok(summary.problems.some((p) => p.startsWith("start chain breaks at starts.jsonl line 2")), JSON.stringify(summary));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an unsigned row after a signed one is named", () => {
    const dir = temp();
    const k = keys();
    try {
      recordBodyStart(dir, 1_000, k);
      recordBodyStart(dir, 2_000);
      const summary = readStartSummary(dir, k.publicKeyPem, "pinned");
      assert.ok(summary.problems.some((p) => p.startsWith("unsigned start row after a signed one")), JSON.stringify(summary));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("another key does not verify them; no key counts them unchecked", () => {
    const dir = temp();
    const k = keys();
    try {
      recordBodyStart(dir, 1_000, k);
      const other = readStartSummary(dir, keys().publicKeyPem, "pinned");
      assert.ok(other.problems.some((p) => p.startsWith("start signature does not verify")));
      const none = readStartSummary(dir);
      assert.deepEqual(none.problems, []);
      assert.equal(none.signed, 1);
      assert.equal(none.signedVerified, 0);
      assert.equal(none.startKey, "none");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("older unsigned rows before the first signed one stay readable", () => {
    const dir = temp();
    const k = keys();
    try {
      recordBodyStart(dir, 1_000);
      recordBodyStart(dir, 2_000, k);
      const summary = readStartSummary(dir, k.publicKeyPem, "pinned");
      assert.deepEqual(summary.problems, []);
      assert.equal(summary.unsigned, true);
      assert.equal(summary.signedVerified, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verax verify fails on a changed signed start, under the key the records carry", async () => {
    const dir = temp();
    const k = keys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: k,
      effectSigner: k,
      now: () => 5_000,
      nonce: () => "start-1",
    });
    try {
      const allowed = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "note-start-1",
            body: { t: 1 },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999,
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:memory"]) },
      );
      assert.equal(allowed.isError, false);
    } finally {
      services.ledger.close();
    }
    try {
      recordBodyStart(dir, 6_000, k);
      const clean: string[] = [];
      await runVerify([dir], (s) => clean.push(s));
      assert.match(clean.join("\n"), /1 of 1 signed verify under the in-ledger record key/);
      assert.doesNotMatch(clean.join("\n"), /start signature does not verify/);
      const row = JSON.parse(lines(dir)[0]!) as { pid: number };
      row.pid += 1;
      write(dir, [JSON.stringify(row)]);
      const out: string[] = [];
      assert.equal(await runVerify([dir], (s) => out.push(s)), 1);
      assert.match(out.join("\n"), /start signature does not verify/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
