import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { recordBodyStart } from "../packages/body/src/heartbeat.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";

/**
 * R26-7. Signed start rows are for a reader facing someone who can write
 * `starts.jsonl` and cannot read the record key. A changed gap is named while
 * the row keeps its `v: 2`. With `v`, `prevStartHash` and `sig` taken off
 * every row the file reads as one written before signing: nothing is checked
 * and a three-day gap rewritten to one second verifies. No key is needed.
 *
 * A reader cannot tell such a file from a real one written by 0.4.8, so the
 * default stays. `--require-signed-starts` is for the reader who knows the
 * ledger was written by a signing body: every start row must then be signed.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const THREE_DAYS = 3 * 24 * 60 * 60 * 1000;

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

type Row = {
  action: string;
  atMs: number;
  prevBeatAtMs: number | null;
  gapMs: number | null;
  pid: number;
  v?: number;
  prevStartHash?: string | null;
  sig?: string;
};

function rows(dir: string): Row[] {
  return readFileSync(join(dir, "starts.jsonl"), "utf8")
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as Row);
}

function writeRows(dir: string, list: object[]): void {
  writeFileSync(join(dir, "starts.jsonl"), `${list.map((r) => JSON.stringify(r)).join("\n")}\n`, "utf8");
}

async function verify(dir: string, keyFile: string, ...flags: string[]): Promise<{ code: number; text: string }> {
  const out: string[] = [];
  const code = await runVerify([dir, "--key", keyFile, ...flags], (s) => out.push(s));
  return { code, text: out.join("\n") };
}

/** One decision at t=5000, a start before it and a start three days after its last beat. */
async function ledgerWithAThreeDayGap(dir: string): Promise<string> {
  const record = keys();
  const effect = keys();
  const services = createBodyServices({
    stateDir: dir,
    policyFile,
    recordSigner: record,
    effectSigner: effect,
    now: () => 5_000,
    nonce: () => "r26-7",
  });
  try {
    recordBodyStart(dir, 4_000, record);
    const allowed = await services.proxy.call(
      {
        name: "memory.put",
        arguments: { id: "note-1", body: { t: 1 }, source: { uri: "file://t", retrievedAtMs: 1 }, validUntilMs: 9_999 },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    assert.equal(allowed.isError, false);
  } finally {
    services.ledger.close();
  }
  const beat = JSON.parse(readFileSync(join(dir, "heartbeat.json"), "utf8")) as { atMs: number };
  recordBodyStart(dir, beat.atMs + THREE_DAYS, record);
  const keyFile = join(dir, "record-pin.pem");
  writeFileSync(keyFile, record.publicKeyPem, "utf8");
  return keyFile;
}

function stripped(list: Row[]): object[] {
  const edited = list.map((r) => ({ ...r }));
  edited[1]!.prevBeatAtMs = edited[1]!.atMs - 1_000;
  edited[1]!.gapMs = 1_000;
  return edited.map(({ v: _v, prevStartHash: _p, sig: _s, ...rest }) => rest);
}

describe("R26-7 start rows with their signatures taken off", () => {
  it("--require-signed-starts names every unsigned row and does not verify", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r26-7-"));
    try {
      const keyFile = await ledgerWithAThreeDayGap(dir);
      const honest = rows(dir);
      assert.equal(honest[1]!.gapMs, THREE_DAYS);
      writeRows(dir, stripped(honest));

      const after = await verify(dir, keyFile, "--require-signed-starts");
      assert.match(after.text, /start-row-unsigned: starts\.jsonl line 1/, after.text);
      assert.match(after.text, /start-row-unsigned: starts\.jsonl line 2/, after.text);
      assert.match(after.text, /NOT VERIFIED/);
      assert.equal(after.code, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the honest ledger passes under the flag", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r26-7-"));
    try {
      const keyFile = await ledgerWithAThreeDayGap(dir);
      const got = await verify(dir, keyFile, "--require-signed-starts");
      assert.equal(got.code, 0, got.text);
      assert.match(got.text, /2 of 2 signed verify under the pinned record key/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a ledger with decisions and no start row at all does not pass under the flag", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r26-7-"));
    try {
      const keyFile = await ledgerWithAThreeDayGap(dir);
      rmSync(join(dir, "starts.jsonl"));
      const got = await verify(dir, keyFile, "--require-signed-starts");
      assert.match(got.text, /start-rows-missing/, got.text);
      assert.equal(got.code, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("without the flag the stripped file still reads as an older ledger, and says unsigned", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r26-7-"));
    try {
      const keyFile = await ledgerWithAThreeDayGap(dir);
      writeRows(dir, stripped(rows(dir)));
      const got = await verify(dir, keyFile);
      assert.equal(got.code, 0, got.text);
      assert.match(got.text, /unsigned \(not verified\)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
