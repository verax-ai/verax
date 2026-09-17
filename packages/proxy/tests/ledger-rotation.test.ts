import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { decisionRecordHash } from "@cedulon/core";
import type { SignedDecisionRecord } from "@cedulon/core";

import { approvePending, approvalsLogFor } from "../src/approvals.ts";
import { writeFileAtomic } from "../src/atomic-write.ts";
import { sha256Canonical } from "../src/hash.ts";
import { inputsLogFor } from "../src/inputs.ts";
import { FileLedger, ledgerFs, lookupDecisionByRef } from "../src/ledger.ts";
import { LEGACY_PIECE_ID, listPieceFiles, readLedgerManifest } from "../src/ledger-manifest.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { tenantKey } from "../src/tenant.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));

function record(i: number, prev: string | null): SignedDecisionRecord {
  return {
    claims: {
      decider: "verax-proxy",
      subject: "memory.get",
      requestHash: "00".repeat(32),
      policyHash: "00".repeat(32),
      inputsHash: "00".repeat(32),
      decision: "allow",
      reasonCode: "allow",
      ref: `r-${i}`,
      effectClass: "memory.get",
      effectHash: "11".repeat(32),
      timestampMs: 1_700_000_000_000 + i * 1000,
      nonce: `n-${i}`,
      prevRecordHash: prev,
    },
    publicKeyPem: "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----\n",
    encoding: "cose",
    coseHex: i.toString(16).padStart(128, "0"),
  };
}

function lastJsonl<T>(path: string): T {
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l !== "");
  return JSON.parse(lines[lines.length - 1]!) as T;
}

const APPROVE_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "memory-put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
  ],
} as const;

const principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
const putCall = {
  name: "memory.put",
  arguments: { id: "n1", body: "hello", source: { kind: "test" }, validUntilMs: 9_999 },
};

describe("ledger rotation", () => {
  it("1: the opening row of a new piece chains to the closed piece's last hash", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-chain-"));
    // A piece closes on the row that fills it, so two rows fill legacy and
    // the third is the opening row of the piece that took its place.
    const ledger = new FileLedger(dir, { pieceMaxRows: 2 });
    try {
      await ledger.appendDecisionChained((prev) => record(0, prev));
      await ledger.appendDecisionChained((prev) => record(1, prev));
      await ledger.appendDecisionChained((prev) => record(2, prev));
      const closed = lastJsonl<SignedDecisionRecord>(join(dir, "decisions.jsonl"));
      assert.equal(closed.claims.ref, "r-1");
      const pieces = listPieceFiles(dir).filter((p) => p.id !== LEGACY_PIECE_ID);
      assert.equal(pieces.length, 1);
      const opened = lastJsonl<SignedDecisionRecord>(pieces[0]!.decisions);
      assert.equal(opened.claims.prevRecordHash, decisionRecordHash(closed));
      assert.notEqual(opened.claims.prevRecordHash, null);
    } finally {
      ledger.close();
    }
  });

  it("3: a defer in a closed piece is found by lookupByRef and approved onto the active piece", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-approve-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 1 });
    const proxy = createProxy({
      policy: loadPolicy(APPROVE_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_700_000_000_000, 1000),
      nonce: queuedNonce(["defer-1", "allow-1"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const deferred = await proxy.call(putCall, principal);
      assert.match(deferred.content[0]?.text ?? "", /deferred:approval-required:defer-1/);
      ledger.close();
    } catch (err) {
      ledger.close();
      throw err;
    }

    const again = new FileLedger(dir, { pieceMaxRows: 50 });
    try {
      const found = await lookupDecisionByRef(again, "defer-1");
      assert.ok(found);
      assert.equal(found!.decision, "defer");
      const outcome = await approvePending({
        ledger: again,
        recordSigner: RECORD_SIGNER,
        now: () => 1_700_000_010_000,
        nonce: () => "allow-1",
        ref: "defer-1",
        approverId: "op-1",
        via: "cli",
        policyHash: found!.policyHash,
        approvals: approvalsLogFor(again),
      });
      assert.equal(outcome.ok, true);
      if (!outcome.ok) return;
      const allow = await lookupDecisionByRef(again, outcome.allowRef);
      assert.ok(allow);
      const inputs = await inputsLogFor(again).get(outcome.allowRef);
      assert.equal(inputs?.approver?.resolves, "defer-1");
      const active = listPieceFiles(dir).find((p) => !p.closed);
      assert.ok(active);
      const activeRows = readFileSync(active!.decisions, "utf8")
        .split("\n")
        .filter((l) => l !== "");
      assert.equal(activeRows.length, 1);
      const allowRec = JSON.parse(activeRows[0]!) as SignedDecisionRecord;
      assert.equal(allowRec.claims.ref, outcome.allowRef);
      assert.equal(allowRec.claims.decision, "allow");
    } finally {
      again.close();
    }
  });

  it("4: same tenant and same _ref after a close is ref-reuse, not a third defer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-reuse-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 1 });
    const proxy = createProxy({
      policy: loadPolicy(APPROVE_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_700_000_000_000, 1000),
      nonce: queuedNonce(["n-reuse"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      await proxy.call({ ...putCall, arguments: { ...putCall.arguments, _ref: "same" } }, principal);
      ledger.close();
    } catch (err) {
      ledger.close();
      throw err;
    }

    const again = new FileLedger(dir, { pieceMaxRows: 50 });
    const proxy2 = createProxy({
      policy: loadPolicy(APPROVE_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: again,
      now: tickingNow(1_700_000_100_000, 1000),
      nonce: queuedNonce(["n-reuse"]),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    try {
      const out = await proxy2.call(
        { ...putCall, arguments: { ...putCall.arguments, body: "swap", _ref: "same" } },
        principal,
      );
      assert.match(out.content[0]?.text ?? "", /denied:ref-reuse:n-reuse/);
      const recs = await again.decisions();
      assert.equal(recs.filter((d) => d.claims.decision === "defer").length, 1);
      assert.equal(recs.filter((d) => d.claims.reasonCode === "ref-reuse").length, 1);
    } finally {
      again.close();
    }
  });

  it("5: a new instance's loadCaches reads 0 bytes from a closed decisions.jsonl", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-boot-"));
    const writer = new FileLedger(dir, { pieceMaxRows: 2 });
    try {
      await writer.appendDecisionChained((prev) => record(0, prev));
      await writer.appendDecisionChained((prev) => record(1, prev));
    } finally {
      writer.close();
    }
    const closedPath = join(dir, "decisions.jsonl");
    assert.ok(statSync(closedPath).size > 0);
    const origRead = ledgerFs.readFile.bind(ledgerFs);
    const origReadSync = ledgerFs.readFileSync.bind(ledgerFs);
    const origOpen = ledgerFs.open.bind(ledgerFs);
    let closedBytes = 0;
    const note = (path: unknown, n: number) => {
      if (String(path) === closedPath) closedBytes += n;
    };
    ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
      const buf = await origRead(path, ...(rest as []));
      note(path, typeof buf === "string" ? Buffer.byteLength(buf) : (buf as Buffer).length);
      return buf;
    }) as typeof ledgerFs.readFile;
    ledgerFs.readFileSync = ((path: Parameters<typeof origReadSync>[0], ...rest: unknown[]) => {
      const buf = origReadSync(path, ...(rest as []));
      note(path, typeof buf === "string" ? Buffer.byteLength(buf) : buf.length);
      return buf;
    }) as typeof ledgerFs.readFileSync;
    ledgerFs.open = (async (path: Parameters<typeof origOpen>[0], ...rest: unknown[]) => {
      const fh = await origOpen(path, ...(rest as []));
      if (String(path) === closedPath) {
        const read = fh.read.bind(fh);
        (fh as { read: typeof fh.read }).read = (async (...args: Parameters<typeof read>) => {
          const out = await read(...args);
          closedBytes += out.bytesRead;
          return out;
        }) as typeof fh.read;
      }
      return fh;
    }) as typeof ledgerFs.open;
    let reader: FileLedger | undefined;
    try {
      reader = new FileLedger(dir);
      assert.equal(closedBytes, 0, `closed decisions.jsonl was read: ${closedBytes} bytes`);
      assert.equal(reader.counts()?.decisions, 2);
      assert.equal(reader.counts()?.activeDecisions, 0);
    } finally {
      ledgerFs.readFile = origRead;
      ledgerFs.readFileSync = origReadSync;
      ledgerFs.open = origOpen;
      reader?.close();
    }
  });

  it("8: an append queued with rotation lands on the new piece and does not throw ledger-lost-lock", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-queue-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 2 });
    try {
      // All three are queued before the first is written; the second fills
      // legacy and closes it inside its queue turn, the third must land on
      // the piece that close opened.
      const p1 = ledger.appendDecisionChained((prev) => record(0, prev));
      const p2 = ledger.appendDecisionChained((prev) => record(1, prev));
      const p3 = ledger.appendDecisionChained((prev) => record(2, prev));
      await Promise.all([p1, p2, p3]);
      const manifest = readLedgerManifest(dir);
      assert.ok(manifest);
      assert.equal(manifest!.pieces.length, 2);
      assert.equal(manifest!.pieces[0]!.closed, true);
      assert.equal(manifest!.pieces[0]!.n, 2);
      const active = listPieceFiles(dir).find((p) => !p.closed);
      assert.ok(active);
      const lines = readFileSync(active!.decisions, "utf8")
        .split("\n")
        .filter((l) => l !== "");
      assert.equal(lines.length, 1);
      const row = JSON.parse(lines[0]!) as SignedDecisionRecord;
      assert.equal(row.claims.ref, "r-2");
    } finally {
      ledger.close();
    }
  });

  it("2: a window that crosses a close names both pieces and sets more", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-window-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 30 });
    try {
      for (let i = 0; i < 60; i += 1) {
        await ledger.appendDecisionChained((prev) => record(i, prev));
      }
      const from = 1_700_000_000_000 + 20 * 1000;
      const to = 1_700_000_000_000 + 41 * 1000;
      // 15 newest rows of [20, 41): 26..29 sit in the closed piece, 30..40 in
      // the open one, so a walk that skips closed pieces comes back short.
      const { rows, more, piecesTouched } = await ledger.decisionsWindow(from, to, 15);
      assert.deepEqual(
        rows.map((r) => r.claims.ref),
        Array.from({ length: 15 }, (_, k) => `r-${26 + k}`),
      );
      assert.equal(more, true);
      assert.ok(piecesTouched.includes(LEGACY_PIECE_ID));
      assert.ok(piecesTouched.some((id) => id !== LEGACY_PIECE_ID));
    } finally {
      ledger.close();
    }
  });

  it("a window inside a piece seeks by timestamp and still reads the tail", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-seek-"));
    const realOpen = ledgerFs.open;
    ledgerFs.open = (async (path: string, flags: string) => {
      const fh = await open(path, flags);
      return { write: (data: string) => fh.write(data), sync: async () => undefined, close: () => fh.close() };
    }) as unknown as typeof open;
    const ledger = new FileLedger(dir, { pieceMaxRows: 10000 });
    try {
      for (let i = 0; i < 5000; i += 1) {
        await ledger.appendDecisionChained((prev) => record(i, prev));
      }
    } finally {
      ledgerFs.open = realOpen;
    }
    const decisionsPath = join(dir, "decisions.jsonl");
    const fileBytes = statSync(decisionsPath).size;
    const origOpen = ledgerFs.open.bind(ledgerFs);
    let bytesRead = 0;
    ledgerFs.open = (async (path: Parameters<typeof origOpen>[0], ...rest: unknown[]) => {
      const fh = await origOpen(path, ...(rest as []));
      if (String(path) === decisionsPath) {
        const read = fh.read.bind(fh);
        (fh as { read: typeof fh.read }).read = (async (...args: Parameters<typeof read>) => {
          const out = await read(...args);
          bytesRead += out.bytesRead;
          return out;
        }) as typeof fh.read;
      }
      return fh;
    }) as typeof ledgerFs.open;
    try {
      const from = 1_700_000_000_000 + 100 * 1000;
      const to = 1_700_000_000_000 + 200 * 1000;
      const mid = await ledger.decisionsWindow(from, to);
      assert.deepEqual(
        mid.rows.map((r) => r.claims.ref),
        Array.from({ length: 100 }, (_, k) => `r-${100 + k}`),
      );
      assert.equal(mid.more, false);
      assert.ok(bytesRead < fileBytes * 0.1, `read ${bytesRead} of ${fileBytes}`);

      const tailFrom = 1_700_000_000_000 + 4900 * 1000;
      const tail = await ledger.decisionsWindow(tailFrom, 9_999_999_999_999);
      assert.deepEqual(
        tail.rows.map((r) => r.claims.ref),
        Array.from({ length: 100 }, (_, k) => `r-${4900 + k}`),
      );
      assert.equal(tail.more, false);
    } finally {
      ledgerFs.open = origOpen;
      ledger.close();
    }
  });

  it("6: after a close at 50, counts keep lifetime 50 and activeDecisions 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-counts-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 50 });
    try {
      for (let i = 0; i < 50; i += 1) {
        await ledger.appendDecisionChained((prev) => record(i, prev));
      }
      const counted = ledger.counts();
      assert.equal(counted?.decisions, 50);
      assert.equal(counted?.activeDecisions, 0);
      assert.equal(counted?.pieces, 2);
    } finally {
      ledger.close();
    }
  });

  it("7: a truncated closed copy is stale even when the open piece copy matches", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-doctor-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 2 });
    try {
      await ledger.appendDecisionChained((prev) => record(0, prev));
      await ledger.appendDecisionChained((prev) => record(1, prev));
      await ledger.appendDecisionChained((prev) => record(2, prev));
    } finally {
      ledger.close();
    }
    const pieces = listPieceFiles(dir);
    const closed = pieces.find((p) => p.id === LEGACY_PIECE_ID);
    const open = pieces.find((p) => !p.closed);
    assert.ok(closed && open);
    writeFileSync(closed!.copyDecisions, "", { encoding: "utf8" });
    const closedCopy = readFileSync(closed!.copyDecisions, "utf8").trim();
    const closedSrc = readFileSync(closed!.decisions, "utf8")
      .split("\n")
      .filter((l) => l !== "");
    assert.equal(closedCopy, "");
    assert.ok(closedSrc.length > 0);
    const openSrc = readFileSync(open!.decisions, "utf8")
      .split("\n")
      .filter((l) => l !== "");
    const openCopy = readFileSync(open!.copyDecisions, "utf8")
      .split("\n")
      .filter((l) => l !== "");
    assert.equal(openSrc.length, openCopy.length);
  });

  it("9: manifest replace under a reader does not throw, and jsonl paths never go to renameSync", async () => {
    const ledgerSrc = readFileSync(join(here, "..", "src", "ledger.ts"), "utf8");
    assert.equal(ledgerSrc.includes("renameSync"), false, "ledger.ts must not name renameSync");
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-rename-"));
    const dest = join(dir, "ledger-manifest.json");
    writeFileAtomic(dest, `${JSON.stringify({ version: 1, pieces: [], countedAtMs: [] })}\n`);
    let reads = 0;
    let parseFails = 0;
    const reader = setInterval(() => {
      try {
        JSON.parse(readFileSync(dest, "utf8"));
        reads += 1;
      } catch {
        parseFails += 1;
      }
    }, 1);
    try {
      for (let i = 0; i < 40; i += 1) {
        writeFileAtomic(dest, `${JSON.stringify({ version: 1, pieces: [{ i }], countedAtMs: [] })}\n`);
        // The reader is a timer; a writer that never yields would starve it.
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
    } finally {
      clearInterval(reader);
    }
    assert.ok(reads > 0, "reader never saw the file");
    assert.equal(parseFails, 0, `torn manifest reads: ${parseFails}`);
    // The jsonl files stay where they were written: after legacy closes, the
    // flat file is still at the root, byte for byte, and the piece that
    // replaced it is a new file under pieces/. A rename would move or empty it.
    // A fresh directory: the manifest above was a stand-in for the torn-read
    // check and names no real piece.
    const ledgerDir = mkdtempSync(join(tmpdir(), "verax-rot-inplace-"));
    const legacyPath = join(ledgerDir, "decisions.jsonl");
    const ledger = new FileLedger(ledgerDir, { pieceMaxRows: 1 });
    try {
      await ledger.appendDecisionChained((prev) => record(0, prev));
      const beforeClose = readFileSync(legacyPath, "utf8");
      assert.ok(beforeClose.length > 0);
      await ledger.appendDecisionChained((prev) => record(1, prev));
      assert.ok(existsSync(legacyPath), "legacy decisions.jsonl left the root");
      assert.equal(readFileSync(legacyPath, "utf8"), beforeClose);
      const opened = listPieceFiles(ledgerDir).find((p) => p.id !== LEGACY_PIECE_ID);
      assert.ok(opened);
      assert.notEqual(opened!.decisions, legacyPath);
      assert.ok(existsSync(opened!.decisions));
    } finally {
      ledger.close();
    }
  });

  it("10: a torn last index line is skipped and the index rebuilt from the pieces", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-torn-"));
    const writer = new FileLedger(dir, { pieceMaxRows: 2 });
    try {
      for (let i = 0; i < 3; i += 1) await writer.appendDecisionChained((prev) => record(i, prev));
    } finally {
      writer.close();
    }
    const indexFile = join(dir, "index.jsonl");
    const whole = readFileSync(indexFile, "utf8");
    // A crash between the write and the close leaves the last line half written.
    writeFileSync(indexFile, whole.slice(0, whole.length - 20));
    const again = new FileLedger(dir);
    try {
      for (let i = 0; i < 3; i += 1) assert.ok(again.lookupByRef("r-" + i), "missing after the torn index: r-" + i);
      const rebuilt = readFileSync(indexFile, "utf8").split("\n").filter((l) => l !== "");
      assert.equal(rebuilt.length, 3);
    } finally {
      again.close();
    }
  });

  it("11: an index padded by effect lines but short on decisions is rebuilt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-padded-"));
    const writer = new FileLedger(dir, { pieceMaxRows: 50 });
    try {
      for (let i = 0; i < 4; i += 1) {
        await writer.appendDecisionChained((prev) => record(i, prev));
        await writer.appendEffect(
          { ref: "r-" + i, effectHash: "22".repeat(32), effectClass: "memory.get", timestampMs: 1_700_000_000_000 + i * 1000 },
          "self",
          "33".repeat(32),
        );
      }
      await writer.appendDecisionChained((prev) => {
        const base = record(4, prev);
        return { ...base, claims: { ...base.claims, decision: "defer", reasonCode: "approval-required" } };
      });
    } finally {
      writer.close();
    }
    const indexFile = join(dir, "index.jsonl");
    const lines = readFileSync(indexFile, "utf8").split("\n").filter((l) => l !== "");
    // Four decision lines, four effect lines, one defer line: dropping the
    // defer leaves eight lines for five decisions. A count that trusts the
    // line total keeps the short index and the defer is unknown.
    const kept = lines.filter((l) => (JSON.parse(l) as { ref: string }).ref !== "r-4");
    assert.equal(kept.length, lines.length - 1);
    writeFileSync(indexFile, kept.join("\n") + "\n");
    const again = new FileLedger(dir);
    try {
      const found = again.lookupByRef("r-4");
      assert.ok(found, "the defer dropped from a padded index was not rebuilt");
      assert.equal(found!.decision, "defer");
    } finally {
      again.close();
    }
  });

  it("12: a corrupt manifest refuses to open instead of hiding the pieces", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-corrupt-"));
    const writer = new FileLedger(dir, { pieceMaxRows: 1 });
    try {
      await writer.appendDecisionChained((prev) => record(0, prev));
      await writer.appendDecisionChained((prev) => record(1, prev));
    } finally {
      writer.close();
    }
    // Opening as a single legacy piece here would chain new rows onto a
    // closed file and hide every piece the manifest named.
    writeFileSync(join(dir, "ledger-manifest.json"), "{ not json", "utf8");
    assert.throws(() => new FileLedger(dir), /ledger-manifest/);
    // The failed open must not leave the lock behind for the next one.
    writeFileSync(join(dir, "ledger-manifest.json"), "", "utf8");
    assert.throws(() => new FileLedger(dir), /ledger-manifest/);
  });

  it("13: a restart does not double the counted work of decisions that had effects", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-counted-"));
    const now = Date.now();
    const stamped = (i: number, prev: string | null): SignedDecisionRecord => {
      const base = record(i, prev);
      return { ...base, claims: { ...base.claims, timestampMs: now - 1000 * (10 - i) } };
    };
    const writer = new FileLedger(dir, { pieceMaxRows: 50 });
    try {
      for (let i = 0; i < 5; i += 1) {
        await writer.appendDecisionChained((prev) => stamped(i, prev));
        await writer.appendEffect(
          { ref: "r-" + i, effectHash: "22".repeat(32), effectClass: "memory.get", timestampMs: now },
          "self",
          "33".repeat(32),
        );
      }
      assert.equal(writer.countedTimes().length, 5);
    } finally {
      writer.close();
    }
    // The daily and per-minute limits read these counts; a doubled count
    // after a restart would hit dailyMax at half the real number.
    const again = new FileLedger(dir);
    try {
      assert.equal(again.countedTimes().length, 5, "counted work doubled after the restart");
    } finally {
      again.close();
    }
  });

  it("14: the index line of an append does not read inputs.jsonl back", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rot-inputs-read-"));
    const ledger = new FileLedger(dir, { pieceMaxRows: 1000 });
    const inputs = inputsLogFor(ledger);
    const inputsPath = join(dir, "inputs.jsonl");
    const origRead = ledgerFs.readFile.bind(ledgerFs);
    const origReadSync = ledgerFs.readFileSync.bind(ledgerFs);
    const origOpen = ledgerFs.open.bind(ledgerFs);
    let inputsBytes = 0;
    const note = (path: unknown, n: number) => {
      if (String(path) === inputsPath) inputsBytes += n;
    };
    ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
      const buf = await origRead(path, ...(rest as []));
      note(path, typeof buf === "string" ? Buffer.byteLength(buf) : (buf as Buffer).length);
      return buf;
    }) as typeof ledgerFs.readFile;
    ledgerFs.readFileSync = ((path: Parameters<typeof origReadSync>[0], ...rest: unknown[]) => {
      const buf = origReadSync(path, ...(rest as []));
      note(path, typeof buf === "string" ? Buffer.byteLength(buf) : buf.length);
      return buf;
    }) as typeof ledgerFs.readFileSync;
    ledgerFs.open = (async (path: Parameters<typeof origOpen>[0], ...rest: unknown[]) => {
      const fh = await origOpen(path, ...(rest as []));
      if (String(path) === inputsPath && String(rest[0]) !== "a") {
        const read = fh.read.bind(fh);
        (fh as { read: typeof fh.read }).read = (async (...args: Parameters<typeof read>) => {
          const out = await read(...args);
          inputsBytes += out.bytesRead;
          return out;
        }) as typeof fh.read;
      }
      return fh;
    }) as typeof ledgerFs.open;
    try {
      // Each call writes its inputs row and then its decision, the way the
      // proxy does. Reading the inputs file back per append made the write
      // path grow with the piece.
      for (let i = 0; i < 200; i += 1) {
        await inputs.append("r-" + i, { principal: { brain: "brain-1", scopes: ["verax:memory"] }, inputs: [] });
        await ledger.appendDecisionChained((prev) => record(i, prev));
      }
      assert.equal(inputsBytes, 0, "inputs.jsonl read back during appends: " + inputsBytes + " bytes");
      assert.equal(ledger.lookupByRef(tenantKey({ brain: "brain-1" }) + ":r-199")?.ref, "r-199", "tenant key still indexed");
    } finally {
      ledgerFs.readFile = origRead;
      ledgerFs.readFileSync = origReadSync;
      ledgerFs.open = origOpen;
      ledger.close();
    }
  });
});
