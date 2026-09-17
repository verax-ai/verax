// The ledger files are append-only and time-ordered, so the newest rows are
// at the end. A reader that wants the last day should not have to read the
// first month. readJsonlTail walks the file backwards in chunks and hands
// each row to a visitor that says take, skip or stop; the rows it took come
// back in file order.

import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { readJsonlTail, seekOffsetByTimestamp } from "../src/jsonl-tail.ts";

type Row = { i: number; pad?: string; text?: string; ts?: number };

function dir(): string {
  return mkdtempSync(join(tmpdir(), "verax-jsonl-tail-"));
}

function writeRows(path: string, rows: Row[], trailingNewline = true): void {
  const text = rows.map((r) => JSON.stringify(r)).join("\n");
  writeFileSync(path, trailingNewline ? `${text}\n` : text, "utf8");
}

describe("readJsonlTail", () => {
  it("takes the last rows in file order and stops when told", async () => {
    const path = join(dir(), "rows.jsonl");
    writeRows(path, Array.from({ length: 3000 }, (_, i) => ({ i })));
    const taken = await readJsonlTail<Row>(path, (row) => (row.i >= 2975 ? "take" : "stop"));
    assert.deepEqual(
      taken.map((r) => r.i),
      Array.from({ length: 25 }, (_, k) => 2975 + k),
    );
  });

  it("skips rows the visitor declines without stopping", async () => {
    const path = join(dir(), "rows.jsonl");
    writeRows(path, Array.from({ length: 3000 }, (_, i) => ({ i })));
    const taken = await readJsonlTail<Row>(path, (row) => {
      if (row.i < 2990) return "stop";
      return row.i % 2 === 1 ? "take" : "skip";
    });
    assert.deepEqual(
      taken.map((r) => r.i),
      [2991, 2993, 2995, 2997, 2999],
    );
  });

  it("reassembles rows longer than a chunk and rows split across chunks", async () => {
    const path = join(dir(), "long.jsonl");
    const rows = Array.from({ length: 40 }, (_, i) => ({ i, pad: "x".repeat(1500 + (i % 7) * 311) }));
    writeRows(path, rows);
    const taken = await readJsonlTail<Row>(path, (row) => (row.i >= 37 ? "take" : "stop"), { chunkBytes: 1024 });
    assert.deepEqual(taken, rows.slice(37));
  });

  it("keeps multibyte characters whole when a chunk boundary falls inside one", async () => {
    const path = join(dir(), "utf8.jsonl");
    const rows = Array.from({ length: 30 }, (_, i) => ({ i, text: `çğş€ ${i} ığüö` }));
    writeRows(path, rows);
    const taken = await readJsonlTail<Row>(path, (row) => (row.i >= 20 ? "take" : "stop"), { chunkBytes: 7 });
    assert.deepEqual(taken, rows.slice(20));
  });

  it("reads a file without a trailing newline and an empty file", async () => {
    const d = dir();
    const noNewline = join(d, "no-newline.jsonl");
    writeRows(noNewline, [{ i: 1 }, { i: 2 }, { i: 3 }], false);
    assert.deepEqual(await readJsonlTail<Row>(noNewline, () => "take"), [{ i: 1 }, { i: 2 }, { i: 3 }]);
    const empty = join(d, "empty.jsonl");
    writeFileSync(empty, "", "utf8");
    assert.deepEqual(await readJsonlTail<Row>(empty, () => "take"), []);
  });

  it("answers [] for a file that does not exist", async () => {
    assert.deepEqual(await readJsonlTail<Row>(join(dir(), "missing.jsonl"), () => "take"), []);
  });

  it("reads only the tail of the file: bytes read stay near one chunk for a handful of rows", async () => {
    const path = join(dir(), "big.jsonl");
    writeRows(path, Array.from({ length: 5000 }, (_, i) => ({ i, pad: "y".repeat(200) })));
    let bytesRead = 0;
    const countingOpen: typeof open = async (...args) => {
      const fh = await open(...(args as Parameters<typeof open>));
      const read = fh.read.bind(fh);
      (fh as { read: unknown }).read = async (...readArgs: unknown[]) => {
        const out = await (read as (...a: unknown[]) => Promise<{ bytesRead: number }>)(...readArgs);
        bytesRead += out.bytesRead;
        return out;
      };
      return fh;
    };
    const chunkBytes = 64 * 1024;
    const taken = await readJsonlTail<Row>(path, (row) => (row.i >= 4990 ? "take" : "stop"), {
      chunkBytes,
      open: countingOpen,
    });
    assert.equal(taken.length, 10);
    // Ten rows of ~220 bytes live in the last chunk; the reader may need the
    // one before it to finish the oldest row it looked at, and no more.
    assert.ok(bytesRead <= 2 * chunkBytes, `read ${bytesRead} bytes of a ~1.1 MB file`);
  });
});

describe("seekOffsetByTimestamp", () => {
  const BASE = 1_700_000_000_000;

  function writeStamped(path: string): { starts: number[]; size: number } {
    const rows = Array.from({ length: 5000 }, (_, i) => ({ ts: BASE + i * 1000, i }));
    writeRows(path, rows);
    const starts: number[] = [];
    let pos = 0;
    for (const row of rows) {
      starts.push(pos);
      pos += Buffer.byteLength(`${JSON.stringify(row)}\n`);
    }
    return { starts, size: pos };
  }

  it("finds the first, last, middle, and out-of-range rows", async () => {
    const path = join(dir(), "seek.jsonl");
    const { starts, size } = writeStamped(path);
    const tsOf = (row: Row) => row.ts!;
    assert.equal(await seekOffsetByTimestamp(path, BASE, tsOf), starts[0]);
    assert.equal(await seekOffsetByTimestamp(path, BASE + 4999 * 1000, tsOf), starts[4999]);
    assert.equal(await seekOffsetByTimestamp(path, BASE + 2500 * 1000, tsOf), starts[2500]);
    assert.equal(await seekOffsetByTimestamp(path, BASE - 1, tsOf), starts[0]);
    assert.equal(await seekOffsetByTimestamp(path, BASE + 5000 * 1000, tsOf), size);
  });

  it("readJsonlTail with endOffset starts at the rows before that offset", async () => {
    const path = join(dir(), "end-offset.jsonl");
    const { starts } = writeStamped(path);
    const taken = await readJsonlTail<Row>(path, () => "take", { endOffset: starts[2500] });
    assert.deepEqual(
      taken.map((r) => r.i),
      Array.from({ length: 2500 }, (_, k) => k),
    );
    const tail = await readJsonlTail<Row>(path, (row) => (row.i >= 2490 ? "take" : "stop"), {
      endOffset: starts[2500],
    });
    assert.deepEqual(
      tail.map((r) => r.i),
      Array.from({ length: 10 }, (_, k) => 2490 + k),
    );
  });
});
