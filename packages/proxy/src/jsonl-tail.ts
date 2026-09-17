// A JSON-lines file read from its end. The ledger files are append-only and
// in time order, so what a reader usually wants (the last day, the last N
// rows) sits at the end, and reading the whole file to get there costs the
// whole file: measured on 17 Sep 2026, a 100k-decision ledger answered a
// 24-hour window in 1.5 s, 40% of the time it took to answer everything.
//
// The file is walked backwards in chunks. Each row goes to a visitor, newest
// first, which says take, skip or stop. What was taken comes back in file
// order. A chunk is cut at its first newline: what lies before it is the tail
// of a row that continues further up and is carried to the next chunk; what
// lies after it is whole rows, decoded together and split. Newlines are
// single bytes that never occur inside a multibyte character, so a chunk
// boundary inside one changes nothing.

import { open as fsOpen } from "node:fs/promises";

export type TailVisit = "take" | "skip" | "stop";

export type TailOpts = {
  /**
   * Bytes read per step from the end. Default 64 KiB: measured on a 194 MB
   * file, 64 KiB, 256 KiB and 1 MiB read the whole of it in the same time,
   * and the small step keeps a small window's cost small.
   */
  chunkBytes?: number;
  /** The file opener, so a seam or a test can count what was read. */
  open?: typeof fsOpen;
  /**
   * Walk backwards from this byte instead of the file's end. A window that
   * starts inside a piece uses this after a timestamp seek so the walk does
   * not cross every later row.
   */
  endOffset?: number;
};

const NEWLINE = 0x0a;

export async function readJsonlTail<T>(
  path: string,
  visit: (row: T) => TailVisit,
  opts: TailOpts = {},
): Promise<T[]> {
  const chunkBytes = Math.max(1, Math.floor(opts.chunkBytes ?? 64 * 1024));
  const openFile = opts.open ?? fsOpen;
  let fh: Awaited<ReturnType<typeof fsOpen>>;
  try {
    fh = await openFile(path, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  // Newest first while reading; reversed once at the end.
  const taken: T[] = [];
  let stopped = false;
  const emitLines = (text: string): void => {
    const lines = text.split("\n");
    for (let i = lines.length - 1; i >= 0 && !stopped; i -= 1) {
      const line = lines[i]!;
      if (line.trim() === "") continue;
      const row = JSON.parse(line) as T;
      const verdict = visit(row);
      if (verdict === "take") taken.push(row);
      if (verdict === "stop") stopped = true;
    }
  };
  try {
    const { size } = await fh.stat();
    const end =
      opts.endOffset === undefined ? size : Math.min(size, Math.max(0, Math.floor(opts.endOffset)));
    let pos = end;
    // The bytes before the first newline of the chunk just read: the tail of
    // a row whose head is still further up the file.
    let carry: Buffer = Buffer.alloc(0);
    while (pos > 0 && !stopped) {
      const len = Math.min(chunkBytes, pos);
      pos -= len;
      const buf = Buffer.allocUnsafe(len);
      let got = 0;
      while (got < len) {
        const r = await fh.read(buf, got, len - got, pos + got);
        if (r.bytesRead === 0) break;
        got += r.bytesRead;
      }
      const data = carry.length > 0 ? Buffer.concat([buf.subarray(0, got), carry]) : buf.subarray(0, got);
      const first = data.indexOf(NEWLINE);
      if (first === -1) {
        // No row ends in this chunk: all of it belongs to a row further up,
        // unless this is the top of the file, where it is the first row.
        if (pos === 0) emitLines(data.toString("utf8"));
        else carry = Buffer.from(data);
        continue;
      }
      emitLines(data.toString("utf8", first + 1));
      if (stopped) break;
      if (pos === 0) {
        if (first > 0) emitLines(data.toString("utf8", 0, first));
        carry = Buffer.alloc(0);
      } else {
        carry = Buffer.from(data.subarray(0, first));
      }
    }
  } finally {
    await fh.close();
  }
  return taken.reverse();
}

/**
 * The start of the first row whose stamp is at or after `targetMs`, or the
 * file size when none is. Rows are treated as time-ordered (one writer, the
 * clock's `now()`); a 60 s slack on the caller covers a clock set back.
 * Each probe reads from the mid offset until the first complete line.
 */
export async function seekOffsetByTimestamp<T>(
  path: string,
  targetMs: number,
  tsOf: (row: T) => number,
  opts: TailOpts = {},
): Promise<number> {
  const chunkBytes = Math.max(1, Math.floor(opts.chunkBytes ?? 64 * 1024));
  const openFile = opts.open ?? fsOpen;
  let fh: Awaited<ReturnType<typeof fsOpen>>;
  try {
    fh = await openFile(path, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw err;
  }
  try {
    const { size } = await fh.stat();
    if (size === 0) return 0;

    const readRange = async (from: number, len: number): Promise<Buffer> => {
      if (len <= 0) return Buffer.alloc(0);
      const buf = Buffer.allocUnsafe(len);
      let got = 0;
      while (got < len) {
        const r = await fh.read(buf, got, len - got, from + got);
        if (r.bytesRead === 0) break;
        got += r.bytesRead;
      }
      return buf.subarray(0, got);
    };

    const probe = Math.min(4096, chunkBytes);

    const parseLine = (
      start: number,
      text: string,
      end: number,
    ): { start: number; end: number; row: T } | null => {
      if (text.trim() === "") return null;
      return { start, end, row: JSON.parse(text) as T };
    };

    const firstCompleteLine = async (
      mid: number,
    ): Promise<{ start: number; end: number; row: T } | null> => {
      const from = mid > 0 ? mid - 1 : 0;
      let collected = await readRange(from, Math.min(probe, size - from));
      if (collected.length === 0) return null;

      let start: number;
      let rel = 0;
      if (mid <= 0) {
        start = 0;
        rel = 0;
      } else if (collected[0] === NEWLINE) {
        start = mid;
        rel = 1;
      } else {
        let pos = from;
        let buf = collected;
        let found = false;
        for (;;) {
          const nl = buf.indexOf(NEWLINE, pos === from ? 1 : 0);
          if (nl !== -1) {
            start = pos + nl + 1;
            collected = buf;
            rel = nl + 1;
            found = true;
            break;
          }
          pos += buf.length;
          if (pos >= size) return null;
          buf = await readRange(pos, Math.min(probe, size - pos));
          if (buf.length === 0) return null;
        }
        if (!found) return null;
      }
      if (start >= size) return null;

      const after = collected.subarray(rel);
      const nl = after.indexOf(NEWLINE);
      if (nl !== -1) {
        const parsed = parseLine(start, after.subarray(0, nl).toString("utf8"), start + nl + 1);
        return parsed ?? firstCompleteLine(start + nl + 1);
      }

      let acc = Buffer.from(after);
      let pos = start + after.length;
      while (pos < size) {
        const chunk = await readRange(pos, Math.min(probe, size - pos));
        if (chunk.length === 0) break;
        const n2 = chunk.indexOf(NEWLINE);
        if (n2 !== -1) {
          const parsed = parseLine(
            start,
            Buffer.concat([acc, chunk.subarray(0, n2)]).toString("utf8"),
            start + acc.length + n2 + 1,
          );
          return parsed ?? firstCompleteLine(start + acc.length + n2 + 1);
        }
        acc = Buffer.concat([acc, chunk]);
        pos += chunk.length;
      }
      return parseLine(start, acc.toString("utf8"), size);
    };

    let lo = 0;
    let hi = size;
    let found = size;
    while (lo < hi) {
      const mid = lo + Math.floor((hi - lo) / 2);
      const line = await firstCompleteLine(mid);
      if (line === null || line.start >= hi) {
        hi = mid;
        continue;
      }
      if (tsOf(line.row) >= targetMs) {
        found = line.start;
        hi = mid;
      } else {
        lo = line.end > lo ? line.end : lo + 1;
      }
    }
    return found;
  } finally {
    await fh.close();
  }
}
