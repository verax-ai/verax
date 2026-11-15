/**
 * Append-only JSONL store of log leaves. Each line is
 * `{"v":1,"index":N,"prev":"<64 hex>","leaf_hash":"<64 hex>","owner_id":"<id>","at_ms":<number>}`
 * where `prev` is SHA-256 of the previous line (including its newline), or
 * 64 zero hex digits for the first line. On start the file is read back in
 * order; a blank line that is not a torn tail, a repeated (owner_id, leaf_hash),
 * a broken chain, or an old unversioned line refuses to load. A final line with
 * no terminating newline is a torn write: it is dropped by writing the kept
 * prefix to a new file in the same directory, fsyncing it, renaming it over
 * the store, and fsyncing the directory (so a crash cannot leave an empty
 * store in place of acknowledged rows). The store path is opened once and that
 * descriptor is kept for the process life so a later symlink cannot redirect
 * appends.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { MerkleLog, type LogLeaf } from "./merkle.ts";

const HASH = /^[0-9a-f]{64}$/;
const ZERO_PREV = "0".repeat(64);

export type StoreRow = {
  leaf_hash: string;
  owner_id: string;
  at_ms: number;
};

export type StoredLine = StoreRow & {
  v: 1;
  index: number;
  prev: string;
};

export type OpenStore = {
  path: string;
  log: MerkleLog;
  append: (row: StoreRow) => void;
  close: () => void;
};

export type StoreStat = {
  isSymbolicLink: () => boolean;
  isFile: () => boolean;
};

export type StoreFileOps = {
  writeSync: (
    fd: number,
    buffer: NodeJS.ArrayBufferView,
    offset?: number,
    length?: number,
    position?: number | null,
  ) => number;
  fsyncSync: (fd: number) => void;
};

/** Steps of torn-tail recovery; tests may fail one via `failAt`. */
export type TornTailRecoveryStep = "write-tmp" | "fsync-tmp" | "rename" | "fsync-dir";

export type StoreRecoveryOps = {
  /** Test-only: throw at this recovery step. Not exposed through the CLI. */
  failAt?: TornTailRecoveryStep;
  writeFileSync?: typeof writeFileSync;
  openSync?: typeof openSync;
  fsyncSync?: typeof fsyncSync;
  closeSync?: typeof closeSync;
  renameSync?: typeof renameSync;
  unlinkSync?: typeof unlinkSync;
};

export type OpenStoreOpts = {
  /** Test-only: substitute for lstatSync. Not exposed through the CLI. */
  lstat?: (path: string) => StoreStat;
  /** Test-only: substitute write/fsync used by append. Not exposed through the CLI. */
  fileOps?: StoreFileOps;
  /** Test-only: substitute torn-tail recovery I/O. Not exposed through the CLI. */
  recoveryOps?: StoreRecoveryOps;
};

function lineDigest(lineWithNewline: string): string {
  return createHash("sha256").update(lineWithNewline, "utf8").digest("hex");
}

function encodeLine(row: StoredLine): string {
  return `${JSON.stringify({
    v: row.v,
    index: row.index,
    prev: row.prev,
    leaf_hash: row.leaf_hash,
    owner_id: row.owner_id,
    at_ms: row.at_ms,
  })}\n`;
}

export function parseStoreLine(line: string, lineNo: number): StoredLine {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error(`store line ${lineNo} is not JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`store line ${lineNo} is not a store row`);
  }
  const row = parsed as Record<string, unknown>;
  if (row.v === undefined && row.index === undefined && row.prev === undefined) {
    throw new Error(
      "store is in an old format without line index and prev hash; start a new store file",
    );
  }
  if (row.v !== 1) {
    throw new Error(`store line ${lineNo} has an unsupported version`);
  }
  if (typeof row.index !== "number" || !Number.isSafeInteger(row.index) || row.index < 0) {
    throw new Error(`store line ${lineNo} has a bad index`);
  }
  if (typeof row.prev !== "string" || !HASH.test(row.prev)) {
    throw new Error(`store line ${lineNo} has a bad prev`);
  }
  if (typeof row.leaf_hash !== "string" || !HASH.test(row.leaf_hash)) {
    throw new Error(`store line ${lineNo} has a bad leaf_hash`);
  }
  if (typeof row.owner_id !== "string" || row.owner_id === "") {
    throw new Error(`store line ${lineNo} has a bad owner_id`);
  }
  if (typeof row.at_ms !== "number" || !Number.isSafeInteger(row.at_ms)) {
    throw new Error(`store line ${lineNo} has a bad at_ms`);
  }
  const keys = Object.keys(row);
  if (keys.length !== 6) throw new Error(`store line ${lineNo} has unexpected fields`);
  return {
    v: 1,
    index: row.index,
    prev: row.prev,
    leaf_hash: row.leaf_hash,
    owner_id: row.owner_id,
    at_ms: row.at_ms,
  };
}

/** Path identity checks used before open; tests may call with a fake lstat. */
export function assertStorePath(path: string, lstat: (path: string) => StoreStat = lstatSync): void {
  try {
    const st = lstat(path);
    if (st.isSymbolicLink()) {
      throw new Error(`store path must not be a symbolic link`);
    }
    if (!st.isFile()) {
      throw new Error(`store path must be a regular file`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
}

function flushParentDir(filePath: string): void {
  try {
    const dirFd = openSync(dirname(filePath), fsConstants.O_RDONLY);
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  } catch {
    // Some platforms refuse to fsync a directory; the file fsync still ran.
  }
}

/**
 * Replace the store with `kept` without truncating the original in place.
 * Write → fsync → rename → directory fsync. A failure before rename leaves
 * the original bytes (including any complete rows) untouched.
 */
function recoverTornTail(path: string, kept: string, ops?: StoreRecoveryOps): void {
  const writeFile = ops?.writeFileSync ?? writeFileSync;
  const open = ops?.openSync ?? openSync;
  const fsync = ops?.fsyncSync ?? fsyncSync;
  const close = ops?.closeSync ?? closeSync;
  const rename = ops?.renameSync ?? renameSync;
  const unlink = ops?.unlinkSync ?? unlinkSync;
  const failAt = ops?.failAt;
  const tmp = join(dirname(path), `.${randomBytes(8).toString("hex")}.store-recovering`);
  try {
    if (failAt === "write-tmp") throw new Error("injected torn-tail recovery failure at write-tmp");
    writeFile(tmp, kept, "utf8");
    if (failAt === "fsync-tmp") throw new Error("injected torn-tail recovery failure at fsync-tmp");
    const tmpFd = open(tmp, "r+");
    try {
      fsync(tmpFd);
    } finally {
      close(tmpFd);
    }
    if (failAt === "rename") throw new Error("injected torn-tail recovery failure at rename");
    rename(tmp, path);
    if (failAt === "fsync-dir") throw new Error("injected torn-tail recovery failure at fsync-dir");
    flushParentDir(path);
  } catch (err) {
    try {
      unlink(tmp);
    } catch {
      /* tmp may be gone after a successful rename */
    }
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`torn-tail recovery failed: ${msg}`);
  }
}

/**
 * Open the store for the life of the process. Creates an empty regular file
 * when missing, fsyncs it and (where the platform allows) its parent directory.
 */
export function openStore(path: string, opts?: OpenStoreOpts): OpenStore {
  const lstat = opts?.lstat ?? lstatSync;
  const io: StoreFileOps = opts?.fileOps ?? { writeSync, fsyncSync };
  const recoveryOps = opts?.recoveryOps;
  assertStorePath(path, lstat);

  let created = false;
  let fd: number;
  try {
    // Exclusive create so a raced symlink cannot become the store.
    fd = openSync(path, "wx");
    created = true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    fd = openSync(path, "a+");
  }

  if (created) {
    try {
      fsyncSync(fd);
      flushParentDir(path);
      closeSync(fd);
      fd = openSync(path, "a+");
    } catch (err) {
      try {
        closeSync(fd);
      } catch {
        /* */
      }
      throw err;
    }
  }

  // Re-check identity after open: refuse if the path is no longer a regular file
  // we would have accepted (symlink swapped in between lstat and open).
  try {
    const st = lstat(path);
    if (st.isSymbolicLink() || !st.isFile()) {
      closeSync(fd);
      throw new Error(`store path must be a regular file`);
    }
  } catch (err) {
    try {
      closeSync(fd);
    } catch {
      /* */
    }
    throw err;
  }

  let text = "";
  try {
    // Read via path is fine for startup; appends use the kept fd.
    text = readFileSync(path, "utf8");
  } catch (err) {
    closeSync(fd);
    throw err;
  }

  if (text !== "" && !text.endsWith("\n")) {
    const cut = text.lastIndexOf("\n");
    const kept = cut < 0 ? "" : text.slice(0, cut + 1);
    try {
      // Never truncate the store in place: a crash between truncate and write
      // would leave an empty file. Write the kept prefix beside the store,
      // fsync, rename over it, fsync the directory, then reopen.
      closeSync(fd);
      fd = -1;
      recoverTornTail(path, kept, recoveryOps);
      fd = openSync(path, "a+");
      fsyncSync(fd);
    } catch (err) {
      if (fd >= 0) {
        try {
          closeSync(fd);
        } catch {
          /* */
        }
      }
      throw err;
    }
    process.stderr.write(`verax-anchor-service: dropped a torn last line from ${path}\n`);
    text = kept;
  }

  const log = new MerkleLog();
  const seenPairs = new Set<string>();
  let prevDigest = ZERO_PREV;
  let nextIndex = 0;

  if (text !== "") {
    if (!text.endsWith("\n")) {
      closeSync(fd);
      throw new Error("store text must end with a newline after torn-tail recovery");
    }
    const lines = text.slice(0, -1).split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      const raw = lines[i]!;
      if (raw.trim() === "") {
        closeSync(fd);
        throw new Error(`store line ${i + 1} is blank`);
      }
      let row: StoredLine;
      try {
        row = parseStoreLine(raw, i + 1);
      } catch (err) {
        closeSync(fd);
        throw err;
      }
      if (row.index !== nextIndex) {
        closeSync(fd);
        throw new Error(`store line ${i + 1} has index ${row.index}, expected ${nextIndex}`);
      }
      if (row.prev !== prevDigest) {
        closeSync(fd);
        throw new Error(`store line ${i + 1} breaks the prev-hash chain`);
      }
      const pair = `${row.owner_id}\0${row.leaf_hash}`;
      if (seenPairs.has(pair)) {
        closeSync(fd);
        throw new Error(`store line ${i + 1} repeats an (owner_id, leaf_hash) pair`);
      }
      seenPairs.add(pair);
      const leaf: LogLeaf = {
        entry: Buffer.from(row.leaf_hash, "hex"),
        ownerId: row.owner_id,
        atMs: row.at_ms,
      };
      log.append(leaf);
      prevDigest = lineDigest(`${raw}\n`);
      nextIndex += 1;
    }
  }

  let closed = false;
  return {
    path,
    log,
    append: (row: StoreRow) => {
      if (closed) throw new Error("store is closed");
      const pair = `${row.owner_id}\0${row.leaf_hash}`;
      if (seenPairs.has(pair)) {
        throw new Error("store refuses a repeated (owner_id, leaf_hash) pair");
      }
      const stored: StoredLine = {
        v: 1,
        index: nextIndex,
        prev: prevDigest,
        leaf_hash: row.leaf_hash,
        owner_id: row.owner_id,
        at_ms: row.at_ms,
      };
      const payload = Buffer.from(encodeLine(stored), "utf8");
      let offset = 0;
      while (offset < payload.length) {
        const n = io.writeSync(fd, payload, offset, payload.length - offset);
        if (n <= 0) throw new Error("store write made no progress");
        offset += n;
      }
      io.fsyncSync(fd);
      seenPairs.add(pair);
      prevDigest = lineDigest(payload.toString("utf8"));
      nextIndex += 1;
    },
    close: () => {
      if (closed) return;
      closed = true;
      closeSync(fd);
    },
  };
}

/** @deprecated Prefer openStore; kept for tests that inject a one-shot append. */
export function loadStore(path: string): MerkleLog {
  const opened = openStore(path);
  const log = opened.log;
  opened.close();
  return log;
}

/** Write one row through a fresh open of the path (tests only). */
export function appendStore(path: string, row: StoreRow): void {
  const opened = openStore(path);
  try {
    opened.append(row);
  } finally {
    opened.close();
  }
}
