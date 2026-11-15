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
 * descriptor is kept for the process life; before each append the path is
 * checked against the open file (dev/ino) so a swap or removal latches
 * store-unavailable instead of writing into an unlinked inode.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

import { MerkleLog, type LogLeaf } from "./merkle.ts";

const HASH = /^[0-9a-f]{64}$/;
const ZERO_PREV = "0".repeat(64);
/** Side-copy name used only during torn-tail recovery; never the configured store. */
const STORE_RECOVERING = /^\.[0-9a-f]{16}\.store-recovering$/;

/** Thrown when the configured path no longer names the open store descriptor. */
export class StoreUnavailableError extends Error {
  readonly code = "STORE_UNAVAILABLE" as const;
  constructor(message = "store-unavailable") {
    super(message);
    this.name = "StoreUnavailableError";
  }
}

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
  /** Same path-identity check `append` runs; call before signing a receipt. */
  assertPathIdentity: () => void;
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

export type ParentDirOps = {
  openSync: (path: string, flags: number) => number;
  fsyncSync: (fd: number) => void;
  closeSync: (fd: number) => void;
};

export type OpenStoreOpts = {
  /** Test-only: substitute for lstatSync. Not exposed through the CLI. */
  lstat?: (path: string) => StoreStat;
  /** Test-only: substitute write/fsync used by append and open flush. Not exposed through the CLI. */
  fileOps?: StoreFileOps;
  /** Test-only: substitute torn-tail recovery I/O. Not exposed through the CLI. */
  recoveryOps?: StoreRecoveryOps;
  /** Test-only: substitute parent-directory flush I/O. Not exposed through the CLI. */
  parentDirOps?: Partial<ParentDirOps>;
  /**
   * Test-only: platform string for directory-flush unsupported errno rules.
   * Defaults to `process.platform`. Not a global patch.
   */
  platform?: NodeJS.Platform;
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

/**
 * Ensure the path still names the same file as the kept descriptor.
 * On POSIX and on Windows volumes that report stable ids, compare `dev` and
 * `ino` from `fstatSync(fd)` with `statSync(path)`. A symlink at the path, a
 * missing path, or a different (dev, ino) means the open file is no longer the
 * configured store. Some volumes report `ino` as 0 for every file; when both
 * sides are 0 the check cannot prove identity and still refuses if the path is
 * gone or is not a regular file, but cannot detect a same-volume replace that
 * also reports ino 0. A rename in the store's directory between this comparison
 * and a following write can also swap the path. Both limits are the same as for
 * the prev chain: whoever can write the store's directory can defeat the check
 * (see docs/STATUS.md, hosted anchoring). No further code closes that.
 */
function assertPathMatchesFd(path: string, fd: number): void {
  let pathStat: ReturnType<typeof statSync>;
  try {
    const link = lstatSync(path);
    if (link.isSymbolicLink()) {
      throw new StoreUnavailableError("store path is a symbolic link");
    }
    pathStat = statSync(path);
  } catch (err) {
    if (err instanceof StoreUnavailableError) throw err;
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new StoreUnavailableError("store path is missing");
    }
    throw err;
  }
  if (!pathStat.isFile()) {
    throw new StoreUnavailableError("store path is not a regular file");
  }
  const fdStat = fstatSync(fd);
  if (fdStat.dev !== pathStat.dev || fdStat.ino !== pathStat.ino) {
    throw new StoreUnavailableError("store path no longer matches the open file");
  }
}

/** Errnos that mean this platform cannot flush a directory fd on every OS. */
const DIR_FLUSH_UNSUPPORTED = new Set(["EINVAL", "ENOTSUP", "ENOSYS", "EISDIR"]);

function dirFlushUnsupported(code: string | undefined, platform: NodeJS.Platform): boolean {
  if (code === undefined) return false;
  if (DIR_FLUSH_UNSUPPORTED.has(code)) return true;
  // On win32, opening a directory for flush is refused with EPERM; that is a
  // missing primitive there. On Linux and macOS EPERM is a denial, not a
  // missing flush, so it must refuse the open.
  if (code === "EPERM" && platform === "win32") return true;
  return false;
}

function flushParentDir(
  filePath: string,
  ops?: Partial<ParentDirOps>,
  platform: NodeJS.Platform = process.platform,
): void {
  const open = ops?.openSync ?? openSync;
  const fsync = ops?.fsyncSync ?? fsyncSync;
  const close = ops?.closeSync ?? closeSync;
  try {
    const dirFd = open(dirname(filePath), fsConstants.O_RDONLY);
    let fsyncErr: unknown;
    try {
      fsync(dirFd);
    } catch (err) {
      fsyncErr = err;
    }
    try {
      close(dirFd);
    } catch (closeErr) {
      // A close error must not mask an earlier fsync failure.
      if (fsyncErr === undefined) fsyncErr = closeErr;
    }
    if (fsyncErr !== undefined) throw fsyncErr;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (dirFlushUnsupported(code, platform)) {
      // Directory flush is not supported here; the file fsync still ran.
      return;
    }
    throw err;
  }
}

/**
 * Replace the store with `kept` without truncating the original in place.
 * Write → fsync → rename → directory fsync. A failure before rename leaves
 * the original bytes (including any complete rows) untouched.
 */
function recoverTornTail(
  path: string,
  kept: string,
  ops?: StoreRecoveryOps,
  parentDirOps?: Partial<ParentDirOps>,
  platform: NodeJS.Platform = process.platform,
): void {
  const writeFile = ops?.writeFileSync ?? writeFileSync;
  const open = ops?.openSync ?? openSync;
  const fsync = ops?.fsyncSync ?? fsyncSync;
  const close = ops?.closeSync ?? closeSync;
  const rename = ops?.renameSync ?? renameSync;
  const unlink = ops?.unlinkSync ?? unlinkSync;
  const failAt = ops?.failAt;
  // Owner bits only: a 0600 store must not become group-writable under a
  // permissive umask, and the temporary copy must not be exposed wider either.
  const ownerMode = (statSync(path).mode & 0o700) || 0o600;
  const tmp = join(dirname(path), `.${randomBytes(8).toString("hex")}.store-recovering`);
  try {
    if (failAt === "write-tmp") throw new Error("injected torn-tail recovery failure at write-tmp");
    writeFile(tmp, kept, { encoding: "utf8", mode: ownerMode, flag: "wx" });
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
    flushParentDir(path, parentDirOps, platform);
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
  const parentDirOps = opts?.parentDirOps;
  const platform = opts?.platform ?? process.platform;
  assertStorePath(path, lstat);

  // Drop leftover recovery side-copies from an interrupted prior start. Safe
  // because names matching STORE_RECOVERING are never the configured store
  // path (they are only the temporary file recoverTornTail writes beside it).
  const storeDir = dirname(path);
  const storeBase = basename(path);
  for (const name of readdirSync(storeDir)) {
    if (name === storeBase) continue;
    if (!STORE_RECOVERING.test(name)) continue;
    try {
      unlinkSync(join(storeDir, name));
    } catch {
      /* best-effort; open continues */
    }
  }

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
      io.fsyncSync(fd);
      flushParentDir(path, parentDirOps, platform);
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
      recoverTornTail(path, kept, recoveryOps, parentDirOps, platform);
      fd = openSync(path, "a+");
      io.fsyncSync(fd);
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

  // Flush the file and (where supported) its parent directory before this
  // process accepts requests — including when the path already existed, so a
  // prior create or recovery that left the file after a failed directory flush
  // cannot be accepted on the next start.
  try {
    io.fsyncSync(fd);
    flushParentDir(path, parentDirOps, platform);
  } catch (err) {
    try {
      closeSync(fd);
    } catch {
      /* */
    }
    throw err;
  }

  let closed = false;
  const assertPathIdentity = (): void => {
    if (closed) throw new Error("store is closed");
    assertPathMatchesFd(path, fd);
  };
  return {
    path,
    log,
    append: (row: StoreRow) => {
      if (closed) throw new Error("store is closed");
      assertPathIdentity();
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
    assertPathIdentity,
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
