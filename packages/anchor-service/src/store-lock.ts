/**
 * Exclusive lock for one store file. Reuses the body's lockState rule from
 * @verax-ai/proxy (beat movement, then pid / start time / boot id) without
 * opening a FileLedger. The lock is a directory beside the store so create
 * and takeover use exclusive mkdir. A stale takeover first mkdir's a gate
 * directory so only one waiter may remove the judged holder bytes; a process
 * never removes a lock whose token is not the one it judged stale.
 */
import { randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { lockBeatOf, lockState, type LockHolder } from "@verax-ai/proxy";

/** Same default beat as the body's ledger.lock. */
export const STORE_LOCK_BEAT_MS = 2000;

/**
 * On win32, mkdir of a path another process is removing can fail with EPERM
 * until the removal finishes. Retry this many times (with a short wait) so a
 * contender either creates the directory or sees EEXIST. Total wait stays
 * well under one second. Other platforms never retry EPERM.
 */
export const WIN32_MKDIR_EPERM_TRIES = 20;
const WIN32_MKDIR_EPERM_WAIT_MS = 25;

/** Tokens of locks this process wrote for stores. */
const ownTokens = new Set<string>();

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

type LockMkdirIo = {
  platform: NodeJS.Platform;
  mkdirSync: typeof mkdirSync;
};

/**
 * Exclusive mkdir. Returns true when created, false on EEXIST. On win32 only,
 * EPERM is retried up to WIN32_MKDIR_EPERM_TRIES; a lasting EPERM is rethrown.
 */
function mkdirExclusive(path: string, io: LockMkdirIo): boolean {
  const maxTries = io.platform === "win32" ? WIN32_MKDIR_EPERM_TRIES : 1;
  for (let tryNo = 1; ; tryNo += 1) {
    try {
      io.mkdirSync(path);
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EEXIST") return false;
      if (code === "EPERM" && io.platform === "win32" && tryNo < maxTries) {
        sleepSync(WIN32_MKDIR_EPERM_WAIT_MS);
        continue;
      }
      throw err;
    }
  }
}

export function storeLockPath(storePath: string): string {
  return `${storePath}.lock`;
}

export function storeTakeoverGatePath(storePath: string): string {
  return `${storeLockPath(storePath)}.takeover`;
}

function holderPath(lockPath: string): string {
  return join(lockPath, "holder");
}

function takeoverGatePath(lockPath: string): string {
  return `${lockPath}.takeover`;
}

function currentBootId(): string | null {
  if (process.platform !== "linux") return null;
  try {
    const id = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return id === "" ? null : id;
  } catch {
    return null;
  }
}

function readLock(lockPath: string): LockHolder | null {
  try {
    const raw = JSON.parse(readFileSync(holderPath(lockPath), "utf8")) as {
      pid?: unknown;
      startedAt?: unknown;
      token?: unknown;
      bootId?: unknown;
      beatMs?: unknown;
    };
    if (typeof raw.pid !== "number" || typeof raw.startedAt !== "number" || !Number.isFinite(raw.startedAt)) {
      return null;
    }
    const beatMs = lockBeatOf(raw.beatMs);
    return {
      pid: raw.pid,
      startedAt: raw.startedAt,
      ...(typeof raw.token === "string" ? { token: raw.token } : {}),
      ...(typeof raw.bootId === "string" && raw.bootId !== "" ? { bootId: raw.bootId } : {}),
      ...(beatMs !== undefined ? { beatMs } : {}),
    };
  } catch {
    return null;
  }
}

function readHolderBytes(lockPath: string): string | null {
  try {
    return readFileSync(holderPath(lockPath), "utf8");
  } catch {
    return null;
  }
}

/**
 * Staleness: same as the body — a beating lock that moves is held; one that
 * does not move (or has no beat) is stale only when lockHolderAlive says the
 * named process cannot still be the writer (dead pid, wrong boot, or this
 * pid with a start time before this process). Pid alone is never enough.
 */
function judge(lockPath: string, lock: LockHolder): "held" | "quiet" | "stale" | "gone" {
  if (lock.token !== undefined && ownTokens.has(lock.token)) return "held";
  return lockState(holderPath(lockPath), lock);
}

export type StoreLock = {
  path: string;
  /** True while the lock on disk still carries this holder's token. */
  stillHeld: () => boolean;
  /**
   * Called once when a beat finds the lock missing or carrying another token.
   * The lock is not removed.
   */
  onLost: (cb: () => void) => void;
  release: () => void;
};

/** Named points where a test may pause a stale takeover. Never from the environment. */
export type TakeoverPausePoint =
  | "after-stale-before-gate"
  | "inside-gate-before-recheck"
  | "inside-gate-before-removal";

export type AcquireStoreLockOpts = {
  /** How often the held lock is touched; tests shorten it. */
  lockBeatMs?: number;
  /**
   * Test-only hook: called at named points during stale takeover. Production
   * callers omit this; it is never read from the environment.
   */
  pauseAt?: (point: TakeoverPausePoint) => void;
  /**
   * Test-only: platform string for win32 EPERM mkdir retry. Defaults to
   * `process.platform`. Not a global patch.
   */
  platform?: NodeJS.Platform;
  /**
   * Test-only: substitute for mkdirSync used by lock and takeover-gate create.
   * Defaults to `fs.mkdirSync`. Not exposed through the CLI.
   */
  mkdirSync?: typeof mkdirSync;
};

function lockedError(storePath: string): Error {
  return new Error(`store already locked: ${storePath}`);
}

/** Fixed sentence when a previous takeover left the gate directory behind. */
export function takeoverGatePresentError(storePath: string): Error {
  const gate = storeTakeoverGatePath(storePath);
  return new Error(
    `store lock takeover gate is present at ${gate}; confirm no takeover is in progress, then remove that gate directory before starting again`,
  );
}

function lockExists(lockPath: string): boolean {
  try {
    return lstatSync(lockPath).isDirectory();
  } catch {
    return false;
  }
}

function tryCreate(lockPath: string, body: string, io: LockMkdirIo): boolean {
  if (!mkdirExclusive(lockPath, io)) return false;
  try {
    writeFileSync(holderPath(lockPath), body, { encoding: "utf8", flag: "wx", mode: 0o600 });
    return true;
  } catch (err) {
    try {
      rmSync(lockPath, { recursive: true, force: true });
    } catch {
      // Best effort; leaving a broken lock directory refuses later starts.
    }
    throw err;
  }
}

function parseHolder(judgedBytes: string): LockHolder | null {
  try {
    const raw = JSON.parse(judgedBytes) as {
      pid?: unknown;
      startedAt?: unknown;
      token?: unknown;
      bootId?: unknown;
      beatMs?: unknown;
    };
    if (typeof raw.pid !== "number" || typeof raw.startedAt !== "number" || !Number.isFinite(raw.startedAt)) {
      return null;
    }
    const beatMs = lockBeatOf(raw.beatMs);
    return {
      pid: raw.pid,
      startedAt: raw.startedAt,
      ...(typeof raw.token === "string" ? { token: raw.token } : {}),
      ...(typeof raw.bootId === "string" && raw.bootId !== "" ? { bootId: raw.bootId } : {}),
      ...(beatMs !== undefined ? { beatMs } : {}),
    };
  } catch {
    return null;
  }
}

/**
 * Under an exclusive takeover gate, remove the lock only when its holder
 * bytes are still exactly the ones judged stale, then create ours.
 */
function takeOverStale(
  lockPath: string,
  storePath: string,
  judgedBytes: string,
  body: string,
  io: LockMkdirIo,
  pauseAt?: (point: TakeoverPausePoint) => void,
): boolean {
  const gate = takeoverGatePath(lockPath);
  pauseAt?.("after-stale-before-gate");
  if (!mkdirExclusive(gate, io)) {
    throw takeoverGatePresentError(storePath);
  }
  try {
    pauseAt?.("inside-gate-before-recheck");
    const current = readHolderBytes(lockPath);
    // Byte identity already refuses a changed token (token is part of the
    // holder JSON). A separate token recheck cannot fail on its own.
    if (current !== judgedBytes) return false;
    // After the recheck and before removal: a second waiter must not be here.
    pauseAt?.("inside-gate-before-removal");
    rmSync(lockPath, { recursive: true, force: true });
    return tryCreate(lockPath, body, io);
  } finally {
    try {
      rmSync(gate, { recursive: true, force: true });
    } catch {
      // Gate left behind blocks the next stale takeover until removed.
    }
  }
}

export function acquireStoreLock(storePath: string, opts?: AcquireStoreLockOpts): StoreLock {
  const lockPath = storeLockPath(storePath);
  const beatMs = lockBeatOf(opts?.lockBeatMs) ?? STORE_LOCK_BEAT_MS;
  const token = randomBytes(16).toString("hex");
  const bootId = currentBootId();
  const body = `${JSON.stringify({
    pid: process.pid,
    startedAt: Date.now(),
    token,
    ...(bootId ? { bootId } : {}),
    beatMs,
  })}\n`;
  const io: LockMkdirIo = {
    platform: opts?.platform ?? process.platform,
    mkdirSync: opts?.mkdirSync ?? mkdirSync,
  };

  if (!tryCreate(lockPath, body, io)) {
    try {
      const st = lstatSync(lockPath);
      if (st.isFile() || st.isSymbolicLink()) {
        throw new Error(`store lock at ${lockPath} is not a lock directory; remove it and start again`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("store lock at ")) throw err;
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }

    const judgedBytes = readHolderBytes(lockPath);
    if (judgedBytes === null) {
      if (!tryCreate(lockPath, body, io)) throw lockedError(storePath);
    } else {
      const lock = parseHolder(judgedBytes);
      const state = lock ? judge(lockPath, lock) : null;
      if (state === "stale") {
        if (typeof lock?.token !== "string") throw lockedError(storePath);
        if (!takeOverStale(lockPath, storePath, judgedBytes, body, io, opts?.pauseAt)) {
          throw lockedError(storePath);
        }
      } else if (state === "gone" && !lockExists(lockPath)) {
        if (!tryCreate(lockPath, body, io)) throw lockedError(storePath);
      } else {
        throw lockedError(storePath);
      }
    }
  }

  ownTokens.add(token);
  let lost = false;
  let lostCb: (() => void) | null = null;
  const markLost = (): void => {
    if (lost) return;
    lost = true;
    lostCb?.();
  };
  const stillHeld = (): boolean => {
    if (lost) return false;
    const onDisk = readLock(lockPath);
    if (onDisk?.token === token) return true;
    markLost();
    return false;
  };

  const beatTarget = holderPath(lockPath);
  const beat = setInterval(() => {
    try {
      if (!stillHeld()) {
        clearInterval(beat);
        return;
      }
      const now = new Date();
      utimesSync(beatTarget, now, now);
    } catch {
      markLost();
      clearInterval(beat);
    }
  }, beatMs);
  beat.unref();

  let released = false;
  return {
    path: lockPath,
    stillHeld,
    onLost: (cb) => {
      lostCb = cb;
      if (lost) cb();
    },
    release: () => {
      if (released) return;
      released = true;
      clearInterval(beat);
      ownTokens.delete(token);
      const onDisk = readLock(lockPath);
      if (onDisk?.token !== token) return;
      try {
        rmSync(lockPath, { recursive: true, force: true });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    },
  };
}
