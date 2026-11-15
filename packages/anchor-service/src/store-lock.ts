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

/** Tokens of locks this process wrote for stores. */
const ownTokens = new Set<string>();

export function storeLockPath(storePath: string): string {
  return `${storePath}.lock`;
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
   * The service latches store-unavailable; the lock is not removed.
   */
  onLost: (cb: () => void) => void;
  release: () => void;
};

export type AcquireStoreLockOpts = {
  /** How often the held lock is touched; tests shorten it. */
  lockBeatMs?: number;
};

function lockedError(storePath: string): Error {
  return new Error(`store already locked: ${storePath}`);
}

function lockExists(lockPath: string): boolean {
  try {
    return lstatSync(lockPath).isDirectory();
  } catch {
    return false;
  }
}

function tryCreate(lockPath: string, body: string): boolean {
  try {
    mkdirSync(lockPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    return false;
  }
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
function takeOverStale(lockPath: string, judgedBytes: string, judgedToken: string, body: string): boolean {
  const gate = takeoverGatePath(lockPath);
  try {
    mkdirSync(gate);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    return false;
  }
  try {
    const current = readHolderBytes(lockPath);
    if (current !== judgedBytes) return false;
    const again = parseHolder(current);
    if (again?.token !== judgedToken) return false;
    rmSync(lockPath, { recursive: true, force: true });
    return tryCreate(lockPath, body);
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

  if (!tryCreate(lockPath, body)) {
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
      if (!tryCreate(lockPath, body)) throw lockedError(storePath);
    } else {
      const lock = parseHolder(judgedBytes);
      const state = lock ? judge(lockPath, lock) : null;
      if (state === "stale") {
        if (typeof lock?.token !== "string") throw lockedError(storePath);
        if (!takeOverStale(lockPath, judgedBytes, lock.token, body)) {
          throw lockedError(storePath);
        }
      } else if (state === "gone" && !lockExists(lockPath)) {
        if (!tryCreate(lockPath, body)) throw lockedError(storePath);
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
