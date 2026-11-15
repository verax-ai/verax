/**
 * Exclusive lock for one store file. Reuses the body's lockState rule from
 * @verax-ai/proxy (beat movement, then pid / start time / boot id) without
 * opening a FileLedger. Unlike the body, a stale lock is taken over so a
 * dead holder cannot block start forever.
 */
import { randomBytes } from "node:crypto";
import {
  existsSync,
  readFileSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { lockBeatOf, lockState, type LockHolder } from "@verax-ai/proxy";

/** Same default beat as the body's ledger.lock. */
export const STORE_LOCK_BEAT_MS = 2000;

/** Tokens of locks this process wrote for stores. */
const ownTokens = new Set<string>();

export function storeLockPath(storePath: string): string {
  return `${storePath}.lock`;
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

function readLock(path: string): LockHolder | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
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
 * Staleness: same as the body — a beating lock that moves is held; one that
 * does not move (or has no beat) is stale only when lockHolderAlive says the
 * named process cannot still be the writer (dead pid, wrong boot, or this
 * pid with a start time before this process). Pid alone is never enough.
 */
function judge(lockPath: string, lock: LockHolder): "held" | "quiet" | "stale" | "gone" {
  if (lock.token !== undefined && ownTokens.has(lock.token)) return "held";
  return lockState(lockPath, lock);
}

export type StoreLock = {
  path: string;
  release: () => void;
};

export type AcquireStoreLockOpts = {
  /** How often the held lock is touched; tests shorten it. */
  lockBeatMs?: number;
};

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

  const tryCreate = (): boolean => {
    try {
      writeFileSync(lockPath, body, { encoding: "utf8", flag: "wx", mode: 0o600 });
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      return false;
    }
  };

  if (!tryCreate()) {
    const existing = readLock(lockPath);
    const state = existing ? judge(lockPath, existing) : null;
    if (state === "stale" || (state === "gone" && !existsSync(lockPath))) {
      if (state === "stale") {
        try {
          unlinkSync(lockPath);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        }
      }
      if (!tryCreate()) {
        throw new Error(`store already locked: ${storePath}`);
      }
    } else {
      throw new Error(`store already locked: ${storePath}`);
    }
  }

  ownTokens.add(token);
  const beat = setInterval(() => {
    try {
      const now = new Date();
      utimesSync(lockPath, now, now);
    } catch {
      // A missed beat is read as still; the next one corrects it.
    }
  }, beatMs);
  beat.unref();

  let released = false;
  return {
    path: lockPath,
    release: () => {
      if (released) return;
      released = true;
      clearInterval(beat);
      ownTokens.delete(token);
      const onDisk = readLock(lockPath);
      if (onDisk?.token !== token) return;
      try {
        unlinkSync(lockPath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    },
  };
}
