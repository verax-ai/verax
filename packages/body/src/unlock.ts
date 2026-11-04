import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import { lockBeatOf, lockState } from "@verax-ai/proxy";

export function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

export type LockRecord = { pid: number; startedAt: number; port?: number; bootId?: string; token?: string; beatMs?: number };

/** A lock from before the body recorded its port has no `port`. That is still a lock. */
export function readLockFile(path: string): LockRecord | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      pid?: unknown;
      startedAt?: unknown;
      port?: unknown;
      bootId?: unknown;
      token?: unknown;
      beatMs?: unknown;
    };
    if (typeof raw.pid !== "number" || typeof raw.startedAt !== "number" || !Number.isFinite(raw.startedAt)) return null;
    const record: LockRecord = { pid: raw.pid, startedAt: raw.startedAt };
    if (typeof raw.port === "number" && Number.isInteger(raw.port) && raw.port > 0 && raw.port < 65536) {
      record.port = raw.port;
    }
    if (typeof raw.bootId === "string" && raw.bootId !== "") record.bootId = raw.bootId;
    if (typeof raw.token === "string") record.token = raw.token;
    const beatMs = lockBeatOf(raw.beatMs);
    if (beatMs !== undefined) record.beatMs = beatMs;
    return record;
  } catch {
    return null;
  }
}

function operatorName(): string {
  try {
    const name = userInfo().username;
    return name.length > 0 ? name : "unknown";
  } catch {
    return "unknown";
  }
}

function errnoCode(err: unknown): string {
  return (err as NodeJS.ErrnoException).code ?? "ERR";
}

function appendUnlockRow(stateDir: string, row: Record<string, unknown>): void {
  appendFileSync(join(stateDir, "unlocks.jsonl"), `${JSON.stringify(row)}\n`, {
    encoding: "utf8",
  });
}

function lockText(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Puts a lock moved aside back, unless a newer one took its place. Its holder then finds the lock lost and stops. */
function restoreLock(claim: string, lockPath: string): void {
  const text = lockText(claim);
  try {
    if (text !== null) writeFileSync(lockPath, text, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch {
    // A newer lock is in place.
  }
  rmSync(claim, { force: true });
}

export function runUnlock(
  stateDir: string,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  options: { force?: boolean; unlink?: (path: string) => void; afterJudge?: () => void; beforeMove?: () => void } = {},
): number {
  const lockPath = join(stateDir, "ledger.lock");
  if (!existsSync(lockPath)) {
    writeErr("no-lock\n");
    return 1;
  }
  const judged = lockText(lockPath);
  if (judged === null) {
    writeErr(existsSync(lockPath) ? "lock-unreadable\n" : "no-lock\n");
    return 1;
  }
  const existing = readLockFile(lockPath);
  let forcedQuiet = false;
  if (!existing) {
    if (!options.force) {
      writeErr("lock-unreadable\n");
      return 1;
    }
  } else {
    // A lock that beats is watched, so a body in another container that shares this pid is seen.
    const state = lockState(lockPath, existing);
    if (state === "gone") {
      writeErr("no-lock\n");
      return 1;
    }
    // A still lock under a live pid: a frozen body, or a dead one whose pid another
    // process now has. Only the operator can say which, so it takes --force and a record.
    forcedQuiet = state === "quiet" && options.force === true;
    if (state === "held" || (state === "quiet" && !forcedQuiet)) {
      writeErr(`still-running:${existing.pid}\n`);
      if (state === "quiet") {
        writeErr(
          `lock-not-beating: pid ${existing.pid} is alive but the lock has not moved; if no body is running, run verax unlock --force\n`,
        );
      }
      return 1;
    }
  }
  const operator = operatorName();
  const base = existing
    ? {
        removedPid: existing.pid,
        startedAt: existing.startedAt,
        operator,
        ...(forcedQuiet ? { reason: "not-beating" } : {}),
      }
    : {
        removedPid: null,
        startedAt: null,
        operator,
        reason: "unreadable",
      };
  try {
    appendUnlockRow(stateDir, { atMs: Date.now(), ...base, result: "removing" });
  } catch (err) {
    writeErr(`record-failed:${errnoCode(err)}\n`);
    return 1;
  }
  const refuse = (result: string, line: string, error?: string): number => {
    try {
      appendUnlockRow(stateDir, { atMs: Date.now(), ...base, result, ...(error ? { error } : {}) });
    } catch (recordErr) {
      writeErr(`record-failed:${errnoCode(recordErr)}\n`);
      return 1;
    }
    writeErr(line);
    return 1;
  };
  options.afterJudge?.();
  // Judging can take five beats, and another start may have cleared this lock and taken its own
  // meanwhile. A lock that already differs is not touched. Moved aside first, the lock is removed
  // only if it is still the one that was judged.
  if (!existsSync(lockPath)) return refuse("already-gone", "no-lock\n");
  if (lockText(lockPath) !== judged) return refuse("lock-changed", "lock-changed\n");
  options.beforeMove?.();
  const claim = `${lockPath}.${randomUUID()}`;
  try {
    renameSync(lockPath, claim);
  } catch (err) {
    const code = errnoCode(err);
    if (code === "ENOENT") return refuse("already-gone", "no-lock\n");
    return refuse("unlink-failed", `unlink-failed:${code}\n`, code);
  }
  if (lockText(claim) !== judged) {
    restoreLock(claim, lockPath);
    return refuse("lock-changed", "lock-changed\n");
  }
  const unlink = options.unlink ?? unlinkSync;
  try {
    unlink(claim);
  } catch (err) {
    const code = errnoCode(err);
    restoreLock(claim, lockPath);
    return refuse("unlink-failed", `unlink-failed:${code}\n`, code);
  }
  try {
    appendUnlockRow(stateDir, { atMs: Date.now(), ...base, result: "removed" });
  } catch (err) {
    writeErr(`record-failed:${errnoCode(err)}\n`);
    return 1;
  }
  return 0;
}

/**
 * For a service manager's start, where nobody is there to run `verax unlock`. Clears what
 * `verax unlock --force` would clear, with the same record: the manager runs one instance, so a
 * lock that does not move has no running owner, and on Windows a reboot can hand its pid to
 * another process. A lock that moves stays, and the ledger refuses it as before.
 */
export function clearStaleLockAtStart(stateDir: string, writeErr: (s: string) => void): void {
  if (existsSync(join(stateDir, "ledger.lock"))) runUnlock(stateDir, writeErr, { force: true });
}
