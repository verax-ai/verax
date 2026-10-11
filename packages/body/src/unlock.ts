import { appendFileSync, existsSync, readFileSync, unlinkSync } from "node:fs";
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

export function runUnlock(
  stateDir: string,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  options: { force?: boolean; unlink?: (path: string) => void } = {},
): number {
  const lockPath = join(stateDir, "ledger.lock");
  if (!existsSync(lockPath)) {
    writeErr("no-lock\n");
    return 1;
  }
  const existing = readLockFile(lockPath);
  if (!existing) {
    if (!options.force) {
      writeErr("lock-unreadable\n");
      return 1;
    }
  } else {
    // A lock that beats is watched, so a body in another container that shares this pid is seen.
    const state = lockState(lockPath, existing);
    if (state === "held") {
      writeErr(`still-running:${existing.pid}\n`);
      return 1;
    }
    if (state === "gone") {
      writeErr("no-lock\n");
      return 1;
    }
  }
  const operator = operatorName();
  const base = existing
    ? {
        removedPid: existing.pid,
        startedAt: existing.startedAt,
        operator,
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
  const unlink = options.unlink ?? unlinkSync;
  try {
    unlink(lockPath);
  } catch (err) {
    const code = errnoCode(err);
    try {
      appendUnlockRow(stateDir, {
        atMs: Date.now(),
        ...base,
        result: "unlink-failed",
        error: code,
      });
    } catch (recordErr) {
      writeErr(`record-failed:${errnoCode(recordErr)}\n`);
      return 1;
    }
    writeErr(`unlink-failed:${code}\n`);
    return 1;
  }
  try {
    appendUnlockRow(stateDir, { atMs: Date.now(), ...base, result: "removed" });
  } catch (err) {
    writeErr(`record-failed:${errnoCode(err)}\n`);
    return 1;
  }
  return 0;
}
