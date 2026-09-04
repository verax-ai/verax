import { appendFileSync, existsSync, readFileSync, unlinkSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";

export function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

export function readLockFile(path: string): { pid: number; startedAt: number } | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as { pid?: unknown; startedAt?: unknown };
    if (typeof raw.pid !== "number" || typeof raw.startedAt !== "number") return null;
    return { pid: raw.pid, startedAt: raw.startedAt };
  } catch {
    return null;
  }
}

export function runUnlock(stateDir: string, writeErr: (s: string) => void = (s) => process.stderr.write(s)): number {
  const lockPath = join(stateDir, "ledger.lock");
  if (!existsSync(lockPath)) {
    writeErr("no-lock\n");
    return 1;
  }
  const existing = readLockFile(lockPath);
  if (!existing) {
    writeErr("lock-unreadable\n");
    return 1;
  }
  if (pidAlive(existing.pid)) {
    writeErr(`still-running:${existing.pid}\n`);
    return 1;
  }
  unlinkSync(lockPath);
  const row = {
    atMs: Date.now(),
    removedPid: existing.pid,
    startedAt: existing.startedAt,
    operator: userInfo().username,
  };
  appendFileSync(join(stateDir, "unlocks.jsonl"), `${JSON.stringify(row)}\n`, { encoding: "utf8" });
  return 0;
}
