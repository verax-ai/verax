import { randomBytes } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

export const ALARM_OUTBOX_DIR = "alarm-outbox";
export const ALARM_HISTORY = "alarm-history.jsonl";

export type AlarmEnvelope = { payload: Record<string, unknown>; sig: string };

function outboxDir(stateDir: string): string {
  return join(stateDir, ALARM_OUTBOX_DIR);
}

function outboxPath(stateDir: string, eventId: string): string {
  return join(outboxDir(stateDir), `${eventId}.json`);
}

function isUnsupportedDirFsync(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === "EPERM" || code === "EISDIR" || code === "EINVAL" || code === "ENOTSUP" || code === "ENOSYS";
}

function fsyncDir(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    if (isUnsupportedDirFsync(err)) return;
    throw err;
  }
}

/** Temporary file, fsync, rename. A reader sees the old file or the new one. */
function writeFileDurable(finalPath: string, payload: string): void {
  const dir = dirname(finalPath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  fsyncDir(dir);
  const tmp = `${finalPath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, payload, 0, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, finalPath);
  try {
    chmodSync(finalPath, 0o600);
  } catch {
    // Windows may refuse chmod; the file is already written.
  }
  fsyncDir(dir);
}

export function writeAlarmOutbox(stateDir: string, envelope: AlarmEnvelope): void {
  const eventId = envelope.payload.eventId;
  if (typeof eventId !== "string" || eventId === "") throw new Error("alarm-event-id-missing");
  writeFileDurable(outboxPath(stateDir, eventId), `${JSON.stringify(envelope)}\n`);
}

export function listAlarmOutbox(stateDir: string): AlarmEnvelope[] {
  const dir = outboxDir(stateDir);
  if (!existsSync(dir)) return [];
  const names = readdirSync(dir).filter((name) => name.endsWith(".json")).sort();
  const out: AlarmEnvelope[] = [];
  for (const name of names) {
    try {
      const parsed = JSON.parse(readFileSync(join(dir, name), "utf8")) as AlarmEnvelope;
      if (!parsed || typeof parsed !== "object" || typeof parsed.sig !== "string") continue;
      if (!parsed.payload || typeof parsed.payload !== "object") continue;
      out.push(parsed);
    } catch {
      // A torn file is left for the next pass; it is not delivered.
    }
  }
  return out;
}

export function markAlarmDelivered(stateDir: string, envelope: AlarmEnvelope, now = Date.now()): void {
  const eventId = envelope.payload.eventId;
  if (typeof eventId !== "string" || eventId === "") return;
  const path = outboxPath(stateDir, eventId);
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  const line = {
    eventId,
    deliveredAtMs: now,
    triggerCode: envelope.payload.triggerCode,
  };
  appendFileSync(join(stateDir, ALARM_HISTORY), `${JSON.stringify(line)}\n`, { encoding: "utf8", mode: 0o600 });
}
