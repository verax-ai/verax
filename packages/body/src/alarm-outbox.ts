import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const ALARM_OUTBOX_DIR = "alarm-outbox";
export const ALARM_HISTORY = "alarm-history.jsonl";
export const ALARM_EVENT_ID = /^[0-9a-f-]{36}$/i;

export type AlarmEnvelope = { payload: Record<string, unknown>; sig: string };

export function isAlarmEventId(eventId: string): boolean {
  if (!ALARM_EVENT_ID.test(eventId)) return false;
  if (eventId.includes("/") || eventId.includes("\\") || eventId.includes("..")) return false;
  return true;
}

/** A leaf name that cannot walk out of the outbox directory. */
export function isSafeOutboxEventId(eventId: string): boolean {
  if (eventId === "" || eventId.includes("/") || eventId.includes("\\") || eventId.includes("..")) return false;
  return true;
}

function outboxDir(stateDir: string): string {
  return join(stateDir, ALARM_OUTBOX_DIR);
}

function outboxPath(stateDir: string, eventId: string): string {
  if (!isSafeOutboxEventId(eventId)) throw new Error("alarm-event-id-invalid");
  const dir = resolve(outboxDir(stateDir));
  const leaf = `${eventId}.json`;
  const path = resolve(dir, leaf);
  const rel = relative(dir, path);
  if (rel === "" || isAbsolute(rel) || rel.startsWith("..") || rel.split(sep).includes("..")) {
    throw new Error("alarm-outbox-path-escape");
  }
  if (path !== join(dir, leaf)) throw new Error("alarm-outbox-path-escape");
  return path;
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

/** Same-name file beside the outbox directory. A folder here blocks the write. */
export const ALARM_OUTBOX_RECORD = `${ALARM_OUTBOX_DIR}.json`;

function outboxRecordPath(stateDir: string): string {
  return join(stateDir, ALARM_OUTBOX_RECORD);
}

function readOutboxEnvelope(path: string): AlarmEnvelope | null {
  try {
    if (!statSync(path).isFile()) return null;
    const parsed = JSON.parse(readFileSync(path, "utf8")) as AlarmEnvelope;
    if (!parsed || typeof parsed !== "object" || typeof parsed.sig !== "string" || parsed.sig === "") return null;
    if (!parsed.payload || typeof parsed.payload !== "object") return null;
    const id = parsed.payload.eventId;
    if (typeof id !== "string" || !isSafeOutboxEventId(id)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function hasAlarmOutbox(stateDir: string, eventId: string): boolean {
  if (!isSafeOutboxEventId(eventId)) return false;
  const envelope = readOutboxEnvelope(outboxPath(stateDir, eventId));
  return envelope !== null && envelope.payload.eventId === eventId;
}

export function deliveredAlarmIds(stateDir: string): Set<string> {
  const path = join(stateDir, ALARM_HISTORY);
  if (!existsSync(path)) return new Set();
  const raw = readFileSync(path, "utf8");
  const ids = new Set<string>();
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    try {
      const row = JSON.parse(line) as { eventId?: unknown };
      if (typeof row.eventId === "string" && isSafeOutboxEventId(row.eventId)) ids.add(row.eventId);
    } catch {
      // A torn history line is not a delivery.
    }
  }
  return ids;
}

export function hasAlarmDelivery(stateDir: string, eventId: string): boolean {
  return deliveredAlarmIds(stateDir).has(eventId);
}

function appendFileDurable(path: string, line: string): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const fd = openSync(path, "a+", 0o600);
  try {
    const size = fstatSync(fd).size;
    if (size > 0) {
      const last = Buffer.alloc(1);
      if (readSync(fd, last, 0, 1, size - 1) === 1 && last[0] !== 0x0a) {
        writeSync(fd, "\n", null, "utf8");
      }
    }
    writeSync(fd, line, null, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDir(dir);
}

export function writeAlarmOutbox(stateDir: string, envelope: AlarmEnvelope): void {
  const eventId = envelope.payload.eventId;
  if (typeof eventId !== "string" || eventId === "") throw new Error("alarm-event-id-missing");
  if (!isSafeOutboxEventId(eventId)) throw new Error("alarm-event-id-invalid");
  const body = `${JSON.stringify(envelope)}\n`;
  writeFileDurable(outboxRecordPath(stateDir), body);
  writeFileDurable(outboxPath(stateDir, eventId), body);
}

export function listAlarmOutbox(stateDir: string): AlarmEnvelope[] {
  const delivered = deliveredAlarmIds(stateDir);
  const dir = outboxDir(stateDir);
  if (!existsSync(dir)) return [];
  const names = readdirSync(dir).filter((name) => name.endsWith(".json")).sort();
  const out: AlarmEnvelope[] = [];
  for (const name of names) {
    const parsed = readOutboxEnvelope(join(dir, name));
    if (!parsed) continue;
    const eventId = parsed.payload.eventId;
    if (typeof eventId !== "string" || delivered.has(eventId)) continue;
    out.push(parsed);
  }
  return out;
}

export function markAlarmDelivered(stateDir: string, envelope: AlarmEnvelope, now = Date.now()): void {
  const eventId = envelope.payload.eventId;
  if (typeof eventId !== "string" || !isSafeOutboxEventId(eventId)) return;
  const line = {
    eventId,
    deliveredAtMs: now,
    triggerCode: envelope.payload.triggerCode,
  };
  appendFileDurable(join(stateDir, ALARM_HISTORY), `${JSON.stringify(line)}\n`);
  for (const path of [outboxPath(stateDir, eventId), outboxRecordPath(stateDir)]) {
    try {
      unlinkSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }
}
