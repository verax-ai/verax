import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID, sign } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { canonical } from "@cedulon/core";
import {
  hasAlarmDelivery,
  hasAlarmOutbox,
  isAlarmEventId,
  writeAlarmOutbox,
  type AlarmEnvelope,
} from "./alarm-outbox.ts";
import { haltBody, readHalt } from "./halt.ts";
import type { IntegrityReason } from "./memory-store.ts";

export const INCIDENT_BY = "verax:memory-integrity";
export const INCIDENT_RECORD = "incident.json";

const INTEGRITY_REASONS = new Set<string>([
  "memory-integrity-mismatch",
  "memory-integrity-missing",
  "memory-integrity-unattested",
  "memory-integrity-history-unavailable",
]);

export type IncidentPayload = {
  v: 1;
  purpose: "verax.incident.v1";
  eventId: string;
  observedAt: number;
  triggerCode: string;
  scopeKind: "global";
  enforcementState: "halted";
  keyId: string;
  memoryHead?: { seq: number; lastHash: string };
};

type StoredIncident = {
  eventId: string;
  triggerCode: IntegrityReason;
  observedAt: number;
  memoryHead?: { seq: number; lastHash: string };
  envelope?: AlarmEnvelope;
};

export function recordKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

export function signIncident(payload: IncidentPayload, privateKeyPem: string): AlarmEnvelope {
  const sig = sign(null, Buffer.from(canonical(payload), "utf8"), createPrivateKey(privateKeyPem)).toString("base64");
  return { payload, sig };
}

function isIntegrityReason(value: string): value is IntegrityReason {
  return INTEGRITY_REASONS.has(value);
}

function oneLine(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err);
  return text.replace(/[\r\n]+/g, " ").slice(0, 300);
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

function writeJsonDurable(path: string, value: unknown): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  fsyncDir(dir);
  const tmp = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, `${JSON.stringify(value)}\n`, 0, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  try {
    chmodSync(path, 0o600);
  } catch {
    // Windows may refuse chmod; the file is already written.
  }
  fsyncDir(dir);
}

function incidentRecordPath(stateDir: string): string {
  return join(stateDir, INCIDENT_RECORD);
}

function readIncidentRecord(stateDir: string): StoredIncident | null {
  let raw: string;
  try {
    raw = readFileSync(incidentRecordPath(stateDir), "utf8");
  } catch {
    return null;
  }
  try {
    const row = JSON.parse(raw) as Partial<StoredIncident> & { envelope?: AlarmEnvelope };
    if (typeof row.eventId !== "string" || !isAlarmEventId(row.eventId)) return null;
    if (typeof row.triggerCode !== "string" || !isIntegrityReason(row.triggerCode)) return null;
    if (typeof row.observedAt !== "number" || !Number.isFinite(row.observedAt)) return null;
    const stored: StoredIncident = {
      eventId: row.eventId,
      triggerCode: row.triggerCode,
      observedAt: row.observedAt,
    };
    const head = row.memoryHead;
    if (head && typeof head === "object" && typeof head.seq === "number" && typeof head.lastHash === "string") {
      stored.memoryHead = { seq: head.seq, lastHash: head.lastHash };
    }
    if (row.envelope && typeof row.envelope === "object" && typeof row.envelope.sig === "string") {
      stored.envelope = row.envelope;
    }
    return stored;
  } catch {
    return null;
  }
}

function writeIncidentRecord(stateDir: string, record: StoredIncident): void {
  writeJsonDurable(incidentRecordPath(stateDir), record);
}

function readHistoryIdentity(stateDir: string): StoredIncident | null {
  const halt = readHalt(stateDir);
  if (!halt.halted || halt.since?.via !== "integrity" || typeof halt.since.eventId !== "string") return null;
  if (!isAlarmEventId(halt.since.eventId)) {
    process.stderr.write("verax: incident: history eventId rejected\n");
    return null;
  }
  const trigger = halt.since.triggerCode ?? "";
  if (!isIntegrityReason(trigger)) {
    process.stderr.write("verax: incident: history triggerCode rejected\n");
    return null;
  }
  return {
    eventId: halt.since.eventId,
    triggerCode: trigger,
    observedAt: halt.since.atMs,
    ...(halt.since.memoryHead ? { memoryHead: halt.since.memoryHead } : {}),
  };
}

function readIntegrityIdentity(stateDir: string): StoredIncident | null {
  const halt = readHalt(stateDir);
  if (!halt.halted) return null;
  const record = readIncidentRecord(stateDir);
  const history = readHistoryIdentity(stateDir);
  if (history) {
    if (record?.eventId === history.eventId) return record;
    return history;
  }
  // C1: switch with no history line — the on-disk record is this halt.
  // An operator halt has `since` and does not own a leftover record.
  if (record && (!halt.since || halt.since.via === "integrity")) return record;
  return null;
}

function persistEnvelope(stateDir: string, envelope: AlarmEnvelope): void {
  try {
    writeAlarmOutbox(stateDir, envelope);
  } catch (err) {
    process.stderr.write(`verax: alarm-outbox: ${oneLine(err)}\n`);
  }
}

export function raiseMemoryIntegrityIncident(opts: {
  stateDir: string;
  reason: IntegrityReason;
  publicKeyPem: string;
  privateKeyPem: string;
  memoryHead?: { seq: number; lastHash: string };
  alarmWebhookUrl?: string;
  now?: number;
}): AlarmEnvelope | null {
  const already = existsSync(join(opts.stateDir, "halted"));
  const existing = already ? readIntegrityIdentity(opts.stateDir) : null;
  if (already && !existing) return null;
  const eventId = existing?.eventId ?? randomUUID();
  const observedAt = existing?.observedAt ?? opts.now ?? Date.now();
  const triggerCode = existing?.triggerCode ?? opts.reason;
  const memoryHead = existing?.memoryHead ?? opts.memoryHead;
  const record: StoredIncident = {
    eventId,
    triggerCode,
    observedAt,
    ...(memoryHead ? { memoryHead } : {}),
    ...(existing?.envelope ? { envelope: existing.envelope } : {}),
  };
  const stored = readIncidentRecord(opts.stateDir);
  if (!already || !stored || stored.eventId !== eventId) writeIncidentRecord(opts.stateDir, record);

  if (!already) {
    haltBody(opts.stateDir, INCIDENT_BY, "integrity", observedAt, undefined, {
      eventId,
      triggerCode,
      ...(memoryHead ? { memoryHead } : {}),
    });
  }

  if (!opts.alarmWebhookUrl) return null;
  if (hasAlarmDelivery(opts.stateDir, eventId)) return null;
  if (already && hasAlarmOutbox(opts.stateDir, eventId)) return null;

  const envelope =
    record.envelope ??
    signIncident(
      {
        v: 1,
        purpose: "verax.incident.v1",
        eventId,
        observedAt,
        triggerCode,
        scopeKind: "global",
        enforcementState: "halted",
        keyId: recordKeyId(opts.publicKeyPem),
        ...(memoryHead ? { memoryHead } : {}),
      },
      opts.privateKeyPem,
    );
  if (!record.envelope) {
    record.envelope = envelope;
    writeIncidentRecord(opts.stateDir, record);
  }
  persistEnvelope(opts.stateDir, envelope);
  return already ? (hasAlarmOutbox(opts.stateDir, eventId) ? envelope : null) : envelope;
}

/** On open: halt exists, outbox and delivery do not — finish the same eventId. */
export function completeMemoryIntegrityIncident(opts: {
  stateDir: string;
  publicKeyPem: string;
  privateKeyPem: string;
  memoryHead?: { seq: number; lastHash: string };
  alarmWebhookUrl?: string;
}): AlarmEnvelope | null {
  if (!existsSync(join(opts.stateDir, "halted"))) return null;
  const existing = readIntegrityIdentity(opts.stateDir);
  return raiseMemoryIntegrityIncident({
    ...opts,
    reason: existing?.triggerCode ?? "memory-integrity-mismatch",
    now: existing?.observedAt,
  });
}
