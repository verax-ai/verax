import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID, sign, verify } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { canonical } from "@cedulon/core";
import {
  hasAlarmDelivery,
  hasAlarmOutbox,
  isAlarmEventId,
  writeAlarmOutbox,
  type AlarmEnvelope,
} from "./alarm-outbox.ts";
import { haltBody, isHaltSwitchFile, readHalt } from "./halt.ts";
import { assertRecordKeyTrust, resolveKeysDir } from "./keys.ts";
import { markHistoryUnavailable, type IntegrityReason } from "./memory-store.ts";

export const INCIDENT_BY = "verax:memory-integrity";
export const INCIDENT_RECORD = "incident.json";
export const INCIDENTS_DIR = "incidents";

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
  /** Resume closed the halt; the alarm is still waiting to be written or sent. */
  closedPendingDelivery?: boolean;
};

export function recordKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

function uuidFromHex(hex: string): string {
  const h = hex.toLowerCase().replace(/[^0-9a-f]/g, "").padEnd(32, "0").slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function uuidFromBytes(buf: Buffer): string {
  const b = Buffer.from(buf);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  return uuidFromHex(b.toString("hex"));
}

export type IncidentEventIdGenerators = {
  randomUUID: () => string;
  randomBytes: (size: number) => Buffer;
};

/**
 * randomUUID, then randomBytes, then a SHA-256 UUID of observedAt+trigger+record key.
 * Generators are a parameter so a failing producer can be injected; that is
 * dependency injection, not a product-code test hook. The last resort is
 * stable for the same inputs (a retry of one incident stays one id).
 */
export function incidentEventIdFrom(
  opts: {
    observedAt: number;
    triggerCode: string;
    publicKeyPem: string;
  },
  generators: IncidentEventIdGenerators,
): string {
  try {
    return generators.randomUUID();
  } catch {
    // RNG may refuse; keep going.
  }
  try {
    return uuidFromBytes(generators.randomBytes(16));
  } catch {
    // Same: fall through to a deterministic identity.
  }
  return lastResortIncidentId(opts, "");
}

const fallbackAlloc = { seq: 0 };

function lastResortIncidentId(
  opts: { observedAt: number; triggerCode: string; publicKeyPem: string },
  unique: string,
): string {
  try {
    const keyId = recordKeyId(opts.publicKeyPem);
    const material = unique
      ? `${opts.observedAt}\0${opts.triggerCode}\0${keyId}\0${unique}`
      : `${opts.observedAt}\0${opts.triggerCode}\0${keyId}`;
    return uuidFromHex(createHash("sha256").update(material, "utf8").digest("hex"));
  } catch {
    const material = unique ? `${opts.observedAt}\0${unique}` : String(opts.observedAt);
    return uuidFromHex(createHash("sha256").update(material, "utf8").digest("hex"));
  }
}

/** Production path: the same cascade; last resort mixes pid, a counter, and extra bytes. */
export function allocateIncidentEventId(opts: {
  observedAt: number;
  triggerCode: string;
  publicKeyPem: string;
}): string {
  try {
    return randomUUID();
  } catch {
    // RNG may refuse; keep going.
  }
  try {
    return uuidFromBytes(randomBytes(16));
  } catch {
    // Same: fall through to a unique last resort.
  }
  fallbackAlloc.seq += 1;
  let entropy = "";
  try {
    entropy = randomBytes(8).toString("hex");
  } catch {
    // Extra bytes are optional; pid + counter still separate two allocations.
  }
  return lastResortIncidentId(opts, `${process.pid}\0${fallbackAlloc.seq}\0${entropy}`);
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

function incidentEventPath(stateDir: string, eventId: string): string {
  if (!isAlarmEventId(eventId)) throw new Error("incident-event-id-invalid");
  const dir = resolve(join(stateDir, INCIDENTS_DIR));
  const leaf = `${eventId}.json`;
  const path = resolve(dir, leaf);
  const rel = relative(dir, path);
  if (rel === "" || isAbsolute(rel) || rel.startsWith("..") || rel.split(sep).includes("..")) {
    throw new Error("incident-path-escape");
  }
  if (path !== join(dir, leaf)) throw new Error("incident-path-escape");
  return path;
}

function legacyIncidentPath(stateDir: string): string {
  return join(stateDir, INCIDENT_RECORD);
}

function parseStoredIncident(raw: string): StoredIncident | null {
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
      const payload = row.envelope.payload;
      if (
        payload &&
        typeof payload === "object" &&
        payload.eventId === row.eventId &&
        typeof payload.triggerCode === "string" &&
        isIntegrityReason(payload.triggerCode)
      ) {
        stored.envelope = row.envelope;
      }
    }
    if (row.closedPendingDelivery === true) stored.closedPendingDelivery = true;
    return stored;
  } catch {
    return null;
  }
}

function readIncidentFromPath(path: string): StoredIncident | null {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  return parseStoredIncident(raw);
}

function legacyMigrationComplete(stateDir: string, legacy: StoredIncident): boolean {
  try {
    const dest = incidentEventPath(stateDir, legacy.eventId);
    if (!existsSync(dest) || !statSync(dest).isFile()) return false;
    const stored = readIncidentFromPath(dest);
    return stored !== null && stored.eventId === legacy.eventId;
  } catch {
    return false;
  }
}

function migrateLegacyIncident(stateDir: string): void {
  const legacy = readIncidentFromPath(legacyIncidentPath(stateDir));
  if (!legacy) return;
  if (legacyMigrationComplete(stateDir, legacy)) return;
  let dest: string;
  try {
    dest = incidentEventPath(stateDir, legacy.eventId);
  } catch {
    return;
  }
  try {
    if (existsSync(dest) && !statSync(dest).isFile()) {
      process.stderr.write("verax: incident: legacy migrate target is not a file\n");
      return;
    }
    writeJsonDurable(dest, legacy);
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
  }
}

function listIncidentRecords(stateDir: string): StoredIncident[] {
  migrateLegacyIncident(stateDir);
  const byId = new Map<string, StoredIncident>();
  const dir = join(stateDir, INCIDENTS_DIR);
  try {
    if (existsSync(dir) && statSync(dir).isDirectory()) {
      for (const name of readdirSync(dir)) {
        if (!name.endsWith(".json")) continue;
        const path = join(dir, name);
        try {
          if (!statSync(path).isFile()) continue;
        } catch {
          continue;
        }
        const stored = readIncidentFromPath(path);
        if (stored) byId.set(stored.eventId, stored);
      }
    }
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
  }
  const legacy = readIncidentFromPath(legacyIncidentPath(stateDir));
  if (legacy) {
    const existing = byId.get(legacy.eventId);
    if (!existing) byId.set(legacy.eventId, legacy);
    else if (legacy.closedPendingDelivery && !existing.closedPendingDelivery) {
      byId.set(legacy.eventId, { ...existing, closedPendingDelivery: true });
    }
  }
  return [...byId.values()];
}

function writeIncidentRecord(stateDir: string, record: StoredIncident): void {
  writeJsonDurable(incidentEventPath(stateDir, record.eventId), record);
  try {
    const legacyPath = legacyIncidentPath(stateDir);
    const existing = readIncidentFromPath(legacyPath);
    if (existing && existing.eventId !== record.eventId && !legacyMigrationComplete(stateDir, existing)) {
      process.stderr.write("verax: incident: legacy record retained\n");
      return;
    }
    writeJsonDurable(legacyPath, record);
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
  }
}

function tryWriteIncidentRecord(stateDir: string, record: StoredIncident): boolean {
  try {
    writeIncidentRecord(stateDir, record);
    return true;
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
    return false;
  }
}

function tryRemoveIncidentRecord(stateDir: string, eventId: string): void {
  try {
    rmSync(incidentEventPath(stateDir, eventId), { force: true });
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
  }
  const legacy = readIncidentFromPath(legacyIncidentPath(stateDir));
  if (legacy && legacy.eventId === eventId) {
    try {
      rmSync(legacyIncidentPath(stateDir), { force: true });
    } catch (err) {
      process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
    }
  }
}

function isUsableStoredEnvelope(envelope: AlarmEnvelope, eventId: string, publicKeyPem: string): boolean {
  const payload = envelope.payload;
  if (!payload || typeof payload !== "object") return false;
  if (payload.eventId !== eventId) return false;
  if (typeof payload.triggerCode !== "string" || !isIntegrityReason(payload.triggerCode)) return false;
  if (typeof envelope.sig !== "string" || envelope.sig === "") return false;
  try {
    return verify(
      null,
      Buffer.from(canonical(payload), "utf8"),
      createPublicKey(publicKeyPem),
      Buffer.from(envelope.sig, "base64"),
    );
  } catch {
    return false;
  }
}

function usableEnvelope(
  envelope: AlarmEnvelope | undefined,
  eventId: string,
  publicKeyPem: string,
): AlarmEnvelope | undefined {
  if (!envelope) return undefined;
  if (isUsableStoredEnvelope(envelope, eventId, publicKeyPem)) return envelope;
  process.stderr.write("verax: incident: stored envelope rejected\n");
  return undefined;
}

function incidentPayload(opts: {
  eventId: string;
  observedAt: number;
  triggerCode: string;
  publicKeyPem: string;
  memoryHead?: { seq: number; lastHash: string };
}): IncidentPayload {
  return {
    v: 1,
    purpose: "verax.incident.v1",
    eventId: opts.eventId,
    observedAt: opts.observedAt,
    triggerCode: opts.triggerCode,
    scopeKind: "global",
    enforcementState: "halted",
    keyId: recordKeyId(opts.publicKeyPem),
    ...(opts.memoryHead ? { memoryHead: opts.memoryHead } : {}),
  };
}

function tryLoadRecordKeys(
  stateDir: string,
  keysDir?: string | null,
): { publicKeyPem: string; privateKeyPem: string } | null {
  const resolved = resolveKeysDir(stateDir, keysDir ?? process.env.VERAX_KEYS_DIR);
  try {
    const recordSigner = {
      publicKeyPem: readFileSync(join(resolved, "record.public.pem"), "utf8"),
      privateKeyPem: readFileSync(join(resolved, "record.private.pem"), "utf8"),
    };
    const publicKeyPem = assertRecordKeyTrust({
      stateDir,
      keysDir: resolved,
      recordSigner,
    });
    return { publicKeyPem, privateKeyPem: recordSigner.privateKeyPem };
  } catch {
    return null;
  }
}

function safeHasAlarmDelivery(stateDir: string, eventId: string): boolean {
  try {
    return hasAlarmDelivery(stateDir, eventId);
  } catch (err) {
    process.stderr.write(`verax: alarm-history: ${oneLine(err)}\n`);
    return false;
  }
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

function recordForEvent(stateDir: string, eventId: string): StoredIncident | null {
  return listIncidentRecords(stateDir).find((row) => row.eventId === eventId) ?? null;
}

function readIntegrityIdentity(stateDir: string): StoredIncident | null {
  const halt = readHalt(stateDir);
  if (!halt.halted) return null;
  const history = readHistoryIdentity(stateDir);
  if (history) {
    const record = recordForEvent(stateDir, history.eventId);
    if (record) return record;
    return history;
  }
  // C1: switch with no history line — the on-disk record is this halt.
  // An operator halt has `since` and does not own a leftover record.
  const records = listIncidentRecords(stateDir).filter((row) => !row.closedPendingDelivery);
  const record = records[0] ?? null;
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

function signedEnvelope(
  opts: {
    publicKeyPem: string;
    privateKeyPem: string;
    memoryHead?: { seq: number; lastHash: string };
  },
  stored: StoredIncident,
): AlarmEnvelope {
  return (
    usableEnvelope(stored.envelope, stored.eventId, opts.publicKeyPem) ??
    signIncident(
      incidentPayload({
        eventId: stored.eventId,
        observedAt: stored.observedAt,
        triggerCode: stored.triggerCode,
        publicKeyPem: opts.publicKeyPem,
        memoryHead: stored.memoryHead ?? opts.memoryHead,
      }),
      opts.privateKeyPem,
    )
  );
}

function finishClosedPending(
  opts: {
    stateDir: string;
    publicKeyPem: string;
    privateKeyPem: string;
    memoryHead?: { seq: number; lastHash: string };
    alarmWebhookUrl?: string;
  },
  stored: StoredIncident,
): AlarmEnvelope | null {
  if (safeHasAlarmDelivery(opts.stateDir, stored.eventId)) {
    tryRemoveIncidentRecord(opts.stateDir, stored.eventId);
    return null;
  }
  if (!opts.alarmWebhookUrl) return null;
  if (hasAlarmOutbox(opts.stateDir, stored.eventId)) return null;
  const envelope = signedEnvelope(opts, stored);
  persistEnvelope(opts.stateDir, envelope);
  if (hasAlarmOutbox(opts.stateDir, stored.eventId) || safeHasAlarmDelivery(opts.stateDir, stored.eventId)) {
    tryRemoveIncidentRecord(opts.stateDir, stored.eventId);
  }
  return hasAlarmOutbox(opts.stateDir, stored.eventId) ? envelope : null;
}

function tryFinishClosedPending(
  opts: {
    stateDir: string;
    publicKeyPem: string;
    privateKeyPem: string;
    memoryHead?: { seq: number; lastHash: string };
    alarmWebhookUrl?: string;
  },
  stored: StoredIncident,
): AlarmEnvelope | null {
  try {
    return finishClosedPending(opts, stored);
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
    return null;
  }
}

function finishAllClosedPending(opts: {
  stateDir: string;
  publicKeyPem: string;
  privateKeyPem: string;
  memoryHead?: { seq: number; lastHash: string };
  alarmWebhookUrl?: string;
}): AlarmEnvelope | null {
  let last: AlarmEnvelope | null = null;
  for (const stored of listIncidentRecords(opts.stateDir)) {
    if (!stored.closedPendingDelivery) continue;
    const envelope = tryFinishClosedPending(opts, stored);
    if (envelope) last = envelope;
  }
  return last;
}

/** Resume: same verify/re-sign path; pending marker is atomic or resume does not finish. */
export function closeIncidentsOnResume(stateDir: string, keysDir?: string | null): void {
  migrateLegacyIncident(stateDir);
  const keys = tryLoadRecordKeys(stateDir, keysDir);
  const records = listIncidentRecords(stateDir);
  const history = readHistoryIdentity(stateDir);
  if (history && !records.some((row) => row.eventId === history.eventId)) records.push(history);
  for (const stored of records) {
    if (safeHasAlarmDelivery(stateDir, stored.eventId)) {
      tryRemoveIncidentRecord(stateDir, stored.eventId);
      continue;
    }
    let envelope: AlarmEnvelope | undefined;
    if (keys) {
      envelope = signedEnvelope(keys, stored);
      persistEnvelope(stateDir, envelope);
    } else if (stored.envelope && typeof stored.envelope === "object") {
      process.stderr.write("verax: incident: resume skipped unverified envelope\n");
    }
    if (hasAlarmOutbox(stateDir, stored.eventId) || safeHasAlarmDelivery(stateDir, stored.eventId)) {
      tryRemoveIncidentRecord(stateDir, stored.eventId);
      continue;
    }
    const pending: StoredIncident = {
      ...stored,
      closedPendingDelivery: true,
      ...(envelope ? { envelope } : {}),
    };
    writeIncidentRecord(stateDir, pending);
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
  let eventId = "";
  let observedAt = opts.now ?? Date.now();
  let triggerCode: IntegrityReason = opts.reason;
  let memoryHead = opts.memoryHead;
  let identity: StoredIncident | null = null;
  let wrote = false;
  let abort = false;
  let already = false;

  try {
    already = isHaltSwitchFile(opts.stateDir);
    eventId = allocateIncidentEventId({
      observedAt,
      triggerCode,
      publicKeyPem: opts.publicKeyPem,
    });
    migrateLegacyIncident(opts.stateDir);
    finishAllClosedPending(opts);
    const leftoverOpen = !already
      ? (listIncidentRecords(opts.stateDir).find((row) => !row.closedPendingDelivery) ?? null)
      : null;
    identity = already ? readIntegrityIdentity(opts.stateDir) : leftoverOpen;
    if (already && !identity) {
      abort = true;
      return null;
    }
    if (identity) {
      eventId = identity.eventId;
      observedAt = identity.observedAt;
      triggerCode = identity.triggerCode;
      memoryHead = identity.memoryHead ?? memoryHead;
    }
    const kept = usableEnvelope(identity?.envelope, eventId, opts.publicKeyPem);
    const record: StoredIncident = {
      eventId,
      triggerCode,
      observedAt,
      ...(memoryHead ? { memoryHead } : {}),
      ...(kept ? { envelope: kept } : {}),
    };
    wrote = tryWriteIncidentRecord(opts.stateDir, record);
    identity = { ...record };
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
  } finally {
    if (!already && !abort) {
      try {
        haltBody(opts.stateDir, INCIDENT_BY, "integrity", observedAt, undefined, {
          ...(eventId !== "" ? { eventId } : {}),
          triggerCode,
          ...(memoryHead ? { memoryHead } : {}),
        });
      } catch (err) {
        process.stderr.write(`verax: halt: ${oneLine(err)}\n`);
        if (!isHaltSwitchFile(opts.stateDir)) {
          markHistoryUnavailable(opts.stateDir);
        }
      }
    }
  }
  if (abort) return null;
  if (eventId === "") return null;
  if (!wrote && identity) tryWriteIncidentRecord(opts.stateDir, identity);

  try {
    if (!opts.alarmWebhookUrl) return null;
    if (safeHasAlarmDelivery(opts.stateDir, eventId)) return null;
    if (already && hasAlarmOutbox(opts.stateDir, eventId)) return null;

    const envelope =
      usableEnvelope(identity?.envelope, eventId, opts.publicKeyPem) ??
      signIncident(
        incidentPayload({ eventId, observedAt, triggerCode, publicKeyPem: opts.publicKeyPem, memoryHead }),
        opts.privateKeyPem,
      );
    if (identity && !identity.envelope) {
      identity.envelope = envelope;
      tryWriteIncidentRecord(opts.stateDir, identity);
    }
    persistEnvelope(opts.stateDir, envelope);
    return already ? (hasAlarmOutbox(opts.stateDir, eventId) ? envelope : null) : envelope;
  } catch (err) {
    process.stderr.write(`verax: incident: ${oneLine(err)}\n`);
    return null;
  }
}

/** On open: finish a missing halt, a missing outbox, or a resume-pending delivery. Same eventId. */
export function completeMemoryIntegrityIncident(opts: {
  stateDir: string;
  publicKeyPem: string;
  privateKeyPem: string;
  memoryHead?: { seq: number; lastHash: string };
  alarmWebhookUrl?: string;
}): AlarmEnvelope | null {
  migrateLegacyIncident(opts.stateDir);
  const pending = finishAllClosedPending(opts);
  if (!isHaltSwitchFile(opts.stateDir)) {
    const leftover = listIncidentRecords(opts.stateDir).find((row) => !row.closedPendingDelivery);
    if (leftover) {
      return raiseMemoryIntegrityIncident({
        ...opts,
        reason: leftover.triggerCode,
        now: leftover.observedAt,
      });
    }
    return pending;
  }
  const existing = readIntegrityIdentity(opts.stateDir);
  return (
    raiseMemoryIntegrityIncident({
      ...opts,
      reason: existing?.triggerCode ?? "memory-integrity-mismatch",
      now: existing?.observedAt,
    }) ?? pending
  );
}
