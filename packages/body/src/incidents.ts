import { createHash, createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { canonical } from "@cedulon/core";
import {
  hasAlarmDelivery,
  hasAlarmOutbox,
  writeAlarmOutbox,
  type AlarmEnvelope,
} from "./alarm-outbox.ts";
import { haltBody, readHalt } from "./halt.ts";
import type { IntegrityReason } from "./memory-store.ts";

export const INCIDENT_BY = "verax:memory-integrity";

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

export function recordKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

export function signIncident(payload: IncidentPayload, privateKeyPem: string): AlarmEnvelope {
  const sig = sign(null, Buffer.from(canonical(payload), "utf8"), createPrivateKey(privateKeyPem)).toString("base64");
  return { payload, sig };
}

function readIntegrityHalt(stateDir: string): {
  eventId: string;
  triggerCode: string;
  atMs: number;
  memoryHead?: { seq: number; lastHash: string };
} | null {
  const halt = readHalt(stateDir);
  if (!halt.halted || halt.since?.via !== "integrity" || typeof halt.since.eventId !== "string") return null;
  return {
    eventId: halt.since.eventId,
    triggerCode: halt.since.triggerCode ?? "memory-integrity-mismatch",
    atMs: halt.since.atMs,
    ...(halt.since.memoryHead ? { memoryHead: halt.since.memoryHead } : {}),
  };
}

function persistEnvelope(stateDir: string, envelope: AlarmEnvelope): void {
  try {
    writeAlarmOutbox(stateDir, envelope);
  } catch {
    // Halt already names this eventId. Open completes the outbox.
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
  const existing = already ? readIntegrityHalt(opts.stateDir) : null;
  if (already && !existing) return null;
  const eventId = existing?.eventId ?? randomUUID();
  const observedAt = existing?.atMs ?? opts.now ?? Date.now();
  const triggerCode = existing?.triggerCode ?? opts.reason;
  const memoryHead = existing?.memoryHead ?? opts.memoryHead;

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

  const payload: IncidentPayload = {
    v: 1,
    purpose: "verax.incident.v1",
    eventId,
    observedAt,
    triggerCode,
    scopeKind: "global",
    enforcementState: "halted",
    keyId: recordKeyId(opts.publicKeyPem),
    ...(memoryHead ? { memoryHead } : {}),
  };
  const envelope = signIncident(payload, opts.privateKeyPem);
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
  const existing = readIntegrityHalt(opts.stateDir);
  if (!existing) return null;
  return raiseMemoryIntegrityIncident({
    ...opts,
    reason: existing.triggerCode as IntegrityReason,
    now: existing.atMs,
  });
}
