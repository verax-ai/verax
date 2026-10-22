import { createHash, createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { canonical } from "@cedulon/core";
import { writeAlarmOutbox, type AlarmEnvelope } from "./alarm-outbox.ts";
import { haltBody } from "./halt.ts";
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
  haltBody(opts.stateDir, INCIDENT_BY, "integrity", opts.now);
  if (already) return null;
  if (!opts.alarmWebhookUrl) return null;
  const payload: IncidentPayload = {
    v: 1,
    purpose: "verax.incident.v1",
    eventId: randomUUID(),
    observedAt: opts.now ?? Date.now(),
    triggerCode: opts.reason,
    scopeKind: "global",
    enforcementState: "halted",
    keyId: recordKeyId(opts.publicKeyPem),
    ...(opts.memoryHead ? { memoryHead: opts.memoryHead } : {}),
  };
  const envelope = signIncident(payload, opts.privateKeyPem);
  writeAlarmOutbox(opts.stateDir, envelope);
  return envelope;
}
