import { existsSync } from "node:fs";
import { tenantKey, type Principal, type ToolCall, type ToolResult } from "@verax-ai/proxy";
import { memoryQuotaBytes } from "../config.ts";
import { loadOrCreateSigners } from "../keys.ts";
import {
  memoryStoreFor,
  openMemoryStoreSync,
  type IntegrityReason,
  type MemoryStore,
} from "../memory-store.ts";

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError,
  };
}

function integrityResult(reason: IntegrityReason, id: string): ToolResult {
  return jsonResult({ error: reason, id }, true);
}

function storeFor(stateDir: string): MemoryStore {
  try {
    return memoryStoreFor(stateDir);
  } catch {
    const keys = loadOrCreateSigners(stateDir);
    return openMemoryStoreSync({
      stateDir,
      publicKeyPem: keys.recordSigner.publicKeyPem,
      privateKeyPem: keys.recordSigner.privateKeyPem,
    });
  }
}

export function memoryHistoryUnavailable(stateDir: string): boolean {
  return storeFor(stateDir).historyUnavailable;
}

/** True when `id` exists under a different tenant. Does not read legacy `memory/`. */
export function memoryBelongsToOtherTenant(stateDir: string, id: string, selfKey: string): boolean {
  if (!ID_RE.test(id)) return false;
  if (!existsSync(stateDir)) return false;
  return storeFor(stateDir).idVisibleForOtherTenant(id, selfKey);
}

/** True when this tenant already has `id` under its own memory path or commit. */
export function memoryExistsForTenant(stateDir: string, id: string, principal: Principal): boolean {
  if (!ID_RE.test(id)) return false;
  return storeFor(stateDir).idHeldByTenant(id, tenantKey(principal));
}

export async function readMemoryMeta(
  stateDir: string,
  id: string,
  principal?: Principal,
): Promise<{ versionHash: string; validFromMs: number; validUntilMs: number } | null> {
  if (!principal) return null;
  if (typeof id !== "string" || !ID_RE.test(id)) return null;
  const got = storeFor(stateDir).verifiedRead(tenantKey(principal), id);
  if (got.kind !== "ok") return null;
  return {
    versionHash: got.versionHash,
    validFromMs: got.object.validFromMs,
    validUntilMs: got.object.validUntilMs,
  };
}

export async function memoryGet(
  call: ToolCall,
  stateDir: string,
  now: () => number,
  principal: Principal,
): Promise<ToolResult> {
  const id = call.arguments.id;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  if (!ID_RE.test(id)) {
    return jsonResult({ error: "id-invalid" }, true);
  }
  const got = storeFor(stateDir).verifiedRead(tenantKey(principal), id);
  if (got.kind === "integrity") return integrityResult(got.reason, id);
  if (got.kind === "not-found") return jsonResult({ error: "not-found", id }, true);
  const item = got.object;
  if (item.validFromMs > now()) {
    return jsonResult({ notYetValid: true, id: item.id, validFromMs: item.validFromMs });
  }
  if (item.validUntilMs < now()) {
    return jsonResult({ stale: true, id: item.id, validUntilMs: item.validUntilMs });
  }
  return jsonResult(item);
}

export async function memoryPut(
  call: ToolCall,
  stateDir: string,
  principal: Principal,
  putRef = "",
): Promise<ToolResult> {
  const id = call.arguments.id;
  const body = call.arguments.body;
  const source = call.arguments.source;
  const validFromMs = call.arguments.validFromMs;
  const validUntilMs = call.arguments.validUntilMs;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  if (!ID_RE.test(id)) {
    return jsonResult({ error: "id-invalid" }, true);
  }
  if (source === null || typeof source !== "object" || Array.isArray(source)) {
    return jsonResult({ error: "source-required" }, true);
  }
  if (typeof validUntilMs !== "number") {
    return jsonResult({ error: "validUntilMs-required" }, true);
  }
  const fromMs = typeof validFromMs === "number" ? validFromMs : 0;
  const store = storeFor(stateDir);
  const written = await store.put({
    tenantKey: tenantKey(principal),
    id,
    body,
    source,
    validFromMs: fromMs,
    validUntilMs,
    putRef,
    quotaBytes: memoryQuotaBytes(),
  });
  if (!written.ok) {
    if (written.error === "memory-integrity-history-unavailable") {
      return integrityResult(written.error, id);
    }
    return jsonResult({ error: written.error }, true);
  }
  return jsonResult({ ok: true, id: written.id, revision: written.revision, versionHash: written.versionHash });
}
