import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { canonical } from "@cedulon/core";
import { tenantKey, type Principal, type ToolCall, type ToolResult } from "@verax-ai/proxy";

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError,
  };
}

function resolveMemoryPath(stateDir: string, id: string, principal: Principal): string | null {
  if (!ID_RE.test(id)) return null;
  const memoryDir = resolve(stateDir, "tenants", tenantKey(principal), "memory");
  const path = resolve(memoryDir, `${id}.json`);
  const prefix = memoryDir.endsWith(sep) ? memoryDir : `${memoryDir}${sep}`;
  if (!path.startsWith(prefix)) return null;
  return path;
}

/** True when `id` exists under a different tenant. Does not read legacy `memory/`. */
export function memoryBelongsToOtherTenant(stateDir: string, id: string, selfKey: string): boolean {
  if (!ID_RE.test(id)) return false;
  const tenantsRoot = resolve(stateDir, "tenants");
  if (!existsSync(tenantsRoot)) return false;
  let names: string[];
  try {
    names = readdirSync(tenantsRoot);
  } catch {
    return false;
  }
  for (const name of names) {
    if (name === selfKey) continue;
    const path = resolve(tenantsRoot, name, "memory", `${id}.json`);
    const prefix = resolve(tenantsRoot, name, "memory");
    const guarded = prefix.endsWith(sep) ? prefix : `${prefix}${sep}`;
    if (!path.startsWith(guarded)) continue;
    if (existsSync(path)) return true;
  }
  return false;
}

export async function readMemoryMeta(
  stateDir: string,
  id: string,
  principal?: Principal,
): Promise<{ versionHash: string; validFromMs: number; validUntilMs: number } | null> {
  if (!principal) return null;
  const path = resolveMemoryPath(stateDir, id, principal);
  if (path === null) return null;
  try {
    const item = JSON.parse(await readFile(path, "utf8")) as {
      id: string;
      body: unknown;
      validFromMs?: number;
      validUntilMs?: number;
      versionHash?: string;
    };
    const validFromMs = typeof item.validFromMs === "number" ? item.validFromMs : 0;
    const validUntilMs = typeof item.validUntilMs === "number" ? item.validUntilMs : 0;
    const versionHash =
      typeof item.versionHash === "string"
        ? item.versionHash
        : sha256Canonical({ id: item.id, body: item.body, validFromMs, validUntilMs });
    return { versionHash, validFromMs, validUntilMs };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

export async function memoryGet(
  call: ToolCall,
  stateDir: string,
  now: () => number,
  principal: Principal,
  ref?: string,
): Promise<ToolResult> {
  const id = call.arguments.id;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  const path = resolveMemoryPath(stateDir, id, principal);
  if (path === null) {
    return jsonResult({ error: "id-invalid" }, true);
  }
  try {
    const item = JSON.parse(await readFile(path, "utf8")) as {
      id: string;
      body: unknown;
      validFromMs?: number;
      validUntilMs?: number;
    };
    if (typeof item.validFromMs === "number" && item.validFromMs > now()) {
      return jsonResult({ notYetValid: true, id: item.id, validFromMs: item.validFromMs });
    }
    if (typeof item.validUntilMs === "number" && item.validUntilMs < now()) {
      return jsonResult({ stale: true, id: item.id, validUntilMs: item.validUntilMs });
    }
    return jsonResult(item);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      const shown = typeof ref === "string" && ref !== "" ? ref : id;
      return {
        content: [{ type: "text", text: `denied:tenant-mismatch:${shown}` }],
        isError: true,
      };
    }
    throw err;
  }
}

export async function memoryPut(call: ToolCall, stateDir: string, principal: Principal): Promise<ToolResult> {
  const id = call.arguments.id;
  const body = call.arguments.body;
  const source = call.arguments.source;
  const validFromMs = call.arguments.validFromMs;
  const validUntilMs = call.arguments.validUntilMs;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  const path = resolveMemoryPath(stateDir, id, principal);
  if (path === null) {
    return jsonResult({ error: "id-invalid" }, true);
  }
  if (source === null || typeof source !== "object" || Array.isArray(source)) {
    return jsonResult({ error: "source-required" }, true);
  }
  if (typeof validUntilMs !== "number") {
    return jsonResult({ error: "validUntilMs-required" }, true);
  }
  const fromMs = typeof validFromMs === "number" ? validFromMs : 0;
  const versionHash = sha256Canonical({ id, body, validFromMs: fromMs, validUntilMs });
  const rec = {
    id,
    body,
    source,
    validFromMs: fromMs,
    validUntilMs,
    versionHash,
  };
  const dir = resolve(stateDir, "tenants", tenantKey(principal), "memory");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(rec)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return jsonResult({ ok: true, id, versionHash });
}
