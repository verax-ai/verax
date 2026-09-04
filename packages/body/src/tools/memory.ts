import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import type { ToolCall, ToolResult } from "@verax-ai/proxy";

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError,
  };
}

function resolveMemoryPath(stateDir: string, id: string): string | null {
  if (!ID_RE.test(id)) return null;
  const memoryDir = resolve(stateDir, "memory");
  const path = resolve(memoryDir, `${id}.json`);
  const prefix = memoryDir.endsWith(sep) ? memoryDir : `${memoryDir}${sep}`;
  if (!path.startsWith(prefix)) return null;
  return path;
}

export async function memoryGet(call: ToolCall, stateDir: string, now: () => number): Promise<ToolResult> {
  const id = call.arguments.id;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  const path = resolveMemoryPath(stateDir, id);
  if (path === null) {
    return jsonResult({ error: "id-invalid" }, true);
  }
  try {
    const item = JSON.parse(await readFile(path, "utf8")) as {
      id: string;
      body: unknown;
      validUntilMs?: number;
    };
    if (typeof item.validUntilMs === "number" && item.validUntilMs < now()) {
      return jsonResult({ stale: true, id: item.id, validUntilMs: item.validUntilMs });
    }
    return jsonResult(item);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return jsonResult({ error: "not-found", id }, true);
    }
    throw err;
  }
}

export async function memoryPut(call: ToolCall, stateDir: string): Promise<ToolResult> {
  const id = call.arguments.id;
  const body = call.arguments.body;
  const source = call.arguments.source;
  const validFromMs = call.arguments.validFromMs;
  const validUntilMs = call.arguments.validUntilMs;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  const path = resolveMemoryPath(stateDir, id);
  if (path === null) {
    return jsonResult({ error: "id-invalid" }, true);
  }
  if (source === null || typeof source !== "object" || Array.isArray(source)) {
    return jsonResult({ error: "source-required" }, true);
  }
  if (typeof validUntilMs !== "number") {
    return jsonResult({ error: "validUntilMs-required" }, true);
  }
  const rec = {
    id,
    body,
    source,
    validFromMs: typeof validFromMs === "number" ? validFromMs : 0,
    validUntilMs,
  };
  const dir = resolve(stateDir, "memory");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(rec)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return jsonResult({ ok: true, id });
}
