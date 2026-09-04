import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolCall, ToolResult } from "@verax-ai/proxy";

function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError,
  };
}

export async function memoryGet(call: ToolCall, stateDir: string, now: () => number): Promise<ToolResult> {
  const id = call.arguments.id;
  if (typeof id !== "string" || id === "") {
    return jsonResult({ error: "id-required" }, true);
  }
  const path = join(stateDir, "memory", `${id}.json`);
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
  const dir = join(stateDir, "memory");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(join(dir, `${id}.json`), `${JSON.stringify(rec)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return jsonResult({ ok: true, id });
}
