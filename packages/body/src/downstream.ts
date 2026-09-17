import { Readable } from "node:stream";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Principal, ToolCall, ToolResult } from "@verax-ai/proxy";

export type DownstreamToolFn = (
  call: ToolCall,
  principal: Principal,
  ref?: string,
) => Promise<ToolResult>;

export type DownstreamSpec = {
  prefix: string;
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
};

export type DownstreamTool = {
  name: string;
  fn: DownstreamToolFn;
};

export type DownstreamSession = {
  prefix: string;
  tools: readonly DownstreamTool[];
  close(): Promise<void>;
};

const PREFIX_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
const CHILD_TOOL_RE = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
/** Prefixed name a caller may put on extraTools: `prefix.childName`. */
const EXTRA_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}\.[A-Za-z][A-Za-z0-9._-]{0,63}$/;

export class DownstreamCallError extends Error {
  readonly prefix: string;
  readonly tool: string;
  constructor(prefix: string, tool: string, cause?: unknown) {
    const detail = cause instanceof Error ? cause.message : "call-failed";
    super(`downstream-call-failed:${prefix}.${tool}:${detail}`);
    this.name = "DownstreamCallError";
    this.prefix = prefix;
    this.tool = tool;
    if (cause !== undefined) this.cause = cause;
  }
}

export function prefixedName(prefix: string, childName: string): string {
  return `${prefix}.${childName}`;
}

export function extraToolNameOk(name: string): boolean {
  return EXTRA_NAME_RE.test(name);
}

export function parseDownstreamJson(raw: string): DownstreamSpec {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("downstream-json-invalid");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("downstream-json-not-object");
  }
  const rec = parsed as Record<string, unknown>;
  if (typeof rec.prefix !== "string" || !PREFIX_RE.test(rec.prefix)) {
    throw new Error("downstream-prefix-invalid");
  }
  if (typeof rec.command !== "string" || rec.command.trim() === "") {
    throw new Error("downstream-command-invalid");
  }
  const spec: DownstreamSpec = { prefix: rec.prefix, command: rec.command };
  if (rec.args !== undefined) {
    if (!Array.isArray(rec.args) || rec.args.some((a) => typeof a !== "string")) {
      throw new Error("downstream-args-invalid");
    }
    spec.args = rec.args as string[];
  }
  if (rec.cwd !== undefined) {
    if (typeof rec.cwd !== "string" || rec.cwd === "") {
      throw new Error("downstream-cwd-invalid");
    }
    spec.cwd = rec.cwd;
  }
  if (rec.env !== undefined) {
    if (rec.env === null || typeof rec.env !== "object" || Array.isArray(rec.env)) {
      throw new Error("downstream-env-invalid");
    }
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(rec.env as Record<string, unknown>)) {
      if (typeof v !== "string") throw new Error("downstream-env-invalid");
      env[k] = v;
    }
    spec.env = env;
  }
  if (rec.timeoutMs !== undefined) {
    if (typeof rec.timeoutMs !== "number" || !Number.isInteger(rec.timeoutMs) || rec.timeoutMs <= 0) {
      throw new Error("downstream-timeout-invalid");
    }
    spec.timeoutMs = rec.timeoutMs;
  }
  return spec;
}

// The SDK result is a union (current shape with an index signature, or the
// legacy { toolResult } shape), so it is narrowed here rather than trusted.
function asTextResult(raw: unknown): ToolResult {
  const rec: Record<string, unknown> =
    raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const content: { type: "text"; text: string }[] = [];
  const items: unknown[] = Array.isArray(rec.content) ? rec.content : [];
  for (const item of items) {
    if (
      item !== null &&
      typeof item === "object" &&
      (item as { type?: unknown }).type === "text" &&
      typeof (item as { text?: unknown }).text === "string"
    ) {
      content.push({ type: "text", text: (item as { text: string }).text });
      continue;
    }
    content.push({ type: "text", text: JSON.stringify(item) });
  }
  return {
    content: content.length > 0 ? content : [{ type: "text", text: "" }],
    isError: rec.isError === true,
  };
}

async function shut(client: Client, transport: StdioClientTransport): Promise<void> {
  await client.close().catch(() => undefined);
  await transport.close().catch(() => undefined);
}

export async function openDownstream(spec: DownstreamSpec): Promise<DownstreamSession> {
  if (!PREFIX_RE.test(spec.prefix)) {
    throw new Error("downstream-prefix-invalid");
  }
  if (spec.command.trim() === "") {
    throw new Error("downstream-command-invalid");
  }
  const timeoutMs = spec.timeoutMs ?? 10_000;
  // Safe inherit + operator overlay. Not process.env: that would copy
  // VERAX_* tokens the body already holds.
  const env = { ...getDefaultEnvironment(), ...(spec.env ?? {}) };
  const transport = new StdioClientTransport({
    command: spec.command,
    args: spec.args,
    cwd: spec.cwd,
    env,
    stderr: "pipe",
  });
  // The SDK types the pipe as Stream; only a Readable can be drained.
  const stderr = transport.stderr;
  if (stderr instanceof Readable) stderr.resume();
  const client = new Client({ name: "verax-downstream", version: "0.0.0" });
  let listed: Awaited<ReturnType<Client["listTools"]>>;
  try {
    await client.connect(transport);
    listed = await client.listTools();
  } catch (err) {
    await shut(client, transport);
    throw err;
  }
  const tools: DownstreamTool[] = [];
  const seen = new Set<string>();
  for (const tool of listed.tools) {
    if (!CHILD_TOOL_RE.test(tool.name)) {
      await shut(client, transport);
      throw new Error(`downstream-child-name-invalid:${tool.name}`);
    }
    const name = prefixedName(spec.prefix, tool.name);
    if (seen.has(name)) {
      await shut(client, transport);
      throw new Error(`downstream-name-collision:${name}`);
    }
    seen.add(name);
    const childName = tool.name;
    tools.push({
      name,
      fn: async (call) => {
        let raw: Awaited<ReturnType<Client["callTool"]>>;
        try {
          // Mutation check: stub this call and the allow test expecting
          // "pong":true from the child goes red.
          raw = await client.callTool(
            { name: childName, arguments: call.arguments },
            undefined,
            { timeout: timeoutMs },
          );
        } catch (err) {
          throw new DownstreamCallError(spec.prefix, childName, err);
        }
        const result = asTextResult(raw);
        if (result.isError) {
          throw new DownstreamCallError(spec.prefix, childName, textOf(result) || "isError");
        }
        return result;
      },
    });
  }
  let closed = false;
  return {
    prefix: spec.prefix,
    tools,
    async close() {
      if (closed) return;
      closed = true;
      await shut(client, transport);
    },
  };
}

function textOf(result: ToolResult): string {
  return result.content.map((c) => c.text).join("");
}
