import { Readable } from "node:stream";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Principal, ToolCall, ToolResult } from "@verax-ai/proxy";

export type DownstreamToolFn = (
  call: ToolCall,
  principal: Principal,
  ref?: string,
) => Promise<ToolResult>;

/**
 * One child, reached one of two ways. `command` spawns it over stdio;
 * `url` speaks Streamable HTTP to one already running. Exactly one of the
 * two: a document naming both does not say which the operator meant, and a
 * document naming neither says nothing at all.
 */
export type DownstreamSpec = {
  prefix: string;
  /** stdio: the process to start. */
  command?: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  /** HTTP: the MCP endpoint of a server already running. */
  url?: string;
  /** HTTP: headers the operator sends to the child, such as its own bearer. */
  headers?: Record<string, string>;
  timeoutMs?: number;
  /**
   * stdio only. The operator wrote that this child runs as the same user
   * as the body and can read the body's signing keys. Required on stdio;
   * forbidden on HTTP.
   */
  trust?: "same-user";
};

export type DownstreamTool = {
  name: string;
  /** The child's own description, as `tools/list` gave it. */
  description?: string;
  /** The child's own input schema, republished unchanged. */
  inputSchema?: unknown;
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
// Sanity bound, not a capacity claim. A child that lists more than this is
// hostile or broken; the body is not a registry for thousands of names.
const MAX_CHILD_TOOLS = 256;
const MAX_TOOL_BYTES = 64 * 1024;

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

/**
 * The operator wrote `"trust": "same-user"` on a stdio child. Missing ack
 * refuses start. One rule, two call sites — do not duplicate the predicate.
 */
function assertStdioTrusted(spec: DownstreamSpec): void {
  if (spec.command !== undefined && spec.trust !== "same-user") {
    // The prefix is the operator's own name for the child and names WHICH entry
    // to fix in a document with several. Nothing else about the child goes in:
    // not the command, the arguments or the environment.
    throw new Error(`downstream-stdio-trust-required:${spec.prefix}`);
  }
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
  const cmdVar = rec.command !== undefined;
  const urlVar = rec.url !== undefined;
  if (cmdVar && urlVar) throw new Error("downstream-transport-ambiguous");
  if (!cmdVar && !urlVar) throw new Error("downstream-transport-missing");
  const spec: DownstreamSpec = { prefix: rec.prefix };
  if (cmdVar) {
    if (typeof rec.command !== "string" || rec.command.trim() === "") {
      throw new Error("downstream-command-invalid");
    }
    spec.command = rec.command;
  } else {
    if (typeof rec.url !== "string" || rec.url.trim() === "") {
      throw new Error("downstream-url-invalid");
    }
    let parsed: URL;
    try {
      parsed = new URL(rec.url);
    } catch {
      throw new Error("downstream-url-invalid");
    }
    // Only the two schemes the SDK transport speaks. A `file:` or `ftp:` URL
    // would be read as a fetch target by something later, so it is refused here.
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("downstream-url-invalid");
    }
    spec.url = rec.url;
    if (rec.headers !== undefined) {
      if (rec.headers === null || typeof rec.headers !== "object" || Array.isArray(rec.headers)) {
        throw new Error("downstream-headers-invalid");
      }
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(rec.headers as Record<string, unknown>)) {
        if (typeof v !== "string") throw new Error("downstream-headers-invalid");
        headers[k] = v;
      }
      spec.headers = headers;
    }
  }
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
  if (rec.trust !== undefined) {
    // HTTP + any trust, or a value other than "same-user", is the same
    // refusal: the field is not a claim about a remote host, and it is
    // not a free-form string.
    if (spec.url !== undefined || rec.trust !== "same-user") {
      throw new Error("downstream-trust-invalid");
    }
    spec.trust = "same-user";
  }
  assertStdioTrusted(spec);
  return spec;
}

/**
 * The `VERAX_DOWNSTREAM` document: one child, or an array of them. An empty
 * array is a document that attaches nothing, which is not the same as no
 * document at all — the operator wrote it, so it is honoured.
 */
export function parseDownstreamDocument(raw: string): DownstreamSpec[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("downstream-json-invalid");
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  const specs: DownstreamSpec[] = [];
  const prefixes = new Set<string>();
  for (const item of items) {
    const spec = parseDownstreamJson(JSON.stringify(item));
    if (prefixes.has(spec.prefix)) {
      throw new Error(`downstream-prefix-duplicate:${spec.prefix}`);
    }
    prefixes.add(spec.prefix);
    specs.push(spec);
  }
  return specs;
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

type ChildTransport = StdioClientTransport | StreamableHTTPClientTransport;

async function shut(client: Client, transport: ChildTransport): Promise<void> {
  await client.close().catch(() => undefined);
  await transport.close().catch(() => undefined);
}

/** Spawns the child. Its stderr is drained so a chatty child cannot block it. */
function stdioTransport(spec: DownstreamSpec): StdioClientTransport {
  if (spec.command === undefined || spec.command.trim() === "") {
    throw new Error("downstream-command-invalid");
  }
  // Last check before the spawn: openDownstream can be called without parse.
  assertStdioTrusted(spec);
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
  return transport;
}

/**
 * Talks to a server already running. The headers are the operator's, from the
 * document — the body's own bearer is never forwarded, for the same
 * confused-deputy reason the stdio child does not inherit `VERAX_*`.
 */
function httpTransport(spec: DownstreamSpec): StreamableHTTPClientTransport {
  if (spec.url === undefined) throw new Error("downstream-url-invalid");
  return new StreamableHTTPClientTransport(new URL(spec.url), {
    requestInit: {
      // The child's address is the operator's document, not a place the
      // child may name. Following a redirect would rewrite that document
      // at run time. The egress list does not see it: egress is for hosts
      // the brain picks.
      redirect: "error",
      ...(spec.headers ? { headers: spec.headers } : {}),
    },
  });
}

/**
 * `connect` does not take a timeout option. Race it, close the transport
 * when the clock wins, and drop the timer so a settled attach cannot keep
 * the process alive.
 */
async function connectWithDeadline(
  client: Client,
  transport: ChildTransport,
  timeoutMs: number,
  prefix: string,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      timer = setTimeout(() => {
        void shut(client, transport);
        reject(new Error(`downstream-attach-timeout:${prefix}`));
      }, timeoutMs);
      client.connect(transport).then(resolve, reject);
    });
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function attachTimeoutError(err: unknown, prefix: string): Error {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.startsWith("downstream-attach-timeout:")) {
    return err instanceof Error ? err : new Error(`downstream-attach-timeout:${prefix}`);
  }
  if (/timed?\s*out|timeout/i.test(msg)) {
    return new Error(`downstream-attach-timeout:${prefix}`);
  }
  return err instanceof Error ? err : new Error(msg);
}

export async function openDownstream(spec: DownstreamSpec): Promise<DownstreamSession> {
  if (!PREFIX_RE.test(spec.prefix)) {
    throw new Error("downstream-prefix-invalid");
  }
  if (spec.command !== undefined && spec.url !== undefined) {
    throw new Error("downstream-transport-ambiguous");
  }
  if (spec.command === undefined && spec.url === undefined) {
    throw new Error("downstream-transport-missing");
  }
  const timeoutMs = spec.timeoutMs ?? 10_000;
  const transport = spec.url !== undefined ? httpTransport(spec) : stdioTransport(spec);
  const client = new Client({ name: "verax-downstream", version: "0.0.0" });
  let listed: Awaited<ReturnType<Client["listTools"]>>;
  try {
    await connectWithDeadline(client, transport, timeoutMs, spec.prefix);
    listed = await client.listTools(undefined, { timeout: timeoutMs });
  } catch (err) {
    await shut(client, transport);
    throw attachTimeoutError(err, spec.prefix);
  }
  if (listed.tools.length > MAX_CHILD_TOOLS) {
    await shut(client, transport);
    throw new Error(`downstream-too-many-tools:${spec.prefix}:${listed.tools.length}`);
  }
  const tools: DownstreamTool[] = [];
  const seen = new Set<string>();
  for (const tool of listed.tools) {
    if (!CHILD_TOOL_RE.test(tool.name)) {
      await shut(client, transport);
      throw new Error(`downstream-child-name-invalid:${tool.name}`);
    }
    const toolBytes = JSON.stringify({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    }).length;
    if (toolBytes > MAX_TOOL_BYTES) {
      await shut(client, transport);
      throw new Error(`downstream-tool-too-large:${spec.prefix}.${tool.name}:${toolBytes}`);
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
      ...(typeof tool.description === "string" ? { description: tool.description } : {}),
      ...(tool.inputSchema !== undefined ? { inputSchema: tool.inputSchema } : {}),
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
