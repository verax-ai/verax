import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Readable } from "node:stream";
import { canonical } from "@cedulon/core";
import type { SignedEffectExtract } from "@cedulon/effect-extract";
import { DISPLAY_ESCAPE_CLASS, effectDescriptor, samePublicKey, sha256Canonical, terminalText, thirdPartyReceiptRejection } from "@verax-ai/proxy";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolResultSchema, ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";
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
  /** Operator-pinned downstream Ed25519 SPKI public key. */
  effectKeyPem?: string;
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
  /**
   * Child tool names to attach, unprefixed. Only these enter the registry
   * and only these are held to the bounds; a name the child does not offer
   * stops the attach. Absent means every tool the child lists.
   */
  tools?: string[];
  /**
   * Content address of the manifest the operator approved: `sha256:` and 64
   * lowercase hex digits. Absent means the child is attached without
   * comparing definitions.
   */
  pins?: string;
};

export type DownstreamTool = {
  name: string;
  /** The child's own description, as `tools/list` gave it. */
  description?: string;
  /** The child's input schema, object keys in canonical order. */
  inputSchema?: unknown;
  fn: DownstreamToolFn;
};

export type DownstreamSession = {
  prefix: string;
  tools: readonly DownstreamTool[];
  close(): Promise<void>;
};

const PREFIX_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
/** `sha256:` plus 64 lowercase hex digits. The capture is the file name. */
const PINS_RE = /^sha256:([0-9a-f]{64})$/;
export const CHILD_TOOL_RE = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
/** Prefixed name a caller may put on extraTools: `prefix.childName`. */
const EXTRA_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}\.[A-Za-z][A-Za-z0-9._-]{0,63}$/;
// Sanity bound, not a capacity claim. A child that lists more than this is
// hostile or broken; the body is not a registry for thousands of names.
const MAX_CHILD_TOOLS = 256;
const MAX_TOOL_BYTES = 64 * 1024;
/**
 * One message from a child: a line on stdio, an HTTP response body, or one
 * SSE event. A whole `tools/list` answer is one message, so this also caps
 * the list the per-tool bounds are then applied to.
 */
const MAX_CHILD_MESSAGE_BYTES = 10 * 1024 * 1024;
const MESSAGE_TOO_LARGE = "downstream-message-too-large";

/** Set when a child sent a message over the bound. The child is then detached. */
type Overflow = { hit: boolean; detach: () => void };

function tripOverflow(overflow: Overflow): void {
  if (overflow.hit) return;
  overflow.hit = true;
  overflow.detach();
}

function assertEffectKey(pem: unknown): asserts pem is string {
  try {
    if (typeof pem !== "string" || !pem.trim().startsWith("-----BEGIN PUBLIC KEY-----") ||
        createPublicKey(pem).asymmetricKeyType !== "ed25519") throw new Error();
  } catch { throw new Error("downstream-effect-key-invalid"); }
}

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

export function parseDownstreamJson(raw: string, bodyPublicKeyPems: readonly string[] = []): DownstreamSpec {
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
  if (rec.effectKeyPem !== undefined) {
    assertEffectKey(rec.effectKeyPem);
    if (bodyPublicKeyPems.some(key => samePublicKey(key, rec.effectKeyPem as string))) {
      throw new Error(`downstream-effect-key-not-independent:${spec.prefix}`);
    }
    spec.effectKeyPem = rec.effectKeyPem;
  }
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
  if (rec.tools !== undefined) {
    const names = rec.tools;
    if (
      !Array.isArray(names) ||
      names.length === 0 ||
      names.length > MAX_CHILD_TOOLS ||
      !names.every((n) => typeof n === "string" && CHILD_TOOL_RE.test(n)) ||
      new Set(names).size !== names.length
    ) {
      throw new Error("downstream-tools-invalid");
    }
    spec.tools = [...(names as string[])];
  }
  if (rec.pins !== undefined) {
    if (typeof rec.pins !== "string" || !PINS_RE.test(rec.pins)) {
      throw new Error(`downstream-pins-invalid:${spec.prefix}`);
    }
    spec.pins = rec.pins;
  }
  assertStdioTrusted(spec);
  return spec;
}

/**
 * The `VERAX_DOWNSTREAM` document: one child, or an array of them. An empty
 * array is a document that attaches nothing, which is not the same as no
 * document at all — the operator wrote it, so it is honoured.
 */
export function parseDownstreamDocument(raw: string, bodyPublicKeyPems: readonly string[] = []): DownstreamSpec[] {
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
    const spec = parseDownstreamJson(JSON.stringify(item), bodyPublicKeyPems);
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
  const content: ToolResult["content"] = [];
  const items: unknown[] = Array.isArray(rec.content) ? rec.content : [];
  for (const item of items) {
    if (item !== null && typeof item === "object") {
      const block = item as Record<string, unknown>;
      if (block.type === "text" && typeof block.text === "string") {
        content.push({ type: "text", text: block.text });
        continue;
      }
      if (
        (block.type === "image" || block.type === "audio") &&
        typeof block.data === "string" &&
        typeof block.mimeType === "string"
      ) {
        content.push({ type: block.type, data: block.data, mimeType: block.mimeType });
        continue;
      }
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

/**
 * Spawns the child. Stderr is drained so a chatty child cannot block it.
 * Pass `stderrChunks` to keep the bytes instead (the pin command shows them);
 * the same cap, and collection stops at the cap instead of growing without bound.
 */
function stdioTransport(spec: DownstreamSpec, stderrChunks?: Buffer[]): StdioClientTransport {
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
    // The client's own default is the same number; it is stated here so the
    // bound is this file's and not a dependency's.
    maxBufferSize: MAX_CHILD_MESSAGE_BYTES,
  });
  // The SDK types the pipe as Stream; only a Readable can be drained.
  const stderr = transport.stderr;
  if (stderr instanceof Readable) {
    if (stderrChunks === undefined) stderr.resume();
    else collectStderr(stderr, stderrChunks);
  }
  return transport;
}

function collectStderr(stderr: Readable, chunks: Buffer[]): void {
  stderr.on("data", (chunk: Buffer | string) => {
    if (chunks.reduce((n, c) => n + c.length, 0) >= MAX_CHILD_MESSAGE_BYTES) return;
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  });
}

/**
 * Talks to a server already running. The headers are the operator's, from the
 * document — the body's own bearer is never forwarded, for the same
 * confused-deputy reason the stdio child does not inherit `VERAX_*`.
 */
function httpTransport(spec: DownstreamSpec, overflow: Overflow): StreamableHTTPClientTransport {
  if (spec.url === undefined) throw new Error("downstream-url-invalid");
  return new StreamableHTTPClientTransport(new URL(spec.url), {
    fetch: boundedFetch(overflow),
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
 * Counts what a child's response carries as it is read, so an answer over the
 * bound is refused at the bound instead of after it has been held and parsed.
 * A JSON answer is one message. On an event stream each event is one, and an
 * empty line ends it; a stream that ends its lines with a bare CR is counted
 * as a single message.
 */
function boundedFetch(overflow: Overflow): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (url, init) => {
    const res = await fetch(url, init);
    if (res.body === null) return res;
    // Events only where every version of the client reads events: a success
    // whose media type is exactly this. An error answer is read whole as text,
    // and so is a JSON answer whose parameters merely mention the name; an
    // empty line inside either must not restart the count.
    const mediaType = (res.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    const events = res.ok && mediaType === "text/event-stream";
    let count = 0;
    let lineEmpty = true;
    const counted = res.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          if (!events) {
            count += chunk.byteLength;
          } else {
            let at = 0;
            while (at < chunk.byteLength && count <= MAX_CHILD_MESSAGE_BYTES) {
              const newline = chunk.indexOf(0x0a, at);
              const end = newline === -1 ? chunk.byteLength : newline;
              const length = end - at;
              if (length > 1 || (length === 1 && chunk[at] !== 0x0d)) lineEmpty = false;
              count += length;
              if (newline === -1) break;
              count += 1;
              if (lineEmpty) count = 0;
              lineEmpty = true;
              at = newline + 1;
            }
          }
          if (count > MAX_CHILD_MESSAGE_BYTES) {
            tripOverflow(overflow);
            controller.error(new Error(MESSAGE_TOO_LARGE));
            return;
          }
          controller.enqueue(chunk);
        },
      }),
    );
    return new Response(counted, { status: res.status, statusText: res.statusText, headers: res.headers });
  };
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

/**
 * Object keys in the order `canonical` uses. Array order stays: it can carry
 * meaning. Two schemas that differ only by key order are then published the same.
 */
function sortedObject(value: unknown): unknown {
  return JSON.parse(canonical(value)) as unknown;
}

type PinnedManifest = {
  prefix: unknown;
  selected: unknown;
  tools: Record<string, unknown>;
};

function manifestInvalid(prefix: string): never {
  throw new Error(`downstream-manifest-invalid:${prefix}`);
}

/** One read. The digest is of those bytes, not of a re-encoded document. */
function readPinnedManifest(prefix: string, pins: string, definitionsDir: string | undefined): PinnedManifest {
  const digest = PINS_RE.exec(pins)?.[1];
  if (digest === undefined) throw new Error(`downstream-pins-invalid:${prefix}`);
  if (definitionsDir === undefined || definitionsDir === "") manifestInvalid(prefix);
  let bytes: Buffer;
  try {
    bytes = readFileSync(join(definitionsDir, "definitions", `${digest}.json`));
  } catch (err) {
    // A missing or corrupt file is not the same fact as a file this account
    // is not allowed to read.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM") throw new Error(`downstream-manifest-unreadable:${prefix}`);
    manifestInvalid(prefix);
  }
  if (createHash("sha256").update(bytes).digest("hex") !== digest) manifestInvalid(prefix);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    manifestInvalid(prefix);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) manifestInvalid(prefix);
  const rec = parsed as Record<string, unknown>;
  if (rec.v !== 1) manifestInvalid(prefix);
  if (rec.tools === null || typeof rec.tools !== "object" || Array.isArray(rec.tools)) manifestInvalid(prefix);
  return { prefix: rec.prefix, selected: rec.selected, tools: rec.tools as Record<string, unknown> };
}

/** Both absent (no `tools`, and `selected` null or missing) is the same selection. */
function sameSelection(specTools: string[] | undefined, selected: unknown): boolean {
  const left = specTools === undefined ? null : specTools;
  const right = selected === undefined || selected === null ? null : selected;
  if (left === null || right === null) return left === null && right === null;
  if (!Array.isArray(right) || right.some((name) => typeof name !== "string")) return false;
  const wanted = new Set(left);
  const pinned = new Set(right);
  if (wanted.size !== pinned.size) return false;
  for (const name of wanted) if (!pinned.has(name)) return false;
  return true;
}

/**
 * With no selection the listed names and the pinned names are one set.
 * With a selection only those names are compared; a selected name with no
 * pin is unpinned. The digest is the whole parsed entry, not a list of fields.
 */
function assertPinnedDefinitions(
  spec: DownstreamSpec,
  offered: readonly { name: string }[],
  manifestTools: Record<string, unknown>,
): void {
  const listedNames = offered.map((tool) => tool.name);
  if (spec.tools === undefined) {
    for (const name of listedNames) {
      if (!Object.hasOwn(manifestTools, name)) {
        throw new Error(`downstream-tool-unpinned:${spec.prefix}.${name}`);
      }
    }
    const listed = new Set(listedNames);
    for (const name of Object.keys(manifestTools)) {
      if (!listed.has(name)) throw new Error(`downstream-tool-unlisted:${spec.prefix}.${name}`);
    }
  } else {
    for (const name of spec.tools) {
      if (!Object.hasOwn(manifestTools, name)) {
        throw new Error(`downstream-tool-unpinned:${spec.prefix}.${name}`);
      }
    }
  }
  const byName = new Map(offered.map((tool) => [tool.name, tool]));
  for (const name of spec.tools ?? listedNames) {
    const listed = byName.get(name);
    if (listed === undefined || !Object.hasOwn(manifestTools, name)) continue;
    let listedDigest: string;
    let pinnedDigest: string;
    try {
      listedDigest = sha256Canonical(listed);
      pinnedDigest = sha256Canonical(manifestTools[name]);
    } catch {
      throw new Error(`downstream-definition-unencodable:${spec.prefix}.${name}`);
    }
    if (listedDigest !== pinnedDigest) {
      throw new Error(`downstream-definition-changed:${spec.prefix}.${name}`);
    }
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

/**
 * A child string that has not passed the name pattern, as it may be printed.
 * JSON quotes it and writes controls, quotes and backslashes as escapes; the
 * display class then writes every remaining mark, unassigned, private-use or
 * surrogate code point as `\uXXXX`, one escape per UTF-16 unit, the same
 * shape the pin command uses. A name that already matched the pattern is not
 * passed through here.
 */
function shown(text: string): string {
  return JSON.stringify(text).replace(new RegExp(`[${DISPLAY_ESCAPE_CLASS}]`, "gu"), (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp <= 0xffff) return `\\u${cp.toString(16).padStart(4, "0")}`;
    const rest = cp - 0x10000;
    const high = 0xd800 + (rest >> 10);
    const low = 0xdc00 + (rest & 0x3ff);
    return `\\u${high.toString(16).padStart(4, "0")}\\u${low.toString(16).padStart(4, "0")}`;
  });
}

/**
 * The child's `tools/list`, held to one set of bounds. A `tools` selection
 * is applied first: anything not selected is never read past its name (no
 * size check, no collision check). Both attach and the pin command use this,
 * so a name, a size, or a collision the body would refuse is refused here too.
 */
function acceptedTools<T extends { name: string }>(spec: DownstreamSpec, listed: readonly T[]): T[] {
  if (listed.length > MAX_CHILD_TOOLS) {
    throw new Error(`downstream-too-many-tools:${spec.prefix}:${listed.length}`);
  }
  const wanted = spec.tools === undefined ? null : new Set(spec.tools);
  const offered = wanted === null ? [...listed] : listed.filter((tool) => wanted.has(tool.name));
  if (wanted !== null) {
    for (const name of wanted) {
      if (!offered.some((tool) => tool.name === name)) {
        throw new Error(`downstream-tool-missing:${spec.prefix}.${name}`);
      }
    }
  }
  const seen = new Set<string>();
  for (const tool of offered) {
    if (!CHILD_TOOL_RE.test(tool.name)) {
      throw new Error(`downstream-child-name-invalid:${shown(tool.name)}`);
    }
    const toolBytes = Buffer.byteLength(JSON.stringify(tool), "utf8");
    if (toolBytes > MAX_TOOL_BYTES) {
      throw new Error(`downstream-tool-too-large:${spec.prefix}.${tool.name}:${toolBytes}`);
    }
    const published = prefixedName(spec.prefix, tool.name);
    if (seen.has(published)) {
      throw new Error(`downstream-name-collision:${published}`);
    }
    seen.add(published);
    // Canonical JSON refuses a non-finite number. That entry cannot be pinned
    // or republished. A lone surrogate is left as text and compared as such.
    try {
      canonical(tool);
    } catch {
      throw new Error(`downstream-definition-unencodable:${spec.prefix}.${tool.name}`);
    }
  }
  return offered;
}

function plainTool(tool: unknown): Record<string, unknown> {
  const parsed = JSON.parse(canonical(tool)) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("downstream-child-name-invalid");
  }
  return parsed as Record<string, unknown>;
}

/** Entries keyed by the child's own name. A null prototype keeps `__proto__` and `constructor` ordinary. */
function snapshotRecord(offered: readonly { name: string }[]): Record<string, unknown> {
  const tools: Record<string, unknown> = Object.create(null);
  for (const tool of offered) tools[tool.name] = plainTool(tool);
  return tools;
}

// Asked as a plain request, not through client.listTools: that call compiles every
// outputSchema the child lists into a validator, and client.callTool then runs it
// on the child's own result inside this process. A child's schema is the child's
// input; a backtracking pattern in it held the body for seconds per call.
function requestToolList(client: Client, timeoutMs: number): ReturnType<Client["listTools"]> {
  return client.request({ method: "tools/list" }, ListToolsResultSchema, { timeout: timeoutMs });
}

/**
 * Connects the child once, takes `tools/list` under the same bounds as
 * `openDownstream`, collects stderr, and closes. The returned tools are the
 * snapshot that is shown and, after the operator types yes, written. Listing
 * again would let the child answer differently from the text that was read.
 * On failure the error carries `stderr` when the child wrote any.
 */
export async function listDownstreamOnce(
  spec: DownstreamSpec,
): Promise<{ tools: Record<string, unknown>; stderr: string }> {
  const timeoutMs = spec.timeoutMs ?? 10_000;
  const overflow: Overflow = { hit: false, detach: () => undefined };
  const stderrChunks: Buffer[] = [];
  const transport = spec.url !== undefined ? httpTransport(spec, overflow) : stdioTransport(spec, stderrChunks);
  const client = new Client({ name: "verax-downstream-pin", version: "0.0.0" });
  overflow.detach = () => void transport.close().catch(() => undefined);
  // On stdio the client's read buffer enforces the bound and closes the child.
  // This is where it says so; the text is the client's.
  client.onerror = (err) => {
    if (/ReadBuffer exceeded maximum size/.test(err.message)) overflow.hit = true;
  };
  const stderrNow = () => Buffer.concat(stderrChunks).toString("utf8");
  try {
    await connectWithDeadline(client, transport, timeoutMs, spec.prefix);
    const listed = await requestToolList(client, timeoutMs);
    return { tools: snapshotRecord(acceptedTools(spec, listed.tools)), stderr: stderrNow() };
  } catch (err) {
    const stderr = stderrNow();
    const message = err instanceof Error ? err.message : "";
    if (overflow.hit && !message.startsWith("downstream-")) {
      const tooLarge = new Error(`${MESSAGE_TOO_LARGE}:${spec.prefix}`) as Error & { stderr?: string };
      tooLarge.stderr = stderr;
      throw tooLarge;
    }
    if (err instanceof Error) {
      (err as Error & { stderr?: string }).stderr = stderr;
      throw err;
    }
    const wrapped = new Error("downstream-pin-failed") as Error & { stderr?: string };
    wrapped.stderr = stderr;
    throw wrapped;
  } finally {
    await shut(client, transport);
  }
}

export async function openDownstream(
  spec: DownstreamSpec,
  opts?: { definitionsDir?: string },
): Promise<DownstreamSession> {
  if (spec.effectKeyPem !== undefined) assertEffectKey(spec.effectKeyPem);
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
  const overflow: Overflow = { hit: false, detach: () => undefined };
  const transport = spec.url !== undefined ? httpTransport(spec, overflow) : stdioTransport(spec);
  const client = new Client({ name: "verax-downstream", version: "0.0.0" });
  // Closing the transport ends every call still waiting on this child at once,
  // an event stream included, instead of at its timeout.
  overflow.detach = () => void transport.close().catch(() => undefined);
  // On stdio the client's read buffer enforces the bound and closes the child.
  // This is where it says so; the text is the client's, and the stdio cases
  // of `attack-r26-child-message-bound` fail if it changes.
  client.onerror = (err) => {
    if (/ReadBuffer exceeded maximum size/.test(err.message)) overflow.hit = true;
  };
  let listed: Awaited<ReturnType<Client["listTools"]>>;
  try {
    await connectWithDeadline(client, transport, timeoutMs, spec.prefix);
    listed = await requestToolList(client, timeoutMs);
  } catch (err) {
    await shut(client, transport);
    if (overflow.hit) throw new Error(`${MESSAGE_TOO_LARGE}:${spec.prefix}`);
    throw attachTimeoutError(err, spec.prefix);
  }
  // With a `tools` list the rest of the child's list is never read past its
  // name: no size check, no registry entry, nothing republished.
  let offered: Awaited<ReturnType<Client["listTools"]>>["tools"];
  try {
    offered = acceptedTools(spec, listed.tools);
  } catch (err) {
    await shut(client, transport);
    throw err;
  }
  const tools: DownstreamTool[] = [];
  for (const tool of offered) {
    const name = prefixedName(spec.prefix, tool.name);
    const childName = tool.name;
    // Key order is published sorted. The encodability of the whole entry was
    // already refused above; a schema that still cannot be written closes the child.
    let inputSchema: unknown;
    try {
      if (tool.inputSchema !== undefined) inputSchema = sortedObject(tool.inputSchema);
    } catch {
      await shut(client, transport);
      throw new Error(`downstream-definition-unencodable:${spec.prefix}.${childName}`);
    }
    tools.push({
      name,
      ...(typeof tool.description === "string" ? { description: tool.description } : {}),
      ...(inputSchema !== undefined ? { inputSchema } : {}),
      fn: async (call, _principal, ref) => {
        // A child that sent one message over the bound is not asked again.
        if (overflow.hit) throw new DownstreamCallError(spec.prefix, childName, new Error(MESSAGE_TOO_LARGE));
        let raw: Awaited<ReturnType<Client["callTool"]>>;
        try {
          // Mutation check: stub this call and the allow test expecting
          // "pong":true from the child goes red.
          raw = await client.request(
            { method: "tools/call",
              params: { name: childName, arguments: call.arguments,
                ...(spec.effectKeyPem ? { _meta: { "io.cedulon/decision": { ref, deciderId: "verax-proxy", prefix: spec.prefix } } } : {}),
              },
            },
            CallToolResultSchema,
            { timeout: timeoutMs },
          );
        } catch (err) {
          throw new DownstreamCallError(spec.prefix, childName, overflow.hit ? new Error(MESSAGE_TOO_LARGE) : err);
        }
        const result = asTextResult(raw);
        if (result.isError) {
          throw new DownstreamCallError(spec.prefix, childName, textOf(result) || "isError");
        }
        if (spec.effectKeyPem) {
          const receipt = raw._meta?.["io.cedulon/effect-extract"];
          const reason = thirdPartyReceiptRejection(receipt, spec.effectKeyPem, ref, name,
            sha256Canonical(effectDescriptor(name, call.arguments)));
          if (reason) process.stderr.write(`verax-body: third-party receipt rejected: ${terminalText(reason)}\n`);
          else result.effectReceipt = receipt as SignedEffectExtract;
        }
        return result;
      },
    });
  }
  // A child can keep a tool's name and change what that name means. The pin
  // names the manifest of the definitions the operator read; the bytes of
  // that file, its prefix and selection, and each listed entry are compared
  // with what this child just returned, so a changed definition cannot attach
  // under the same name.
  if (spec.pins !== undefined) {
    try {
      const manifest = readPinnedManifest(spec.prefix, spec.pins, opts?.definitionsDir);
      if (manifest.prefix !== spec.prefix || !sameSelection(spec.tools, manifest.selected)) {
        throw new Error(`downstream-manifest-mismatch:${spec.prefix}`);
      }
      assertPinnedDefinitions(spec, offered, manifest.tools);
    } catch (err) {
      await shut(client, transport);
      throw err;
    }
  }
  tools.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
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
  return result.content.map((c) => (c.type === "text" ? c.text : "")).join("");
}
