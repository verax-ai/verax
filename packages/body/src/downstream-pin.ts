import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { canonical } from "@cedulon/core";
import { sha256Canonical } from "@verax-ai/proxy";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { defaultElevated } from "./install.ts";
import { CHILD_TOOL_RE, parseDownstreamDocument, prefixedName, type DownstreamSpec } from "./downstream.ts";

/**
 * `verax downstream pin` lists one child's tools a single time, shows each
 * entry with control and format characters visible, and writes a
 * content-addressed manifest beside the downstream document only after the
 * operator types yes. The document is never edited. The operator copies the
 * printed pins line into it, so this command cannot race another editor on
 * that file.
 */

const PINS_RE = /^sha256:([0-9a-f]{64})$/;
const MAX_CHILD_TOOLS = 256;
const MAX_TOOL_BYTES = 64 * 1024;
const MAX_CHILD_MESSAGE_BYTES = 10 * 1024 * 1024;
const MESSAGE_TOO_LARGE = "downstream-message-too-large";

type ChildTransport = StdioClientTransport | StreamableHTTPClientTransport;
type Overflow = { hit: boolean; detach: () => void };

export type DownstreamPinIO = {
  out: (s: string) => void;
  ask: () => Promise<string>;
};

function say(out: (s: string) => void, text: string): void {
  out(text.endsWith("\n") ? text : `${text}\n`);
}

function errorText(err: unknown): string {
  return err instanceof Error && err.message !== "" ? err.message : "downstream-pin-failed";
}

/**
 * Control characters (C0, DEL, C1), format characters (ESC, bidi marks,
 * zero-width characters) and line and paragraph separators are written as
 * `\uXXXX` so a child cannot hide text or drive the terminal. The entry
 * itself is not shortened.
 */
function escapeVisible(text: string): string {
  return text.replace(/\p{Cc}|\p{Cf}|\p{Zl}|\p{Zp}/gu, (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp <= 0xffff) return `\\u${cp.toString(16).padStart(4, "0")}`;
    const rest = cp - 0x10000;
    const high = 0xd800 + (rest >> 10);
    const low = 0xdc00 + (rest & 0x3ff);
    return `\\u${high.toString(16).padStart(4, "0")}\\u${low.toString(16).padStart(4, "0")}`;
  });
}

export function renderToolEntry(entry: unknown): string {
  let encoded: string;
  try {
    encoded = canonical(entry);
  } catch {
    encoded = JSON.stringify(entry) ?? "null";
  }
  return escapeVisible(encoded);
}

function runningAccount(): string {
  if (process.platform === "win32") {
    const name = process.env.USERNAME?.trim() ?? "";
    const domain = process.env.USERDOMAIN?.trim() ?? "";
    if (name !== "") return domain !== "" ? `${domain}\\${name}` : name;
  }
  try {
    const info = userInfo();
    const name = info.username || "unknown";
    if (typeof info.uid === "number" && info.uid >= 0) return `${name} (uid ${info.uid})`;
    return name;
  } catch {
    return "unknown";
  }
}

/** Windows elevation, or POSIX uid 0. An HTTP child is not spawned here, so it is not refused. */
function stdioElevationRefusal(prefix: string): string | null {
  if (process.platform === "win32") {
    try {
      if (!defaultElevated("win32")) return null;
    } catch (err) {
      return `refusing: could not tell whether this process is elevated (${errorText(err)}); stdio child ${prefix} was not started`;
    }
    return `refusing: this process is elevated, so stdio child ${prefix} was not started`;
  }
  if (typeof process.getuid === "function" && process.getuid() === 0) {
    return `refusing: this process is uid 0, so stdio child ${prefix} was not started`;
  }
  return null;
}

function tripOverflow(overflow: Overflow): void {
  if (overflow.hit) return;
  overflow.hit = true;
  overflow.detach();
}

function boundedFetch(overflow: Overflow): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (url, init) => {
    const res = await fetch(url, init);
    if (res.body === null) return res;
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

async function shut(client: Client, transport: ChildTransport): Promise<void> {
  await client.close().catch(() => undefined);
  await transport.close().catch(() => undefined);
}

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

function attachStderr(transport: StdioClientTransport, chunks: Buffer[]): void {
  const stderr = transport.stderr;
  if (!(stderr instanceof Readable)) return;
  stderr.on("data", (chunk: Buffer | string) => {
    if (chunks.reduce((n, c) => n + c.length, 0) >= MAX_CHILD_MESSAGE_BYTES) return;
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  });
}

/**
 * One `tools/list`. The snapshot returned here is what is shown and, after
 * yes, what is written. Connecting again would let the child answer differently
 * from the text the operator read.
 */
async function listOnce(spec: DownstreamSpec): Promise<{ tools: unknown[]; stderr: string }> {
  const timeoutMs = spec.timeoutMs ?? 10_000;
  const overflow: Overflow = { hit: false, detach: () => undefined };
  const stderrChunks: Buffer[] = [];
  const transport =
    spec.url !== undefined
      ? new StreamableHTTPClientTransport(new URL(spec.url), {
          fetch: boundedFetch(overflow),
          requestInit: {
            redirect: "error",
            ...(spec.headers ? { headers: spec.headers } : {}),
          },
        })
      : new StdioClientTransport({
          command: spec.command ?? "",
          args: spec.args,
          cwd: spec.cwd,
          // Safe inherit plus the operator's overlay. Not process.env: that would
          // hand the child VERAX_* tokens this process already holds.
          env: { ...getDefaultEnvironment(), ...(spec.env ?? {}) },
          // "inherit" would print the child's bytes on this terminal. The pipe
          // is shown only after the same escaping as a tool entry.
          stderr: "pipe",
          maxBufferSize: MAX_CHILD_MESSAGE_BYTES,
        });
  if (transport instanceof StdioClientTransport) attachStderr(transport, stderrChunks);
  const client = new Client({ name: "verax-downstream-pin", version: "0.0.0" });
  overflow.detach = () => void transport.close().catch(() => undefined);
  client.onerror = (err) => {
    if (/ReadBuffer exceeded maximum size/.test(err.message)) overflow.hit = true;
  };
  try {
    await connectWithDeadline(client, transport, timeoutMs, spec.prefix);
    // Plain request, not client.listTools: that call compiles every outputSchema
    // the child lists into a validator in this process.
    const listed = await client.request({ method: "tools/list" }, ListToolsResultSchema, { timeout: timeoutMs });
    if (listed.tools.length > MAX_CHILD_TOOLS) {
      throw new Error(`downstream-too-many-tools:${spec.prefix}:${listed.tools.length}`);
    }
    return { tools: [...listed.tools], stderr: Buffer.concat(stderrChunks).toString("utf8") };
  } catch (err) {
    const stderr = Buffer.concat(stderrChunks).toString("utf8");
    if (overflow.hit) {
      const tooLarge = new Error(`${MESSAGE_TOO_LARGE}:${spec.prefix}`) as Error & { stderr?: string };
      tooLarge.stderr = stderr;
      throw tooLarge;
    }
    if (err instanceof Error) {
      (err as Error & { stderr?: string }).stderr = stderr;
      throw err;
    }
    const wrapped = new Error(errorText(err)) as Error & { stderr?: string };
    wrapped.stderr = stderr;
    throw wrapped;
  } finally {
    await shut(client, transport);
  }
}

function plainTool(tool: unknown): Record<string, unknown> {
  const parsed = JSON.parse(canonical(tool)) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("downstream-child-name-invalid");
  }
  return parsed as Record<string, unknown>;
}

function snapshotOf(spec: DownstreamSpec, listed: readonly unknown[]): Record<string, unknown> {
  const wanted = spec.tools === undefined ? null : new Set(spec.tools);
  // A null prototype keeps `__proto__` and `constructor` as ordinary keys.
  // The bytes `canonical` writes are the same as for a plain object.
  const tools: Record<string, unknown> = Object.create(null);
  const seen = new Set<string>();
  for (const tool of listed) {
    const name =
      tool !== null && typeof tool === "object" && typeof (tool as { name?: unknown }).name === "string"
        ? (tool as { name: string }).name
        : undefined;
    if (name === undefined) throw new Error("downstream-child-name-invalid");
    if (wanted !== null && !wanted.has(name)) continue;
    if (!CHILD_TOOL_RE.test(name)) throw new Error(`downstream-child-name-invalid:${name}`);
    const published = prefixedName(spec.prefix, name);
    if (seen.has(published)) throw new Error(`downstream-name-collision:${published}`);
    seen.add(published);
    const bytes = Buffer.byteLength(JSON.stringify(tool), "utf8");
    if (bytes > MAX_TOOL_BYTES) throw new Error(`downstream-tool-too-large:${spec.prefix}.${name}:${bytes}`);
    tools[name] = plainTool(tool);
  }
  if (wanted !== null) {
    for (const name of wanted) {
      if (!Object.hasOwn(tools, name)) throw new Error(`downstream-tool-missing:${spec.prefix}.${name}`);
    }
  }
  return tools;
}

function showDifference(
  out: (s: string) => void,
  spec: DownstreamSpec,
  tools: Record<string, unknown>,
  docDir: string,
): void {
  if (spec.pins === undefined) return;
  const digest = PINS_RE.exec(spec.pins)?.[1];
  if (digest === undefined) {
    say(out, escapeVisible(`pins ${spec.pins} is not a digest`));
    return;
  }
  const path = join(docDir, "definitions", `${digest}.json`);
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    say(out, escapeVisible(`named manifest sha256:${digest} could not be read: ${errorText(err)}`));
    return;
  }
  if (createHash("sha256").update(bytes).digest("hex") !== digest) {
    say(out, escapeVisible(`named manifest sha256:${digest} does not hash to its name`));
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    say(out, escapeVisible(`named manifest sha256:${digest} is not json`));
    return;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    say(out, escapeVisible(`named manifest sha256:${digest} is not an object`));
    return;
  }
  const rec = parsed as { prefix?: unknown; selected?: unknown; tools?: unknown };
  if (rec.prefix !== spec.prefix) {
    say(out, escapeVisible(`manifest prefix differs from ${spec.prefix}`));
  }
  try {
    if (canonical(rec.selected ?? null) !== canonical(spec.tools ?? null)) {
      say(out, escapeVisible("manifest selection differs from the document"));
    }
  } catch {
    say(out, escapeVisible("manifest selection could not be compared"));
  }
  if (rec.tools === null || typeof rec.tools !== "object" || Array.isArray(rec.tools)) {
    say(out, escapeVisible("manifest tools are not an object"));
    return;
  }
  const previous = rec.tools as Record<string, unknown>;
  const names = [...new Set([...Object.keys(previous), ...Object.keys(tools)])].sort();
  let differed = false;
  for (const name of names) {
    const before = Object.hasOwn(previous, name) ? previous[name] : undefined;
    const after = Object.hasOwn(tools, name) ? tools[name] : undefined;
    if (before === undefined) {
      differed = true;
      say(out, escapeVisible(`added ${name}`));
      continue;
    }
    if (after === undefined) {
      differed = true;
      say(out, escapeVisible(`removed ${name}`));
      say(out, renderToolEntry(before));
      continue;
    }
    if (sha256Canonical(before) !== sha256Canonical(after)) {
      differed = true;
      say(out, escapeVisible(`changed ${name}`));
      say(out, renderToolEntry(before));
    }
  }
  if (!differed) say(out, escapeVisible(`listed definitions match sha256:${digest}`));
}

function writeManifest(docDir: string, manifest: unknown): { ok: true; digest: string } | { ok: false; reason: string } {
  const bytes = canonical(manifest);
  const digest = sha256Canonical(manifest);
  const folder = join(docDir, "definitions");
  const dest = join(folder, `${digest}.json`);
  // The file is named by its digest, and the operator's document names that
  // digest, so the manifest is not a secret. 0755 and 0644 let the account
  // that runs the body read a manifest an operator account wrote. chmod
  // follows the create because the process umask would otherwise clear
  // the other-read and other-execute bits.
  mkdirSync(folder, { recursive: true, mode: 0o755 });
  chmodSync(folder, 0o755);
  try {
    writeFileSync(dest, bytes, { encoding: "utf8", flag: "wx", mode: 0o644 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") return { ok: false, reason: errorText(err) };
    let existing: Buffer;
    try {
      existing = readFileSync(dest);
    } catch (readErr) {
      return { ok: false, reason: errorText(readErr) };
    }
    if (!existing.equals(Buffer.from(bytes, "utf8"))) {
      return { ok: false, reason: `downstream-manifest-conflict:${digest}` };
    }
  }
  chmodSync(dest, 0o644);
  return { ok: true, digest };
}

export async function runDownstreamPin(
  input: { file: string; prefix: string },
  io: DownstreamPinIO,
): Promise<number> {
  let specs: DownstreamSpec[];
  try {
    specs = parseDownstreamDocument(readFileSync(input.file, "utf8"));
  } catch (err) {
    say(io.out, escapeVisible(errorText(err)));
    return 1;
  }
  const spec = specs.find((item) => item.prefix === input.prefix);
  if (spec === undefined) {
    say(io.out, escapeVisible(`no downstream child with prefix ${input.prefix}`));
    return 1;
  }
  if (spec.command !== undefined) {
    say(io.out, escapeVisible(`stdio child ${spec.prefix} will run as ${runningAccount()}`));
    const refusal = stdioElevationRefusal(spec.prefix);
    if (refusal !== null) {
      say(io.out, escapeVisible(refusal));
      return 1;
    }
  }
  let listed: { tools: unknown[]; stderr: string };
  try {
    listed = await listOnce(spec);
  } catch (err) {
    const stderr = (err as { stderr?: unknown }).stderr;
    if (typeof stderr === "string" && stderr !== "") {
      say(io.out, "child stderr:");
      say(io.out, escapeVisible(stderr));
    }
    say(io.out, escapeVisible(errorText(err)));
    return 1;
  }
  if (listed.stderr !== "") {
    say(io.out, "child stderr:");
    say(io.out, escapeVisible(listed.stderr));
  }
  let tools: Record<string, unknown>;
  try {
    tools = snapshotOf(spec, listed.tools);
  } catch (err) {
    say(io.out, escapeVisible(errorText(err)));
    return 1;
  }
  for (const name of Object.keys(tools).sort()) say(io.out, renderToolEntry(tools[name]));
  showDifference(io.out, spec, tools, dirname(input.file));
  let answer: string;
  try {
    answer = await io.ask();
  } catch (err) {
    say(io.out, escapeVisible(errorText(err)));
    return 1;
  }
  if (answer !== "yes") return 1;
  const manifest = { v: 1, prefix: spec.prefix, selected: spec.tools ?? null, tools };
  let written: { ok: true; digest: string } | { ok: false; reason: string };
  try {
    written = writeManifest(dirname(input.file), manifest);
  } catch (err) {
    say(io.out, escapeVisible(errorText(err)));
    return 1;
  }
  if (!written.ok) {
    say(io.out, escapeVisible(written.reason));
    return 1;
  }
  say(io.out, `"pins": "sha256:${written.digest}"`);
  return 0;
}
