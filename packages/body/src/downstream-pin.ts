import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { canonical } from "@cedulon/core";
import { DISPLAY_ESCAPE_CLASS, sha256Canonical } from "@verax-ai/proxy";
import { defaultElevated } from "./install.ts";
import { listDownstreamOnce, parseDownstreamDocument, type DownstreamSpec } from "./downstream.ts";

/**
 * `verax downstream pin` lists one child's tools a single time, shows each
 * entry with characters that draw nothing visible as escapes, and writes a
 * content-addressed manifest beside the downstream document only after the
 * operator types yes. The document is never edited. The operator copies the
 * printed pins line into it, so this command cannot race another editor on
 * that file.
 */

const PINS_RE = /^sha256:([0-9a-f]{64})$/;

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
 * Control and format characters, and the other code points that draw nothing
 * (default-ignorable code points, variation selectors, the braille blank,
 * every space separator except U+0020), are written as `\uXXXX` so a child
 * cannot hide text or drive the terminal. A supplementary-plane code point
 * is two escapes, one per UTF-16 unit. The entry itself is not shortened.
 *
 * A written escape and the character it names must not look the same. A real
 * backslash is written as two characters first, then the class is escaped:
 * the same rule as `plain()` on the door page. A JSON line has already
 * doubled every backslash, so it uses `escapeVisible` alone; doubling it
 * again would change the value. Every other line uses `escapeLine`.
 */
function escapeVisible(text: string): string {
  return text.replace(new RegExp(`[${DISPLAY_ESCAPE_CLASS}]`, "gu"), (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp <= 0xffff) return `\\u${cp.toString(16).padStart(4, "0")}`;
    const rest = cp - 0x10000;
    const high = 0xd800 + (rest >> 10);
    const low = 0xdc00 + (rest & 0x3ff);
    return `\\u${high.toString(16).padStart(4, "0")}\\u${low.toString(16).padStart(4, "0")}`;
  });
}

function escapeLine(text: string): string {
  return escapeVisible(text.replace(/\\/g, "\\\\"));
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

function showDifference(
  out: (s: string) => void,
  spec: DownstreamSpec,
  tools: Record<string, unknown>,
  docDir: string,
): void {
  if (spec.pins === undefined) return;
  const digest = PINS_RE.exec(spec.pins)?.[1];
  if (digest === undefined) {
    say(out, escapeLine(`pins ${spec.pins} is not a digest`));
    return;
  }
  const path = join(docDir, "definitions", `${digest}.json`);
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    say(out, escapeLine(`named manifest sha256:${digest} could not be read: ${errorText(err)}`));
    return;
  }
  if (createHash("sha256").update(bytes).digest("hex") !== digest) {
    say(out, escapeLine(`named manifest sha256:${digest} does not hash to its name`));
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    say(out, escapeLine(`named manifest sha256:${digest} is not json`));
    return;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    say(out, escapeLine(`named manifest sha256:${digest} is not an object`));
    return;
  }
  const rec = parsed as { prefix?: unknown; selected?: unknown; tools?: unknown };
  if (rec.prefix !== spec.prefix) {
    say(out, escapeLine(`manifest prefix differs from ${spec.prefix}`));
  }
  try {
    if (canonical(rec.selected ?? null) !== canonical(spec.tools ?? null)) {
      say(out, escapeLine("manifest selection differs from the document"));
    }
  } catch {
    say(out, escapeLine("manifest selection could not be compared"));
  }
  if (rec.tools === null || typeof rec.tools !== "object" || Array.isArray(rec.tools)) {
    say(out, escapeLine("manifest tools are not an object"));
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
      say(out, escapeLine(`added ${name}`));
      continue;
    }
    if (after === undefined) {
      differed = true;
      say(out, escapeLine(`removed ${name}`));
      say(out, renderToolEntry(before));
      continue;
    }
    if (sha256Canonical(before) !== sha256Canonical(after)) {
      differed = true;
      say(out, escapeLine(`changed ${name}`));
      say(out, renderToolEntry(before));
    }
  }
  if (!differed) say(out, escapeLine(`listed definitions match sha256:${digest}`));
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
    say(io.out, escapeLine(errorText(err)));
    return 1;
  }
  const spec = specs.find((item) => item.prefix === input.prefix);
  if (spec === undefined) {
    say(io.out, escapeLine(`no downstream child with prefix ${input.prefix}`));
    return 1;
  }
  if (spec.command !== undefined) {
    say(io.out, escapeLine(`stdio child ${spec.prefix} will run as ${runningAccount()}`));
    const refusal = stdioElevationRefusal(spec.prefix);
    if (refusal !== null) {
      say(io.out, escapeLine(refusal));
      return 1;
    }
  }
  // Elevation was refused above, before this call. The tools returned here are
  // the snapshot that is shown and, after yes, written. There is no second list.
  let listed: { tools: Record<string, unknown>; stderr: string };
  try {
    listed = await listDownstreamOnce(spec);
  } catch (err) {
    const stderr = (err as { stderr?: unknown }).stderr;
    if (typeof stderr === "string" && stderr !== "") {
      say(io.out, "child stderr:");
      say(io.out, escapeLine(stderr));
    }
    say(io.out, escapeLine(errorText(err)));
    return 1;
  }
  if (listed.stderr !== "") {
    say(io.out, "child stderr:");
    say(io.out, escapeLine(listed.stderr));
  }
  const tools = listed.tools;
  for (const name of Object.keys(tools).sort()) say(io.out, renderToolEntry(tools[name]));
  showDifference(io.out, spec, tools, dirname(input.file));
  let answer: string;
  try {
    answer = await io.ask();
  } catch (err) {
    say(io.out, escapeLine(errorText(err)));
    return 1;
  }
  if (answer !== "yes") return 1;
  const manifest = { v: 1, prefix: spec.prefix, selected: spec.tools ?? null, tools };
  let written: { ok: true; digest: string } | { ok: false; reason: string };
  try {
    written = writeManifest(dirname(input.file), manifest);
  } catch (err) {
    say(io.out, escapeLine(errorText(err)));
    return 1;
  }
  if (!written.ok) {
    say(io.out, escapeLine(written.reason));
    return 1;
  }
  say(io.out, `"pins": "sha256:${written.digest}"`);
  return 0;
}
