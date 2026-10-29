import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { maskField, type SpanClass } from "@conarium-ai/mask";

import { DEFAULT_SCAN_CHAR_CAP, detectorsFor, SPAN_CLASSES } from "./data-classes.ts";
import { sha256Canonical } from "./hash.ts";
import { terminalText } from "./policy.ts";
import type { DecisionKind } from "@cedulon/core";
import type {
  DecisionInputs,
  MediaConfig,
  Policy,
  Principal,
  ResultClassChoice,
  ResultContent,
  ToolResult,
} from "./types.ts";
import { isMediaContent, isTextContent } from "./types.ts";

/** Text results and error text use Conarium's text pipeline. */
const TEXT_MASK_PIPELINE = "text" as const;
/** Transcripts use its speech pipeline (split digit runs, spoken addresses); its harsher rules would over-mask plain text. */
const TRANSCRIPT_MASK_PIPELINE = "speech" as const;
type MaskPipeline = typeof TEXT_MASK_PIPELINE | typeof TRANSCRIPT_MASK_PIPELINE;

export type ResultRecordWriter = (opts: {
  decision: DecisionKind;
  reasonCode: string;
  ref: string;
  requestHash: string;
  inputs: DecisionInputs;
  effectHash: string | null;
  subject: string;
  timestampMs: number;
}) => Promise<void>;

export type ResultMasker = typeof maskField;

export type ResultGateDeps = {
  policy: Policy;
  nonce: () => string;
  now: () => number;
  writeRecord: ResultRecordWriter;
  /** Defaults to Conarium's `maskField`. */
  masker?: ResultMasker;
};

function principalOf(principal: Principal): DecisionInputs["principal"] {
  return {
    brain: principal.brain,
    scopes: [...principal.scopes].sort(),
    ...(principal.iss ? { iss: principal.iss } : {}),
    ...(principal.tenant ? { tenant: principal.tenant } : {}),
    ...(principal.org ? { org: principal.org } : {}),
  };
}

function choicesFor(policy: Policy, tool: string): Record<string, ResultClassChoice> {
  if (!policy.resultClasses) return {};
  return { ...policy.resultClasses.document, ...(policy.resultClasses.byTool[tool] ?? {}) };
}

function addCounts(into: Record<string, number>, add: Record<string, number> | undefined): void {
  if (!add) return;
  for (const [key, n] of Object.entries(add)) {
    if (typeof n !== "number" || n <= 0) continue;
    into[key] = (into[key] ?? 0) + n;
  }
}

function compactCounts(counts: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, n] of Object.entries(counts)) {
    if (n > 0) out[key] = n;
  }
  return out;
}

function firstBlocked(
  classes: Record<string, number>,
  choices: Record<string, ResultClassChoice>,
): SpanClass | undefined {
  for (const cls of SPAN_CLASSES) {
    if ((classes[cls] ?? 0) > 0 && choices[cls] === "block") return cls;
  }
  return undefined;
}

function firstBlockChoice(choices: Record<string, ResultClassChoice>): SpanClass | undefined {
  for (const cls of SPAN_CLASSES) {
    if (choices[cls] === "block") return cls;
  }
  return undefined;
}

function blockedOrUnscanned(
  classes: Record<string, number>,
  masked: Record<string, number>,
  choices: Record<string, ResultClassChoice>,
): SpanClass | undefined {
  return firstBlocked(classes, choices) ?? ((masked.whole ?? 0) > 0 ? firstBlockChoice(choices) : undefined);
}

function splitTextForScan(text: string, cap: number): string[] {
  if (text.length <= cap) return [text];
  const lines = text.split("\n");
  const pieces: string[] = [];
  let buf = "";
  for (let i = 0; i < lines.length; i += 1) {
    const chunk = i < lines.length - 1 ? `${lines[i]}\n` : lines[i]!;
    if (buf.length === 0) {
      buf = chunk;
      continue;
    }
    if (buf.length + chunk.length <= cap) {
      buf += chunk;
      continue;
    }
    pieces.push(buf);
    buf = chunk;
  }
  if (buf.length > 0) pieces.push(buf);
  return pieces;
}

function scanText(
  text: string,
  only: SpanClass[],
  cap: number,
  masker: ResultMasker,
  pipeline: MaskPipeline,
  detectors?: { ip: true },
): { text: string; classes: Record<string, number>; masked: Record<string, number> } {
  const pieces = splitTextForScan(text, cap);
  const classes: Record<string, number> = {};
  const masked: Record<string, number> = {};
  const out: string[] = [];
  for (const piece of pieces) {
    const { body, suffix } = dropScanBreak(piece);
    const result = masker(body, {
      pipeline,
      only,
      scanCharCap: cap,
      ...(detectors ? { detectors } : {}),
    });
    out.push(`${result.text}${suffix}`);
    addCounts(classes, result.classes);
    addCounts(masked, result.masked);
  }
  return { text: out.join(""), classes, masked };
}

/** A trailing `\r\n` or `\n` is not part of the line; put back exactly that suffix. */
function dropScanBreak(piece: string): { body: string; suffix: string } {
  if (piece.endsWith("\r\n")) return { body: piece.slice(0, -2), suffix: "\r\n" };
  if (piece.endsWith("\n")) return { body: piece.slice(0, -1), suffix: "\n" };
  return { body: piece, suffix: "" };
}

function audioExt(mimeType: string): string {
  const mime = mimeType.toLowerCase().split(";")[0]!.trim();
  if (mime === "audio/mpeg" || mime === "audio/mp3") return ".mp3";
  if (mime === "audio/wav" || mime === "audio/wave" || mime === "audio/x-wav") return ".wav";
  if (mime === "audio/ogg") return ".ogg";
  if (mime === "audio/webm") return ".webm";
  if (mime === "audio/mp4") return ".m4a";
  return ".bin";
}

function mediaChoice(kind: "audio" | "image", media: MediaConfig | undefined): "allow" | "transcribe" | "withhold" {
  if (kind === "audio") return media?.audio ?? "withhold";
  return media?.image ?? "withhold";
}

function stopTranscriberTree(child: ChildProcess): void {
  if (process.platform !== "win32" && child.pid !== undefined) {
    try {
      process.kill(-child.pid, "SIGKILL");
      return;
    } catch {
      // The pid was not a group leader, or the group was already gone.
    }
  }
  child.kill("SIGKILL");
}

function runTranscriber(
  command: readonly string[],
  file: string,
  timeoutMs: number,
  cap: number,
): Promise<string | null> {
  const args = command.slice(1).map((arg) => (arg.includes("{file}") ? arg.replace("{file}", file) : arg));
  return new Promise((resolve) => {
    let settled = false;
    const finish = (text: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(text);
    };
    let child;
    try {
      child = spawn(command[0]!, args, {
        shell: false,
        windowsHide: true,
        // POSIX: a new group so a timeout can SIGKILL the launcher and what it
        // started. Do not detach on Windows: that takes the child out of
        // node's job object, which is what stops the tree there.
        ...(process.platform === "win32" ? {} : { detached: true }),
      });
    } catch {
      finish(null);
      return;
    }
    let out = "";
    let over = false;
    let timedOut = false;
    const abandon = () => {
      child.stdout?.destroy();
      child.stderr?.destroy();
    };
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      if (settled || over) return;
      out += chunk;
      if (out.length > cap) {
        over = true;
        stopTranscriberTree(child);
        abandon();
        finish(null);
      }
    });
    child.on("error", () => finish(null));
    child.on("close", (code, signal) => {
      if (over || timedOut || signal) {
        finish(null);
        return;
      }
      if (code !== 0) {
        finish(null);
        return;
      }
      const text = out.trim();
      if (text === "" || out.length > cap) {
        finish(null);
        return;
      }
      finish(text);
    });
    const timer = setTimeout(() => {
      timedOut = true;
      stopTranscriberTree(child);
      abandon();
      finish(null);
    }, timeoutMs);
  });
}

async function transcribeBlock(
  data: string,
  mimeType: string,
  media: MediaConfig,
  cap: number,
): Promise<string | null> {
  const transcriber = media.transcriber;
  if (!transcriber) return null;
  const dir = mkdtempSync(join(tmpdir(), "verax-stt-"));
  try {
    if (process.platform !== "win32") chmodSync(dir, 0o700);
    const file = join(dir, `audio${audioExt(mimeType)}`);
    writeFileSync(file, Buffer.from(data, "base64"), { mode: 0o600 });
    return await runTranscriber(transcriber.command, file, transcriber.timeoutMs, cap);
  } catch {
    return null;
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
    } catch {
      process.stderr.write(`verax-proxy: temporary audio not removed: ${terminalText(dir)}\n`);
    }
  }
}

function withheldError(callRef: string): ToolResult {
  return {
    content: [{ type: "text", text: `result-unrecorded:${callRef}` }],
    isError: true,
  };
}

function blockError(cls: string, callRef: string): ToolResult {
  return {
    content: [{ type: "text", text: `withheld:result-class-block:${cls}:${callRef}` }],
    isError: true,
  };
}

function classError(callRef: string): ToolResult {
  return {
    content: [{ type: "text", text: `withheld:result-class-error:${callRef}` }],
    isError: true,
  };
}

type LeavingError = Error & { prefix?: string; tool?: string };

const CLASS_NAME = /^[A-Za-z_$][\w$]{0,63}$/;

/**
 * A new object: the original's prototype (or Error), the masked message, a
 * one-line stack, and `prefix`/`tool` when both are strings. Nothing else
 * is copied — those fields can hold the raw text. The name is the class's,
 * from code, not the error's own `name`, which a tool can set to anything.
 */
function leaveError(original: unknown, message: string): LeavingError {
  try {
    const isErr = original instanceof Error;
    const proto = isErr ? Object.getPrototypeOf(original) : Error.prototype;
    const className: unknown = (proto as { constructor?: { name?: unknown } } | null)?.constructor?.name;
    const name = typeof className === "string" && CLASS_NAME.test(className) ? className : "Error";
    const out = Object.create(proto) as LeavingError;
    Object.defineProperty(out, "name", { configurable: true, writable: true, value: name });
    Object.defineProperty(out, "message", { configurable: true, writable: true, value: message });
    Object.defineProperty(out, "stack", { configurable: true, writable: true, value: `${name}: ${message}` });
    if (isErr) {
      const prefix = (original as { prefix?: unknown }).prefix;
      const tool = (original as { tool?: unknown }).tool;
      if (typeof prefix === "string" && typeof tool === "string") {
        out.prefix = prefix;
        out.tool = tool;
      }
    }
    return out;
  } catch {
    const fallback = new Error(message);
    fallback.stack = `Error: ${message}`;
    return fallback;
  }
}

/**
 * Mask a tool throw the same way as a text block. The `:threw` row is already
 * written over the original payload. Returns a new object so a string, a
 * frozen Error, a stack that was already read, or a stuck cause cannot
 * carry the raw text out. A throw inside this gate becomes
 * `withheld:result-class-error:<ref>`, never the original. The error comes
 * back wrapped, so awaiting the gate cannot adopt a thenable error. Call it
 * only when the policy sets `resultClasses`.
 */
export async function gateThrownError(
  err: unknown,
  tool: string,
  callRef: string,
  resultHash: string,
  principal: Principal,
  deps: ResultGateDeps,
): Promise<{ error: unknown }> {
  const { policy } = deps;
  if (!policy.resultClasses) return { error: err };

  try {
    const choices = choicesFor(policy, tool);
    const only = SPAN_CLASSES.filter((cls) => choices[cls] === "mask");
    const cap = policy.scanCharCap ?? policy.dataClasses?.scanCharCap ?? DEFAULT_SCAN_CHAR_CAP;
    const masker = deps.masker ?? maskField;
    const original = err instanceof Error ? `${err.message}` : String(err);
    let leaving = original;
    let decision: DecisionKind = "allow";
    let reasonCode = "result-classes";
    const masked: Record<string, number> = {};
    let scanFailed = false;

    try {
      const scanned = scanText(original, only, cap, masker, TEXT_MASK_PIPELINE, detectorsFor(choices));
      addCounts(masked, scanned.masked);
      const blocked = blockedOrUnscanned(scanned.classes, scanned.masked, choices);
      if (blocked) {
        leaving = `withheld:result-class-block:${blocked}:${callRef}`;
        decision = "deny";
        reasonCode = `result-class-block:${blocked}`;
      } else {
        leaving = scanned.text;
      }
    } catch {
      scanFailed = true;
      leaving = `withheld:result-class-error:${callRef}`;
      decision = "deny";
      reasonCode = "result-class-error";
    }

    const next = leaveError(err, leaving);
    if (leaving === original && !scanFailed) return { error: next };

    try {
      await deps.writeRecord({
        decision,
        reasonCode,
        ref: deps.nonce(),
        requestHash: resultHash,
        inputs: {
          principal: principalOf(principal),
          inputs: [],
          resultOf: callRef,
          resultClasses: {
            masked: compactCounts(masked),
            transcribed: 0,
            withheld: {},
            returnedHash: sha256Canonical({ error: leaving }),
          },
        },
        effectHash: decision === "deny" ? null : resultHash,
        subject: tool,
        timestampMs: deps.now(),
      });
    } catch {
      return { error: leaveError(err, `result-unrecorded:${callRef}`) };
    }
    return { error: next };
  } catch {
    return { error: leaveError(err, `withheld:result-class-error:${callRef}`) };
  }
}

export async function gateResultClasses(
  result: ToolResult,
  tool: string,
  callRef: string,
  resultHash: string,
  principal: Principal,
  deps: ResultGateDeps,
): Promise<ToolResult> {
  const { policy } = deps;
  if (!policy.resultClasses && !policy.media) return result;

  const choices = choicesFor(policy, tool);
  const only = SPAN_CLASSES.filter((cls) => choices[cls] === "mask");
  const cap = policy.scanCharCap ?? policy.dataClasses?.scanCharCap ?? DEFAULT_SCAN_CHAR_CAP;
  const masker = deps.masker ?? maskField;
  const classCounts: Record<string, number> = {};
  const masked: Record<string, number> = {};
  const withheld: Record<string, number> = {};
  let transcribed = 0;
  let changed = false;
  let scanFailed = false;
  const content: ResultContent[] = [];

  for (const block of result.content) {
    if (isTextContent(block)) {
      if (!policy.resultClasses) {
        content.push(block);
        continue;
      }
      let scanned;
      try {
        scanned = scanText(block.text, only, cap, masker, TEXT_MASK_PIPELINE, detectorsFor(choices));
      } catch {
        scanFailed = true;
        break;
      }
      addCounts(classCounts, scanned.classes);
      addCounts(masked, scanned.masked);
      if (scanned.text !== block.text) changed = true;
      content.push({ type: "text", text: scanned.text });
      continue;
    }
    if (!isMediaContent(block)) continue;
    const choice = mediaChoice(block.type, policy.media);
    if (choice === "allow") {
      content.push(block);
      continue;
    }
    if (block.type === "image" || choice === "withhold") {
      changed = true;
      withheld[block.type] = (withheld[block.type] ?? 0) + 1;
      content.push({ type: "text", text: `[${block.type} withheld]` });
      continue;
    }
    const transcript = await transcribeBlock(block.data, block.mimeType, policy.media!, cap);
    changed = true;
    if (transcript === null) {
      withheld.audio = (withheld.audio ?? 0) + 1;
      content.push({ type: "text", text: "[audio withheld: transcriber-failed]" });
      continue;
    }
    transcribed += 1;
    if (!policy.resultClasses) {
      content.push({ type: "text", text: `[audio transcript] ${transcript}` });
      continue;
    }
    let scanned;
    try {
      scanned = scanText(transcript, only, cap, masker, TRANSCRIPT_MASK_PIPELINE, detectorsFor(choices));
    } catch {
      scanFailed = true;
      break;
    }
    addCounts(classCounts, scanned.classes);
    addCounts(masked, scanned.masked);
    content.push({ type: "text", text: `[audio transcript] ${scanned.text}` });
  }

  const blocked = scanFailed ? undefined : blockedOrUnscanned(classCounts, masked, choices);
  const gated: ToolResult = scanFailed
    ? classError(callRef)
    : blocked
      ? blockError(blocked, callRef)
      : { content, isError: result.isError };
  if (!scanFailed && !blocked && !changed) return result;

  const recordInputs: DecisionInputs = {
    principal: principalOf(principal),
    inputs: [],
    resultOf: callRef,
    resultClasses: {
      masked: compactCounts(masked),
      transcribed,
      withheld: compactCounts(withheld),
      returnedHash: sha256Canonical(gated),
    },
  };
  try {
    await deps.writeRecord({
      decision: scanFailed || blocked ? "deny" : "allow",
      reasonCode: scanFailed
        ? "result-class-error"
        : blocked
          ? `result-class-block:${blocked}`
          : "result-classes",
      ref: deps.nonce(),
      requestHash: resultHash,
      inputs: recordInputs,
      // Cedulon refuses an allow with a null effectHash (`allow-requires-effect-hash`).
      // The hash is the same resultHash the effect row already stored.
      effectHash: scanFailed || blocked ? null : resultHash,
      subject: tool,
      timestampMs: deps.now(),
    });
  } catch {
    return withheldError(callRef);
  }
  return gated;
}
