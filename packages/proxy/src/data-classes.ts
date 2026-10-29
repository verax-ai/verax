import { maskField, type SpanClass } from "@conarium-ai/mask";
import { sha256Canonical } from "./hash.ts";
import type { DataClassChoice, DataClassConfig, ToolCall } from "./types.ts";

/** Detector class names, in the order a block or local deny names the first hit. */
export const SPAN_CLASSES: readonly SpanClass[] = [
  "email",
  "entity-email",
  "phone",
  "tckn",
  "card",
  "ssn",
  "iban",
  "mrz",
  "ip",
  "secret",
  "connection",
  "bearer",
  "labelled-secret",
  "name",
  "embedded",
  "custom",
];

const SPAN_CLASS_SET = new Set<string>(SPAN_CLASSES);
const CHOICES = new Set<string>(["allow", "mask", "local", "block"]);
/** Conarium's default when the policy does not set `scanCharCap`. */
export const DEFAULT_SCAN_CHAR_CAP = 16_384;
/** Nested objects or arrays deeper than this cannot be hashed or scanned safely. */
export const MAX_ARGUMENT_DEPTH = 64;

export type DataClassGateResult =
  | { action: "unchanged" }
  | { action: "deny"; reasonCode: string }
  | {
      action: "forward";
      arguments: Record<string, unknown>;
      dataClasses: { masked: Record<string, number>; forwardedHash: string };
    };

export function parseDataClassMap(raw: unknown): Record<string, DataClassChoice> {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("policy-data-class-unknown");
  }
  const out: Record<string, DataClassChoice> = {};
  for (const [name, choice] of Object.entries(raw as Record<string, unknown>)) {
    if (!SPAN_CLASS_SET.has(name)) throw new Error(`policy-data-class-unknown:${name}`);
    if (typeof choice !== "string" || !CHOICES.has(choice)) {
      throw new Error(`policy-data-class-choice:${name}`);
    }
    out[name] = choice as DataClassChoice;
  }
  return out;
}

export function dataClassMapHasLocal(
  map: Readonly<Record<string, DataClassChoice>> | undefined,
): boolean {
  if (!map) return false;
  return Object.values(map).some((choice) => choice === "local");
}

const FILE_TYPE_TOKEN_SPLIT = /[\s"'`,;|&<>()[\]{}$=]+/;

function lastMeaningfulSegment(text: string): string | undefined {
  const trimmed = text.replace(/[/\\]+$/u, "");
  const parts = trimmed.split(/[/\\]/).filter((seg) => seg !== "" && seg !== "." && seg !== "..");
  return parts.length === 0 ? undefined : parts[parts.length - 1];
}

function cutQueryAndFragment(text: string): string {
  const cut = text.search(/[?#]/);
  return cut === -1 ? text : text.slice(0, cut);
}

function decodeWherePossible(text: string): string {
  return text.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

function decodeCandidates(text: string): string[] {
  const out = [text];
  const partial = decodeWherePossible(text);
  if (partial !== text) out.push(partial);
  try {
    const full = decodeURIComponent(text);
    if (full !== text && full !== partial) out.push(full);
  } catch {
    // Malformed escape: keep the original and the partial decode.
  }
  return out;
}

function ntfsNameCandidates(segment: string): string[] {
  const colon = segment.indexOf(":");
  if (colon === -1) return [segment];
  const parts = segment.split(":");
  return [parts[0] ?? "", ...parts.slice(1), segment];
}

function trimTrailingDotsAndSpaces(text: string): string {
  return text.replace(/[.\s]+$/u, "");
}

function nameHasListedExtension(name: string, listed: string): boolean {
  const lower = name.toLowerCase();
  const ext = listed.toLowerCase();
  return lower.length >= ext.length && lower.endsWith(ext);
}

function blockedFileTypeInToken(text: string, blocked: readonly string[]): string | undefined {
  const stripped = cutQueryAndFragment(text);
  for (const candidate of decodeCandidates(stripped)) {
    const segment = lastMeaningfulSegment(cutQueryAndFragment(candidate));
    if (segment === undefined) continue;
    for (const raw of ntfsNameCandidates(segment)) {
      const name = trimTrailingDotsAndSpaces(raw);
      if (name === "" || name === "." || name === "..") continue;
      for (const listed of blocked) {
        if (nameHasListedExtension(name, listed)) return listed;
      }
    }
  }
  return undefined;
}

function blockedFileType(text: string, blocked: readonly string[]): string | undefined {
  if (blocked.length === 0) return undefined;
  const tokens = text.split(FILE_TYPE_TOKEN_SPLIT).filter((token) => token.length > 0);
  for (const token of tokens) {
    const hit = blockedFileTypeInToken(token, blocked);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

function restrictsChoices(choices: Record<string, DataClassChoice>): boolean {
  return Object.values(choices).some((choice) => choice === "mask" || choice === "block" || choice === "local");
}

function firstBlockedFileType(value: unknown, blocked: readonly string[]): string | undefined {
  if (blocked.length === 0) return undefined;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (typeof cur === "string") {
      const hit = blockedFileType(cur, blocked);
      if (hit !== undefined) return hit;
      continue;
    }
    if (Array.isArray(cur)) {
      for (const item of cur) stack.push(item);
      continue;
    }
    if (cur !== null && typeof cur === "object") {
      const rec = cur as Record<string, unknown>;
      for (const key of Object.keys(rec)) {
        const keyHit = blockedFileType(key, blocked);
        if (keyHit !== undefined) return keyHit;
        stack.push(rec[key]);
      }
    }
  }
  return undefined;
}

function addCounts(into: Record<string, number>, add: Record<string, number> | undefined): void {
  if (!add) return;
  for (const [key, n] of Object.entries(add)) {
    if (typeof n !== "number" || n <= 0) continue;
    into[key] = (into[key] ?? 0) + n;
  }
}

function choicesFor(config: DataClassConfig, tool: string): Record<string, DataClassChoice> {
  return { ...config.document, ...(config.byTool[tool] ?? {}) };
}

/** Conarium leaves the IP detector off unless the operator names `ip`. */
export function detectorsFor(choices: Readonly<Record<string, unknown>>): { ip: true } | undefined {
  return choices.ip !== undefined ? { ip: true } : undefined;
}

function asDecimalString(value: number | bigint): string {
  return typeof value === "bigint" ? value.toString(10) : value.toString(10);
}

/** Iterative depth of objects and arrays. Leaves are the depth they sit at. */
export function argumentDepth(value: unknown): number {
  let max = 0;
  const stack: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const frame = stack.pop()!;
    if (frame.depth > max) max = frame.depth;
    if (frame.depth > MAX_ARGUMENT_DEPTH) return frame.depth;
    const cur = frame.value;
    if (cur === null || typeof cur !== "object") continue;
    const next = frame.depth + 1;
    if (Array.isArray(cur)) {
      for (const item of cur) stack.push({ value: item, depth: next });
    } else {
      for (const child of Object.values(cur as Record<string, unknown>)) {
        stack.push({ value: child, depth: next });
      }
    }
  }
  return max;
}

function restrictedClass(
  classes: Record<string, number> | undefined,
  choices: Record<string, DataClassChoice>,
): SpanClass | undefined {
  if (!classes) return undefined;
  for (const cls of SPAN_CLASSES) {
    if ((classes[cls] ?? 0) > 0 && choices[cls] !== undefined && choices[cls] !== "allow") {
      return cls;
    }
  }
  return undefined;
}

/**
 * Scan Verax's own `_ref` / `_inputs` (ids, sources, every nested string).
 * A class whose choice is not `allow` is `data-class-meta:<class>`.
 */
export function scanCallMeta(call: ToolCall, config: DataClassConfig): string | null {
  const choices = choicesFor(config, call.name);
  if (!restrictsChoices(choices)) return null;
  const args = call.arguments;
  const effectiveCap = config.scanCharCap ?? DEFAULT_SCAN_CHAR_CAP;
  const detectors = detectorsFor(choices);
  const opts = {
    pipeline: "text" as const,
    only: [] as SpanClass[],
    ...(detectors ? { detectors } : {}),
    ...(config.scanCharCap !== undefined ? { scanCharCap: config.scanCharCap } : {}),
  };

  const hitIn = (text: string): string | null => {
    try {
      const result = maskField(text, opts);
      const cls = restrictedClass(result.classes, choices);
      if (cls) return `data-class-meta:${cls}`;
      if (couldNotScan(text, result, effectiveCap)) return "data-class-unscanned";
      return null;
    } catch {
      return "data-class-error";
    }
  };

  const walkMeta = (value: unknown): string | null => {
    const stack: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
    while (stack.length > 0) {
      const frame = stack.pop()!;
      if (frame.depth > MAX_ARGUMENT_DEPTH) return "data-class-unscanned";
      const cur = frame.value;
      if (typeof cur === "string") {
        const hit = hitIn(cur);
        if (hit) return hit;
        continue;
      }
      if (typeof cur === "number" || typeof cur === "bigint") {
        const hit = hitIn(asDecimalString(cur));
        if (hit) return hit;
        continue;
      }
      if (cur === null || typeof cur !== "object") continue;
      const next = frame.depth + 1;
      if (Array.isArray(cur)) {
        for (const item of cur) stack.push({ value: item, depth: next });
        continue;
      }
      const rec = cur as Record<string, unknown>;
      for (const key of Object.keys(rec)) {
        const keyHit = hitIn(key);
        if (keyHit) return keyHit;
        stack.push({ value: rec[key], depth: next });
      }
    }
    return null;
  };

  if (Object.prototype.hasOwnProperty.call(args, "_ref")) {
    const hit = walkMeta(args._ref);
    if (hit) return hit;
  }
  if (Object.prototype.hasOwnProperty.call(args, "_inputs")) {
    const hit = walkMeta(args._inputs);
    if (hit) return hit;
  }
  return null;
}

type ScanKind = "value" | "key" | "number";

type ScanState = {
  classCounts: Record<string, number>;
  masked: Record<string, number>;
  keyClasses: Record<string, number>;
  fileType: string | undefined;
  error: string | null;
};

function couldNotScan(
  text: string,
  result: { masked: Record<string, number> },
  cap: number,
): boolean {
  return (result.masked.whole ?? 0) > 0 || text.length > cap;
}

export function gateDataClasses(
  call: ToolCall,
  config: DataClassConfig | undefined,
): DataClassGateResult {
  if (!config) return { action: "unchanged" };
  const choices = choicesFor(config, call.name);
  if (!restrictsChoices(choices)) {
    const fileType = firstBlockedFileType(call.arguments, config.blockedFileTypes);
    if (fileType !== undefined) return { action: "deny", reasonCode: `file-type-block:${fileType}` };
    return { action: "unchanged" };
  }
  const only = SPAN_CLASSES.filter((cls) => choices[cls] === "mask");
  const hasBlockOrLocal = SPAN_CLASSES.some(
    (cls) => choices[cls] === "block" || choices[cls] === "local",
  );
  const effectiveCap = config.scanCharCap ?? DEFAULT_SCAN_CHAR_CAP;
  const detectors = detectorsFor(choices);
  const opts = {
    pipeline: "text" as const,
    only,
    ...(detectors ? { detectors } : {}),
    ...(config.scanCharCap !== undefined ? { scanCharCap: config.scanCharCap } : {}),
  };
  const state: ScanState = {
    classCounts: {},
    masked: {},
    keyClasses: {},
    fileType: undefined,
    error: null,
  };

  const scanText = (text: string, kind: ScanKind): string => {
    if (state.fileType === undefined) {
      state.fileType = blockedFileType(text, config.blockedFileTypes);
    }
    try {
      const result = maskField(text, opts);
      addCounts(state.classCounts, result.classes);
      if (kind === "key") addCounts(state.keyClasses, result.classes);
      else addCounts(state.masked, result.masked);
      const unscanned = couldNotScan(text, result, effectiveCap);
      if (unscanned && state.error === null) {
        // A key cannot be rewritten; an unscanned key is always a deny.
        // A value the masker could not scan, while any class is block or
        // local, is a deny even if another class is mask.
        if (kind === "key" || hasBlockOrLocal) {
          state.error = "data-class-unscanned";
        }
      }
      // Keys cannot be rewritten; values (and numbers) take the engine's text,
      // which is the whole-field label when the string could not be scanned.
      return kind === "key" ? text : result.text;
    } catch {
      if (state.error === null) state.error = "data-class-error";
      return text;
    }
  };

  const walk = (value: unknown, depth: number): unknown => {
    if (depth > MAX_ARGUMENT_DEPTH) {
      if (state.error === null) state.error = "data-class-unscanned";
      return value;
    }
    if (typeof value === "string") return scanText(value, "value");
    if (typeof value === "number" || typeof value === "bigint") {
      const text = asDecimalString(value);
      const replaced = scanText(text, "number");
      return replaced === text ? value : replaced;
    }
    if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1));
    if (value !== null && typeof value === "object") {
      const src = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(src)) {
        scanText(key, "key");
        out[key] = walk(src[key], depth + 1);
      }
      return out;
    }
    return value;
  };

  const argumentsOut = walk(call.arguments, 0) as Record<string, unknown>;

  if (state.fileType !== undefined) {
    return { action: "deny", reasonCode: `file-type-block:${state.fileType}` };
  }
  if (state.error !== null) return { action: "deny", reasonCode: state.error };

  for (const cls of SPAN_CLASSES) {
    if (choices[cls] === "block" && (state.classCounts[cls] ?? 0) > 0) {
      return { action: "deny", reasonCode: `data-class-block:${cls}` };
    }
  }
  for (const cls of SPAN_CLASSES) {
    if (
      choices[cls] === "local" &&
      (state.classCounts[cls] ?? 0) > 0 &&
      !config.localTools.includes(call.name)
    ) {
      return { action: "deny", reasonCode: `data-class-local:${cls}` };
    }
  }
  for (const cls of SPAN_CLASSES) {
    if (choices[cls] === "mask" && (state.keyClasses[cls] ?? 0) > 0) {
      return { action: "deny", reasonCode: `data-class-key:${cls}` };
    }
  }

  return {
    action: "forward",
    arguments: argumentsOut,
    dataClasses: {
      masked: state.masked,
      forwardedHash: sha256Canonical({ name: call.name, arguments: argumentsOut }),
    },
  };
}
