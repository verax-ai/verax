import { parseIJson } from "@cedulon/core";
import { dataClassMapHasLocal, parseDataClassMap } from "./data-classes.ts";
import { defaultDiskFreeBytes } from "./disk.ts";
import { sha256Canonical } from "./hash.ts";
import type { DataClassChoice, Policy, PolicyDecision, PolicyEvalCtx, PolicyLimits, Principal, ToolCall } from "./types.ts";

export type PolicySpend = {
  maxAmountMinor: number;
  currency: string;
  payees: readonly string[];
  dailyMaxMinor?: number;
  /**
   * Minutes added to `createdAtMs` before the UTC day bucket.
   * 0 is UTC. −720..840 covers the offsets an operator's clock can sit in.
   */
  dayOffsetMinutes?: number;
  /** Statement stamps for this payee. Optional; never guessed. */
  descriptors?: readonly string[];
};

export type PolicyRule = {
  id: string;
  tool: string;
  requires: readonly string[];
  text: string;
  mode?: "allow" | "approve";
  spend?: PolicySpend;
  egress?: true;
  dataClasses?: Readonly<Record<string, DataClassChoice>>;
};

export type PolicyDocument = {
  version: 1 | 2;
  default: "deny";
  approvalTtlMs?: number;
  egress?: readonly string[];
  /** Body-wide: a call with no `_inputs` key, or an empty list, is deny inputs-required. */
  requireInputs?: true;
  limits?: {
    ratePerMinute?: number;
    dailyMax?: number;
    diskFreeBytes?: number;
  };
  dataClasses?: Readonly<Record<string, DataClassChoice>>;
  localTools?: readonly string[];
  fileTypes?: { block: readonly string[] };
  scanCharCap?: number;
  rules: PolicyRule[];
};

/** One DNS label: letters, digits, hyphens; no leading or trailing hyphen. */
function plainDnsLabel(label: string): boolean {
  if (label.length === 0 || label.length > 63) return false;
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
}

/** A hostname and nothing else: no port, path, whitespace, or trailing dot. */
function plainDnsHost(host: string): string | undefined {
  if (host.length === 0 || host.length > 253) return undefined;
  const labels = host.split(".");
  if (labels.length === 0 || labels.some((label) => !plainDnsLabel(label))) return undefined;
  return host.toLowerCase();
}

/**
 * `to` is one address. More than one `@`, a local part that carries a list
 * separator or whitespace, or a host that is not a plain DNS name yields no
 * host, and the egress rule then denies `egress-host-missing`.
 */
function hasControl(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

function messageSendHost(args: Record<string, unknown>): string | undefined {
  const to = args.to;
  if (typeof to !== "string" || to === "") return undefined;
  const at = to.indexOf("@");
  if (at <= 0 || at !== to.lastIndexOf("@")) return undefined;
  const local = to.slice(0, at);
  const host = to.slice(at + 1);
  if (local === "" || /[\s,;<>"]/.test(local) || hasControl(local)) return undefined;
  return plainDnsHost(host);
}

/** Named per tool. Do not sniff `host` / `url` on arbitrary arguments. */
export const HOST_EXTRACTORS: Record<string, (args: Record<string, unknown>) => string | undefined> = {
  "message.send": messageSendHost,
};

const DEFAULT_APPROVAL_TTL_MS = 86_400_000;

const DOCUMENT_KEYS = new Set(["version", "default", "rules", "egress", "approvalTtlMs", "limits", "requireInputs"]);
const DOCUMENT_KEYS_V2 = new Set([...DOCUMENT_KEYS, "dataClasses", "localTools", "fileTypes", "scanCharCap"]);
const RULE_KEYS = new Set(["id", "tool", "requires", "text", "mode", "spend", "egress"]);
const RULE_KEYS_V2 = new Set([...RULE_KEYS, "dataClasses"]);
const SPEND_KEYS = new Set(["maxAmountMinor", "currency", "payees", "dailyMaxMinor", "dayOffsetMinutes", "descriptors"]);
const LIMIT_KEYS = new Set(["ratePerMinute", "dailyMax", "diskFreeBytes"]);

export type PolicyParseOptions = {
  /**
   * "refuse" (the default) for a policy an operator is loading: a misspelt
   * control would otherwise leave the policy weaker than the file reads.
   * "ignore" only for a snapshot already on disk, written by a release that
   * dropped unknown keys; its hash was taken without them.
   */
  unknownKeys?: "refuse" | "ignore";
};

function rejectUnknownKeys(
  rec: Record<string, unknown>,
  known: ReadonlySet<string>,
  code: string,
  options: PolicyParseOptions,
): void {
  if (options.unknownKeys === "ignore") return;
  for (const key of Object.keys(rec)) {
    if (!known.has(key)) throw new Error(`${code}:${key}`);
  }
}

function asRule(raw: unknown, index: number, options: PolicyParseOptions, version: 1 | 2): PolicyRule {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`policy-rule-invalid:${index}`);
  }
  const rec = raw as Record<string, unknown>;
  if (typeof rec.id !== "string" || rec.id === "") {
    throw new Error(`policy-rule-id:${index}`);
  }
  rejectUnknownKeys(rec, version === 2 ? RULE_KEYS_V2 : RULE_KEYS, `policy-rule-unknown-key:${rec.id}`, options);
  if (typeof rec.tool !== "string" || rec.tool === "") {
    throw new Error(`policy-rule-tool:${rec.id}`);
  }
  if (!Array.isArray(rec.requires) || rec.requires.some((s) => typeof s !== "string" || s === "")) {
    throw new Error(`policy-rule-requires:${rec.id}`);
  }
  if (typeof rec.text !== "string" || rec.text.trim() === "") {
    throw new Error(`policy-rule-text:${rec.id}`);
  }
  const rule: PolicyRule = {
    id: rec.id,
    tool: rec.tool,
    requires: rec.requires as string[],
    text: rec.text,
  };
  if (rec.mode !== undefined) {
    if (rec.mode !== "allow" && rec.mode !== "approve") {
      throw new Error(`policy-rule-mode:${rec.id}`);
    }
    rule.mode = rec.mode;
  }
  if (rec.tool === "spend") {
    if (rule.mode !== "approve") {
      throw new Error(`policy-rule-spend-mode:${rec.id}`);
    }
    if (rec.spend === undefined) {
      throw new Error(`policy-rule-spend-missing:${rec.id}`);
    }
    rule.spend = asSpend(rec.spend, rec.id, options);
  } else if (rec.spend !== undefined && options.unknownKeys !== "ignore") {
    // The gate reads a spend block on the spend tool only. On any other rule it
    // would set no cap and stay out of the policy hash, so the file does not load.
    throw new Error(`policy-rule-spend-not-spend-tool:${rec.id}`);
  }
  if (rec.egress !== undefined) {
    if (rec.egress !== true) {
      throw new Error(`policy-rule-egress:${rec.id}`);
    }
    // The gate decides `spend` by payee and amount and returns before it looks
    // at a host. A mark there would read as a host check that never runs.
    if (rec.tool === "spend" && options.unknownKeys !== "ignore") {
      throw new Error(`policy-rule-egress-on-spend:${rec.id}`);
    }
    rule.egress = true;
  } else if (options.unknownKeys !== "ignore" && Object.hasOwn(HOST_EXTRACTORS, rec.tool)) {
    // The gate reads this tool's host, and only under the mark. Without it
    // the call would reach any host, so the rule does not load.
    throw new Error(`policy-rule-egress-unmarked:${rec.id}`);
  }
  if (version === 2 && rec.dataClasses !== undefined) {
    rule.dataClasses = parseDataClassMap(rec.dataClasses);
  }
  return rule;
}

function asSpend(raw: unknown, id: string, options: PolicyParseOptions): PolicySpend {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  const rec = raw as Record<string, unknown>;
  rejectUnknownKeys(rec, SPEND_KEYS, `policy-rule-spend-unknown-key:${id}`, options);
  if (
    typeof rec.maxAmountMinor !== "number" ||
    !Number.isInteger(rec.maxAmountMinor) ||
    rec.maxAmountMinor <= 0
  ) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  if (typeof rec.currency !== "string" || !/^[A-Z]{3}$/.test(rec.currency)) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  if (!Array.isArray(rec.payees) || rec.payees.length === 0 || rec.payees.some((p) => typeof p !== "string" || p === "")) {
    throw new Error(`policy-rule-spend-missing:${id}`);
  }
  const spend: PolicySpend = {
    maxAmountMinor: rec.maxAmountMinor,
    currency: rec.currency,
    payees: rec.payees as string[],
  };
  if (rec.dailyMaxMinor !== undefined) {
    if (typeof rec.dailyMaxMinor !== "number" || !Number.isInteger(rec.dailyMaxMinor) || rec.dailyMaxMinor <= 0) {
      throw new Error(`policy-rule-spend-missing:${id}`);
    }
    spend.dailyMaxMinor = rec.dailyMaxMinor;
  }
  if (rec.dayOffsetMinutes !== undefined) {
    if (
      typeof rec.dayOffsetMinutes !== "number" ||
      !Number.isInteger(rec.dayOffsetMinutes) ||
      rec.dayOffsetMinutes < -720 ||
      rec.dayOffsetMinutes > 840
    ) {
      throw new Error(`policy-rule-spend-day-offset:${id}`);
    }
    spend.dayOffsetMinutes = rec.dayOffsetMinutes;
  }
  if (rec.descriptors !== undefined) {
    if (
      !Array.isArray(rec.descriptors) ||
      rec.descriptors.length === 0 ||
      rec.descriptors.some((d) => typeof d !== "string" || d === "")
    ) {
      throw new Error(`policy-rule-spend-descriptors:${id}`);
    }
    spend.descriptors = rec.descriptors as string[];
  }
  return spend;
}

/**
 * What the spend gate refuses in payee, reference and currency: every
 * control (Cc, C0 and C1), every format character (Cf: bidi, ZWJ/ZWNJ,
 * U+FEFF), and the line and paragraph separators (Zl, Zp).
 */
export const TERMINAL_CONTROL_CLASS = "\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}";

/**
 * What the three operator screens show as the text itself: the approve
 * prompt, the pin listing, and the door page. Past control and format
 * characters, a combining mark draws over the character before it, and an
 * unassigned or private-use code point has no glyph to rely on. A surrogate
 * is not a character. Text for the inside of a character class: the
 * spend-gate class, plus default-ignorable code points, variation selectors,
 * the braille blank (U+2800), every space separator except U+0020, combining
 * marks (M), unassigned code points (Cn), private-use code points (Co), and
 * surrogates (Cs).
 * Turkish and Latin letters arrive as one code point (NFC) and are left as
 * they are. Writing that uses combining marks (Hindi, Thai, and the like)
 * is shown escaped on these screens. The bytes that were recorded do not
 * change.
 */
export const DISPLAY_ESCAPE_CLASS =
  `${TERMINAL_CONTROL_CLASS}\\p{Default_Ignorable_Code_Point}\\p{Variation_Selector}` +
  "\\u2800\\u00A0\\u1680\\u2000-\\u200A\\u202F\\u205F\\u3000\\p{M}\\p{Cn}\\p{Co}\\p{Cs}";

const DISPLAY_ESCAPE = new RegExp(`[${DISPLAY_ESCAPE_CLASS}]`, "gu");

function escapeDisplayUnit(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  if (cp <= 0xffff) return `\\u${cp.toString(16).padStart(4, "0")}`;
  const rest = cp - 0x10000;
  const high = 0xd800 + (rest >> 10);
  const low = 0xdc00 + (rest & 0x3ff);
  return `\\u${high.toString(16).padStart(4, "0")}\\u${low.toString(16).padStart(4, "0")}`;
}

/**
 * Printed form of text this process did not write. Same `\uXXXX` per UTF-16
 * unit as the pin listing, but no added quotes and no doubled backslash: a
 * Windows path in a diagnostic line stays readable. Escape only at the
 * write. The thrown message is what the ledger and the agent still receive.
 */
export function terminalText(text: string): string {
  return text.replace(DISPLAY_ESCAPE, escapeDisplayUnit);
}

/** Line breaks the body wrote on purpose stay; every other class member is escaped. */
export function terminalLines(text: string): string {
  return text.split("\n").map((line) => terminalText(line)).join("\n");
}

const SPEND_CONTROL = new RegExp(`[${TERMINAL_CONTROL_CLASS}]`, "u");

function spendArgsInvalid(args: Record<string, unknown>): boolean {
  const keys = Object.keys(args);
  const allowed = new Set(["amountMinor", "currency", "payee", "reference"]);
  if (keys.length !== 4 || keys.some((k) => !allowed.has(k))) return true;
  const amt = args.amountMinor;
  if (typeof amt !== "number" || !Number.isInteger(amt) || amt <= 0) return true;
  if (typeof args.currency !== "string" || !/^[A-Z]{3}$/.test(args.currency)) return true;
  if (typeof args.payee !== "string" || args.payee === "" || SPEND_CONTROL.test(args.payee)) return true;
  if (typeof args.reference !== "string" || args.reference.length > 140 || SPEND_CONTROL.test(args.reference)) return true;
  if (SPEND_CONTROL.test(args.currency)) return true;
  return false;
}

export function parsePolicyDocument(json: unknown, options: PolicyParseOptions = {}): PolicyDocument {
  const raw = typeof json === "string" ? parseIJson(json) : json;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("policy-not-object");
  }
  const rec = raw as Record<string, unknown>;
  const version: 1 | 2 | undefined = rec.version === 2 ? 2 : rec.version === 1 ? 1 : undefined;
  if (version === 2) {
    rejectUnknownKeys(rec, DOCUMENT_KEYS_V2, "policy-unknown-key", options);
  } else {
    rejectUnknownKeys(rec, DOCUMENT_KEYS, "policy-unknown-key", options);
    if (version !== 1) {
      throw new Error("policy-version");
    }
  }
  if (rec.default !== "deny") {
    throw new Error("policy-default-not-deny");
  }
  if (!Array.isArray(rec.rules)) {
    throw new Error("policy-rules");
  }
  const document: PolicyDocument = {
    version: version ?? 1,
    default: "deny",
    rules: rec.rules.map((rule, index) => asRule(rule, index, options, version ?? 1)),
  };
  if (rec.egress !== undefined) {
    if (
      !Array.isArray(rec.egress) ||
      rec.egress.some((h) => typeof h !== "string" || h.trim() === "")
    ) {
      throw new Error("policy-egress");
    }
    // Only a marked rule for a tool whose host the gate reads uses the list. A
    // file that names hosts and has no such rule would restrict less than it
    // reads, so it does not load. A mark on a tool with no host reader refuses
    // every call to it and reads no list.
    if (
      options.unknownKeys !== "ignore" &&
      !document.rules.some((rule) => rule.egress === true && Object.hasOwn(HOST_EXTRACTORS, rule.tool))
    ) {
      throw new Error("policy-egress-unused");
    }
    document.egress = rec.egress as string[];
  }
  if (rec.approvalTtlMs !== undefined) {
    if (typeof rec.approvalTtlMs !== "number" || !Number.isFinite(rec.approvalTtlMs) || rec.approvalTtlMs < 0) {
      throw new Error("policy-approval-ttl");
    }
    document.approvalTtlMs = rec.approvalTtlMs;
  }
  if (rec.limits !== undefined) {
    document.limits = asLimits(rec.limits, options);
  }
  if (rec.requireInputs !== undefined) {
    if (rec.requireInputs !== true) {
      throw new Error("policy-require-inputs");
    }
    document.requireInputs = true;
  }
  if (version === 2) {
    if (rec.dataClasses !== undefined) {
      document.dataClasses = parseDataClassMap(rec.dataClasses);
    }
    if (rec.localTools !== undefined) {
      document.localTools = asLocalTools(rec.localTools);
    }
    if (rec.fileTypes !== undefined) {
      document.fileTypes = asFileTypes(rec.fileTypes);
    }
    if (rec.scanCharCap !== undefined) {
      if (
        typeof rec.scanCharCap !== "number" ||
        !Number.isInteger(rec.scanCharCap) ||
        rec.scanCharCap <= 0
      ) {
        throw new Error("policy-scan-char-cap");
      }
      document.scanCharCap = rec.scanCharCap;
    }
    const localUsed =
      dataClassMapHasLocal(document.dataClasses) ||
      document.rules.some((rule) => dataClassMapHasLocal(rule.dataClasses));
    if (localUsed && (document.localTools === undefined || document.localTools.length === 0)) {
      throw new Error("policy-data-class-local-tools");
    }
  }
  rejectDuplicateRules(document.rules);
  return document;
}

function asLocalTools(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.some((t) => typeof t !== "string" || t === "")) {
    throw new Error("policy-data-class-local-tools");
  }
  return raw as string[];
}

function asFileTypes(raw: unknown): { block: string[] } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("policy-file-types");
  }
  const rec = raw as Record<string, unknown>;
  for (const key of Object.keys(rec)) {
    if (key !== "block") throw new Error("policy-file-types");
  }
  if (!Array.isArray(rec.block)) throw new Error("policy-file-types");
  for (const ext of rec.block) {
    if (typeof ext !== "string" || !ext.startsWith(".") || ext !== ext.toLowerCase() || ext.length < 2) {
      throw new Error("policy-file-types");
    }
  }
  return { block: rec.block as string[] };
}

function rejectDuplicateRules(rules: readonly PolicyRule[]): void {
  const seenId = new Set<string>();
  const toolOwner = new Map<string, string>();
  for (const rule of rules) {
    if (seenId.has(rule.id)) {
      throw new Error(`duplicate rule id ${rule.id} and ${rule.id}`);
    }
    seenId.add(rule.id);
    const prior = toolOwner.get(rule.tool);
    if (prior !== undefined) {
      throw new Error(`duplicate rule for tool ${rule.tool}: ${prior} and ${rule.id}`);
    }
    toolOwner.set(rule.tool, rule.id);
  }
}

function asLimits(raw: unknown, options: PolicyParseOptions): NonNullable<PolicyDocument["limits"]> {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("policy-limits");
  }
  const rec = raw as Record<string, unknown>;
  rejectUnknownKeys(rec, LIMIT_KEYS, "policy-limits-unknown-key", options);
  const limits: NonNullable<PolicyDocument["limits"]> = {};
  for (const key of ["ratePerMinute", "dailyMax", "diskFreeBytes"] as const) {
    if (rec[key] === undefined) continue;
    const n = rec[key];
    if (typeof n !== "number" || !Number.isInteger(n) || n <= 0) {
      throw new Error("policy-limits");
    }
    limits[key] = n;
  }
  return limits;
}

export function ruleTextHash(text: string): string {
  return sha256Canonical(text);
}

export function loadPolicy(json: unknown, options: PolicyParseOptions = {}): Policy {
  const document = parsePolicyDocument(json, options);
  const hash = sha256Canonical(document);
  const limits: PolicyLimits = {
    diskFreeBytes: document.limits?.diskFreeBytes ?? defaultDiskFreeBytes(),
    ...(document.limits?.ratePerMinute !== undefined ? { ratePerMinute: document.limits.ratePerMinute } : {}),
    ...(document.limits?.dailyMax !== undefined ? { dailyMax: document.limits.dailyMax } : {}),
  };
  const spendRule = document.rules.find((rule) => rule.tool === "spend");
  // Only a spend rule carries a parsed spend block, so these are the descriptors the hash covers.
  const descriptorsByPayee: Record<string, readonly string[]> = {};
  for (const rule of document.rules) {
    if (rule.tool !== "spend" || !rule.spend?.descriptors) continue;
    for (const payee of rule.spend.payees) descriptorsByPayee[payee] = rule.spend.descriptors;
  }
  return {
    hash,
    descriptorsByPayee,
    dayOffsetMinutes: spendRule?.spend?.dayOffsetMinutes ?? 0,
    approvalTtlMs: document.approvalTtlMs ?? DEFAULT_APPROVAL_TTL_MS,
    limits,
    ...(document.requireInputs ? { requireInputs: true as const } : {}),
    ...(document.version === 2
      ? {
          dataClasses: {
            document: document.dataClasses ?? {},
            byTool: Object.fromEntries(
              document.rules
                .filter((rule) => rule.dataClasses !== undefined)
                .map((rule) => [rule.tool, rule.dataClasses!]),
            ),
            localTools: document.localTools ?? [],
            blockedFileTypes: [...(document.fileTypes?.block ?? [])],
            ...(document.scanCharCap !== undefined ? { scanCharCap: document.scanCharCap } : {}),
          },
        }
      : {}),
    rule(id: string | null) {
      if (id === null) return null;
      const found = document.rules.find((r) => r.id === id);
      return found
        ? {
            id: found.id,
            text: found.text,
            ...(found.spend
              ? {
                  spend: {
                    ...(found.spend.dailyMaxMinor !== undefined ? { dailyMaxMinor: found.spend.dailyMaxMinor } : {}),
                    dayOffsetMinutes: found.spend.dayOffsetMinutes ?? 0,
                  },
                }
              : {}),
          }
        : null;
    },
    evaluate(call: ToolCall, principal: Principal, ctx?: PolicyEvalCtx): PolicyDecision {
      if (call.name === "pay") {
        return { decision: "deny", reasonCode: "spend-not-wired", rule: null };
      }
      if (call.name === "spend") {
        const rule = document.rules.find((r) => r.tool === "spend");
        if (!rule || !rule.spend) {
          return { decision: "deny", reasonCode: "spend-not-wired", rule: null };
        }
        for (const scope of rule.requires) {
          if (!principal.scopes.has(scope)) {
            return { decision: "deny", reasonCode: "scope-missing", rule: rule.id };
          }
        }
        if (spendArgsInvalid(call.arguments)) {
          return { decision: "deny", reasonCode: "spend-args-invalid", rule: rule.id };
        }
        const amountMinor = call.arguments.amountMinor as number;
        const currency = call.arguments.currency as string;
        const payee = call.arguments.payee as string;
        if (currency !== rule.spend.currency) {
          return { decision: "deny", reasonCode: "spend-currency", rule: rule.id };
        }
        if (amountMinor > rule.spend.maxAmountMinor) {
          return { decision: "deny", reasonCode: "spend-cap", rule: rule.id };
        }
        if (!rule.spend.payees.includes(payee)) {
          return { decision: "deny", reasonCode: "spend-payee", rule: rule.id };
        }
        if (rule.spend.dailyMaxMinor !== undefined) {
          const spent = ctx?.spentTodayMinor?.(currency) ?? 0;
          if (spent + amountMinor > rule.spend.dailyMaxMinor) {
            return { decision: "deny", reasonCode: "spend-daily", rule: rule.id };
          }
        }
        return { decision: "defer", reasonCode: "approval-required", rule: rule.id };
      }
      const rule = document.rules.find((r) => r.tool === call.name);
      if (!rule) {
        return { decision: "deny", reasonCode: "no-rule", rule: null };
      }
      for (const scope of rule.requires) {
        if (!principal.scopes.has(scope)) {
          return { decision: "deny", reasonCode: "scope-missing", rule: rule.id };
        }
      }
      if (rule.egress === true) {
        const extract = HOST_EXTRACTORS[call.name];
        const host = extract ? extract(call.arguments) : undefined;
        if (!extract || host === undefined) {
          return { decision: "deny", reasonCode: "egress-host-missing", rule: rule.id };
        }
        const allowed = document.egress ?? [];
        if (!allowed.includes(host)) {
          return { decision: "deny", reasonCode: "egress-blocked", rule: rule.id };
        }
      }
      if (rule.mode === "approve") {
        return { decision: "defer", reasonCode: "approval-required", rule: rule.id };
      }
      return { decision: "allow", reasonCode: "allow", rule: rule.id };
    },
  };
}
