import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const copyDir = join(here, "..", "src", "copy");
const golden = join(here, "..", "..", "..", "packages", "proxy", "tests", "fixtures", "ledger-golden");
const defaultPolicy = join(here, "..", "..", "..", "packages", "proxy", "policy", "default.json");

function collectStrings(value: unknown, out: Set<string>): void {
  if (typeof value === "string" && value.length > 0) {
    out.add(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, out);
  }
}

function collectJsonl(path: string, out: Set<string>): void {
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line === "") continue;
    collectStrings(JSON.parse(line), out);
  }
}

/**
 * Words the sample ledger and its policy documents put on the screen.
 * Translating them would rewrite the record (L1). The interface around
 * them is what the reverse language gate measures.
 */
export function demoLedgerValues(): string[] {
  const out = new Set<string>();
  collectStrings(JSON.parse(readFileSync(join(golden, "policy-store.json"), "utf8")), out);
  collectStrings(JSON.parse(readFileSync(defaultPolicy, "utf8")), out);
  collectJsonl(join(golden, "decisions.jsonl"), out);
  collectJsonl(join(golden, "effects.jsonl"), out);
  collectJsonl(join(golden, "inputs.jsonl"), out);
  for (const extra of [
    "demo-spend-defer",
    "demo-spend-allow",
    "demo-spend-open",
    "sample-brain",
    "verax:pay",
    "operator-1",
    "cli",
    "Sample spend needs operator approval.",
    "example-payee",
    "TRY",
    "card",
    "verax-proxy",
    "verax-operator",
    "spend-sample",
    "self",
    "same-org",
    "spend",
    "allow",
    "deny",
    "defer",
    "approval-required",
    "approved-by-operator",
    // Audit field values the record carries as they are. The frames around
    // them ("Guarantee: …", "trust root: …") went into the copy table, so
    // the gate now catches those too.
    "none",
    "unknown",
    "body",
    "unconditional",
    "conditional",
    "ghost",
    "reauth",
  ]) {
    out.add(extra);
  }
  return [...out];
}

export function turkishCopyValues(): string[] {
  const table = JSON.parse(readFileSync(join(copyDir, "tr.json"), "utf8")) as Record<string, string>;
  return Object.values(table);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function templateToCapturingRegExp(template: string): RegExp {
  const body = escapeRegExp(template)
    .replace(/\\\{n\\\}/g, "(\\d+)")
    .replace(/\\\{[a-zA-Z]+\\\}/g, "(.+)");
  return new RegExp(body, "g");
}

function isLedgerFragment(word: string, ledger: string[]): boolean {
  const w = word.toLowerCase();
  for (const value of ledger) {
    const v = value.toLowerCase();
    if (v === w) return true;
    for (const token of v.split(/[^a-z0-9]+/)) {
      if (token === w) return true;
    }
  }
  return false;
}

function englishWordsIn(text: string, ledger: string[], copyPlain: string[]): string[] {
  let rest = text;
  rest = rest.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g, " ");
  rest = rest.replace(/\b[0-9a-f]{8,}\b/gi, " ");
  // A value the screen cut short is not a word. shortHash prints
  // "demo-spe…", and the fragment before the ellipsis has no language.
  rest = rest.replace(/\S*…/gu, " ");
  rest = rest.replace(/[0-9]+/g, " ");
  for (const phrase of copyPlain) {
    if (phrase.length < 2) continue;
    rest = rest.split(phrase).join(" ");
  }
  const leftover: string[] = [];
  for (const word of rest.split(/[^\p{L}]+/u).filter((w) => w.length >= 2)) {
    if (/^(EN|TR)$/i.test(word)) continue;
    if (isLedgerFragment(word, ledger)) continue;
    if (/[A-Za-z]/.test(word) && !/[çğıöşüÇĞİÖŞÜ]/.test(word)) leftover.push(word);
  }
  return leftover;
}

/**
 * After the Turkish copy table and the sample ledger's own words are
 * removed, no leftover line may still carry an English interface word.
 * Slots inside a copy template are inspected, not swallowed: "Defter
 * kilidi: held" still fails even though the frame is Turkish.
 */
export function englishInterfaceLeftovers(pageText: string): string[] {
  const ledger = demoLedgerValues();
  const copy = turkishCopyValues();
  const templates = copy.filter((p) => p.includes("{")).sort((a, b) => b.length - a.length);
  const copyPlain = copy.filter((p) => !p.includes("{")).sort((a, b) => b.length - a.length);
  const leftover: string[] = [];
  for (const line of pageText.split(/\r?\n/)) {
    let rest = line;
    for (const template of templates) {
      const re = templateToCapturingRegExp(template);
      rest = rest.replace(re, (_whole, ...args) => {
        const slots = args.slice(0, -2).filter((s): s is string => typeof s === "string");
        leftover.push(...slots.flatMap((slot) => englishWordsIn(slot, ledger, copyPlain)));
        return " ";
      });
    }
    leftover.push(...englishWordsIn(rest, ledger, copyPlain));
  }
  return [...new Set(leftover)];
}
