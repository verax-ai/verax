#!/usr/bin/env node
// adapted from cedulon@da7bf9b
// Cedulon's original scan rejects a handwritten suite size. Verax also
// rejects a short list of certainty phrases on README.md and docs/.
//
// This script does not run the suite. It only reads files.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export type Exception = {
  file: string;
  contains: string;
  reason: string;
};

export type ClaimHit = {
  file: string;
  line: number;
  text: string;
};

// A suite-size claim is a number attached to "passing tests" / "tests passing"
// / "tests passed" / "N/N passing". Demo figures such as "100/100 allows" or
// "97-block" do not match.
const SUITE_SIZE =
  /(\d+)\s+passing tests|(\d+)\s+tests?\s+passing|all\s+(\d+)\s+tests\s+passed|(\d+)\/(\d+)\s+passing/i;

const BANNED_PHRASES: ReadonlyArray<{ name: string; re: RegExp }> = [
  { name: "proven", re: /\bproven\b/i },
  { name: "guarantees", re: /\bguarantees\b/i },
  { name: "secure by design", re: /\bsecure by design\b/i },
  { name: "secure by default", re: /\bsecure by default\b/i },
  { name: "production-ready", re: /\bproduction-ready\b/i },
  { name: "60 fps", re: /\b60\s*fps\b/i },
];

function stripTags(s: string): string {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

/** "works" is banned only as the first word of a sentence. */
export function hasSentenceInitialWorks(text: string): boolean {
  return /(?:^|[.!?])\s*works\b/i.test(text);
}

export function matchBanned(line: string): string | null {
  const normalized = stripTags(line);
  if (SUITE_SIZE.test(normalized)) return "suite-size";
  if (hasSentenceInitialWorks(normalized)) return "works (sentence-initial)";
  for (const phrase of BANNED_PHRASES) {
    if (phrase.re.test(normalized)) return phrase.name;
  }
  return null;
}

function publishedFiles(base: string): string[] {
  const docsDir = join(base, "docs");
  const docs = existsSync(docsDir)
    ? readdirSync(docsDir)
        .filter((n) => n.endsWith(".md"))
        .map((n) => join("docs", n).replace(/\\/g, "/"))
    : [];
  return [...docs, "README.md"];
}

function loadExceptions(base: string): Exception[] {
  const raw = JSON.parse(
    readFileSync(join(base, "scripts", "claim-guard-exceptions.json"), "utf8"),
  ) as Exception[];
  if (!Array.isArray(raw)) {
    throw new Error("claim-guard exceptions must be an array");
  }
  for (const ex of raw) {
    if (!ex.file || !ex.contains || !ex.reason) {
      throw new Error("claim-guard exception is missing file, contains, or reason");
    }
  }
  return raw;
}

export function scanClaims(base = root): { hits: ClaimHit[]; exceptions: Exception[] } {
  const exceptions = loadExceptions(base);
  const hits: ClaimHit[] = [];
  for (const rel of publishedFiles(base)) {
    const text = readFileSync(join(base, rel), "utf8");
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const normalized = stripTags(lines[i]);
      const kind = matchBanned(lines[i]);
      if (!kind) continue;
      const excepted = exceptions.some(
        (ex) => ex.file === rel.replace(/\\/g, "/") && normalized.includes(ex.contains),
      );
      if (excepted) continue;
      hits.push({ file: rel.replace(/\\/g, "/"), line: i + 1, text: normalized });
    }
  }
  return { hits, exceptions };
}

const invoked =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const { hits } = scanClaims();
  if (hits.length === 0) {
    process.stdout.write("claim-guard: no banned claims on published surfaces\n");
    process.exit(0);
  }
  for (const hit of hits) {
    process.stderr.write(`${hit.file}:${hit.line}: ${hit.text}\n`);
  }
  process.stderr.write(
    `claim-guard: ${hits.length} banned claim(s). Remove the phrase; STATUS.md states what is unproven.\n`,
  );
  process.exit(1);
}
