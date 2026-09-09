#!/usr/bin/env node
// adapted from cedulon@da7bf9b
// Tracked text blobs must not carry CR (0x0D). Windows checkout with
// core.autocrlf=true has already bitten the fence parser; this guard
// checks the object store, not the working tree.
//
// They must not carry a stray control character either. A source line written
// through a tool that mishandles escapes can land a real backspace where the
// author meant a regex boundary: the pattern then matches nothing, the test
// that uses it measures nothing, and it stays green. That happened here. The
// same slip in the other direction leaves a replacement character behind.
//
// This script never writes.

import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export type BinaryException = {
  file: string;
  reason: string;
};

/** Tracked binaries. A 0x0D in these is payload, not a line ending. */
export const BINARY_EXCEPTIONS: BinaryException[] = [];

export type CrHit = {
  file: string;
  count: number;
};

const BINARY_EXT = /\.(png|pdf|bin|tgz)$/i;

export function isBinaryPath(file: string): boolean {
  const normalized = file.replace(/\\/g, "/");
  if (BINARY_EXCEPTIONS.some((ex) => ex.file === normalized)) {
    return true;
  }
  return BINARY_EXT.test(normalized);
}

export function countCarriageReturns(bytes: Buffer): number {
  let n = 0;
  for (const b of bytes) {
    if (b === 0x0d) n += 1;
  }
  return n;
}

export function looksBinary(bytes: Buffer): boolean {
  return bytes.includes(0);
}

export function trackedFiles(base = root): string[] {
  const raw = execFileSync("git", ["ls-files", "-z"], { cwd: base });
  return raw
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .map((f) => f.replace(/\\/g, "/"));
}

export function blobsOf(files: string[], base = root): Map<string, Buffer> {
  if (files.length === 0) return new Map();
  const input = files.map((f) => `:${f}`).join("\n") + "\n";
  const raw = execFileSync("git", ["cat-file", "--batch"], {
    cwd: base,
    input,
    maxBuffer: 32 * 1024 * 1024,
  });
  const out = new Map<string, Buffer>();
  let offset = 0;
  for (const file of files) {
    const nl = raw.indexOf(0x0a, offset);
    if (nl < 0) throw new Error(`crlf-guard: missing header for ${file}`);
    const header = raw.subarray(offset, nl).toString("utf8");
    const parts = header.split(" ");
    if (parts[1] !== "blob") {
      throw new Error(`crlf-guard: ${file} is ${parts[1] ?? "missing"}, not a blob`);
    }
    const size = Number(parts[2]);
    const start = nl + 1;
    out.set(file, raw.subarray(start, start + size));
    offset = start + size + 1;
  }
  return out;
}

export function findCarriageReturns(
  base = root,
  extra: Array<{ file: string; bytes: Buffer }> = [],
): CrHit[] {
  const hits: CrHit[] = [];
  const files = trackedFiles(base);
  const blobs = blobsOf(files, base);
  for (const file of files) {
    if (isBinaryPath(file)) continue;
    const bytes = blobs.get(file);
    if (!bytes) throw new Error(`crlf-guard: no blob for ${file}`);
    if (looksBinary(bytes)) continue;
    const count = countCarriageReturns(bytes);
    if (count > 0) {
      hits.push({ file, count });
    }
  }
  for (const item of extra) {
    const file = item.file.replace(/\\/g, "/");
    if (isBinaryPath(file) || looksBinary(item.bytes)) continue;
    const count = countCarriageReturns(item.bytes);
    if (count > 0) {
      hits.push({ file, count });
    }
  }
  return hits;
}

export type ControlHit = {
  file: string;
  codePoints: string[];
};

/**
 * Control characters that have no business in tracked text: everything below
 * space except newline and tab (CR is the check above), and the replacement
 * character, which means the bytes were not the encoding they claimed.
 */
export function findStrayControls(
  base = root,
  extra: Array<{ file: string; bytes: Buffer }> = [],
): ControlHit[] {
  const decoder = new TextDecoder("utf8");
  const hits: ControlHit[] = [];
  const check = (file: string, bytes: Buffer) => {
    if (isBinaryPath(file) || looksBinary(bytes)) return;
    const seen = new Set<string>();
    for (const ch of decoder.decode(bytes)) {
      const code = ch.codePointAt(0) ?? 0;
      const stray =
        (code < 0x20 && code !== 0x0a && code !== 0x09 && code !== 0x0d) || code === 0xfffd;
      if (stray) seen.add(`0x${code.toString(16)}`);
    }
    if (seen.size > 0) hits.push({ file, codePoints: [...seen] });
  };
  const files = trackedFiles(base);
  const blobs = blobsOf(files, base);
  for (const file of files) {
    const bytes = blobs.get(file);
    if (!bytes) throw new Error(`crlf-guard: no blob for ${file}`);
    check(file, bytes);
  }
  for (const item of extra) {
    check(item.file.split(String.fromCharCode(92)).join("/"), item.bytes);
  }
  return hits;
}

const invoked =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const hits = findCarriageReturns();
  const strays = findStrayControls();
  if (hits.length > 0 || strays.length > 0) {
    for (const hit of hits) {
      console.error(`crlf-guard: ${hit.file} has ${hit.count} CR byte(s)`);
    }
    for (const stray of strays) {
      console.error(`crlf-guard: ${stray.file} carries ${stray.codePoints.join(", ")}`);
    }
    process.exit(1);
  }
  console.log("crlf-guard: no CR and no stray control byte in tracked text blobs");
}
