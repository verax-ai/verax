#!/usr/bin/env node
// adapted from cedulon@da7bf9b
// Tracked text blobs must not carry CR (0x0D). Windows checkout with
// core.autocrlf=true has already bitten the fence parser; this guard
// checks the object store, not the working tree.
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

const invoked =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const hits = findCarriageReturns();
  if (hits.length > 0) {
    for (const hit of hits) {
      console.error(`crlf-guard: ${hit.file} has ${hit.count} CR byte(s)`);
    }
    process.exit(1);
  }
  console.log("crlf-guard: no CR in tracked text blobs");
}
