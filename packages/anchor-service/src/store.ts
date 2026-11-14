/**
 * Append-only JSONL store of log leaves. Each line is
 * `{"leaf_hash":"<64 hex>","owner_id":"<id>","at_ms":<number>}`. On start the
 * file is read back in order; a line that does not parse or breaks the
 * expected shape refuses to load.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";

import { MerkleLog, type LogLeaf } from "./merkle.ts";

const HASH = /^[0-9a-f]{64}$/;

export type StoreRow = {
  leaf_hash: string;
  owner_id: string;
  at_ms: number;
};

export function parseStoreLine(line: string, lineNo: number): StoreRow {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error(`store line ${lineNo} is not JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`store line ${lineNo} is not a store row`);
  }
  const row = parsed as Record<string, unknown>;
  if (typeof row.leaf_hash !== "string" || !HASH.test(row.leaf_hash)) {
    throw new Error(`store line ${lineNo} has a bad leaf_hash`);
  }
  if (typeof row.owner_id !== "string" || row.owner_id === "") {
    throw new Error(`store line ${lineNo} has a bad owner_id`);
  }
  if (typeof row.at_ms !== "number" || !Number.isSafeInteger(row.at_ms)) {
    throw new Error(`store line ${lineNo} has a bad at_ms`);
  }
  const keys = Object.keys(row);
  if (keys.length !== 3) throw new Error(`store line ${lineNo} has unexpected fields`);
  return { leaf_hash: row.leaf_hash, owner_id: row.owner_id, at_ms: row.at_ms };
}

export function loadStore(path: string): MerkleLog {
  const log = new MerkleLog();
  if (!existsSync(path)) {
    // Touch the file so later appends do not create it under a race the
    // operator did not intend; open for append creates an empty file.
    closeSync(openSync(path, "a"));
    return log;
  }
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!.trim();
    if (line === "") continue;
    const row = parseStoreLine(line, i + 1);
    const leaf: LogLeaf = {
      entry: Buffer.from(row.leaf_hash, "hex"),
      ownerId: row.owner_id,
      atMs: row.at_ms,
    };
    log.append(leaf);
  }
  return log;
}

export function appendStore(path: string, row: StoreRow): void {
  const fd = openSync(path, "a");
  try {
    writeSync(fd, `${JSON.stringify(row)}\n`, null, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
