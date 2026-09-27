import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { SignedCheckpoint } from "@cedulon/checkpoint";

export function checkpointsPath(dir: string): string {
  return join(dir, "checkpoints.jsonl");
}

export function loadCheckpoints(dir: string): SignedCheckpoint[] {
  let text: string;
  try {
    text = readFileSync(checkpointsPath(dir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const out: SignedCheckpoint[] = [];
  for (const line of text.split("\n")) {
    if (line === "") continue;
    try {
      const row = JSON.parse(line) as SignedCheckpoint;
      if (row && typeof row === "object" && row.claims && typeof row.coseHex === "string") {
        out.push(row);
      }
    } catch {
      // skip a truncated line; the next honest row still loads
    }
  }
  return out;
}

function isCheckpointRow(row: unknown): row is SignedCheckpoint {
  if (!row || typeof row !== "object" || Array.isArray(row)) return false;
  const rec = row as { claims?: unknown; coseHex?: unknown };
  return Boolean(rec.claims) && typeof rec.coseHex === "string";
}

/**
 * Every non-empty line is either a checkpoint row or a named problem.
 * A missing file is an empty result with no problem. A line that does not
 * parse, and a line that parses but is not a checkpoint, are both problems.
 */
export function readCheckpointFile(dir: string): { rows: SignedCheckpoint[]; problems: string[] } {
  let text: string;
  try {
    text = readFileSync(checkpointsPath(dir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { rows: [], problems: [] };
    return { rows: [], problems: ["checkpoint file could not be read"] };
  }
  const rows: SignedCheckpoint[] = [];
  const problems: string[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (line === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      problems.push(`checkpoint line ${i + 1} is not a checkpoint`);
      continue;
    }
    if (!isCheckpointRow(parsed)) {
      problems.push(`checkpoint line ${i + 1} is not a checkpoint`);
      continue;
    }
    rows.push(parsed);
  }
  return { rows, problems };
}
