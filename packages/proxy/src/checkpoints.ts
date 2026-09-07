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
