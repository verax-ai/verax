import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolCall, ToolResult } from "@verax-ai/proxy";

export async function messageRead(_call: ToolCall, stateDir: string): Promise<ToolResult> {
  const path = join(stateDir, "inbox.jsonl");
  let rows: unknown[] = [];
  try {
    const text = await readFile(path, "utf8");
    rows = text
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as unknown);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  return {
    content: [{ type: "text", text: JSON.stringify(rows) }],
    isError: false,
  };
}
