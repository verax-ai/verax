import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | undefined;

/** The published package answers with its own version, not a copy of it. Read once. */
export function bodyVersion(): string {
  cached ??= readVersion();
  return cached;
}

function readVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const path of [join(here, "..", "package.json"), join(here, "..", "..", "package.json")]) {
    try {
      const raw = JSON.parse(readFileSync(path, "utf8")) as { name?: string; version?: string };
      if (raw.name === "@verax-ai/body" && typeof raw.version === "string") return raw.version;
    } catch {
      // try the next candidate: the file layout differs between src and dist.
    }
  }
  return "unknown";
}
