import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The default policy ships inside @verax-ai/proxy as policy/default.json.
 * The proxy exports only its entry, not its package.json, so the file is
 * found one directory above that entry (dist/index.js). That holds wherever
 * npm put the proxy: next to the body, under the body's own node_modules
 * (npm install -g does not hoist) or in an npx cache. The two sibling paths
 * cover a checkout of this repository.
 */
export function shippedPolicyPath(): string | null {
  const here = dirname(fileURLToPath(import.meta.url));
  let fromEntry: string | null = null;
  try {
    fromEntry = join(dirname(fileURLToPath(import.meta.resolve("@verax-ai/proxy"))), "..", "policy", "default.json");
  } catch {
    fromEntry = null;
  }
  const candidates = [
    fromEntry,
    join(here, "..", "..", "proxy", "policy", "default.json"),
    join(here, "..", "..", "@verax-ai", "proxy", "policy", "default.json"),
  ];
  for (const path of candidates) {
    if (path && existsSync(path)) return path;
  }
  return null;
}
