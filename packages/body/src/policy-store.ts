import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadPolicy } from "@verax-ai/proxy";

const HASH_RE = /^[0-9a-f]{64}$/;

function snapshotPath(stateDir: string, hash: string): string {
  return join(stateDir, "policies", `${hash}.json`);
}

/** Write <stateDir>/policies/<policyHash>.json once; existing bytes are hash-checked. */
export function persistPolicySnapshot(stateDir: string, hash: string, document: unknown): void {
  if (!HASH_RE.test(hash)) {
    throw new Error(`policy-hash-invalid:${hash}`);
  }
  const dir = join(stateDir, "policies");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = snapshotPath(stateDir, hash);
  if (existsSync(path)) {
    const existing = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (loadPolicy(existing).hash !== hash) {
      throw new Error(`policy-snapshot-mismatch:${hash}`);
    }
    return;
  }
  writeFileSync(path, `${JSON.stringify(document)}\n`, { encoding: "utf8", mode: 0o600 });
}

export function readPolicySnapshots(
  stateDir: string,
  hashes: Iterable<string>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const hash of hashes) {
    if (!HASH_RE.test(hash)) continue;
    const path = snapshotPath(stateDir, hash);
    if (!existsSync(path)) continue;
    try {
      const document = JSON.parse(readFileSync(path, "utf8")) as unknown;
      if (loadPolicy(document).hash !== hash) continue;
      out[hash] = document;
    } catch {
      // Omit a bad snapshot so the panel can say the historical policy is unavailable.
    }
  }
  return out;
}
