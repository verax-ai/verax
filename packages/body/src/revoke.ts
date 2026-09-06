import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export function isRevokedJti(stateDir: string, jti: string): boolean {
  const path = join(stateDir, "revoked-jti.jsonl");
  if (!existsSync(path)) return false;
  const text = readFileSync(path, "utf8");
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { jti?: unknown };
    if (row.jti === jti) return true;
  }
  return false;
}
