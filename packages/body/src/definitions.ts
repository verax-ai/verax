import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const DIGEST_RE = /^[0-9a-f]{64}$/;

/**
 * Copies the pinned manifest into the state directory, create-only, before a
 * start row names it. The source bytes must hash to the digest; a file
 * already there must be those same bytes. What the copy and the signed row
 * prove, and no more: the body that held a trusted record key recorded these
 * definitions at that start. They do not prove that a person read them or
 * that the child's code behaves as described.
 */
export function copyDefinition(stateDir: string, definitionsDir: string, digest: string): void {
  if (!DIGEST_RE.test(digest)) throw new Error(`downstream-manifest-invalid:${digest}`);
  const source = join(definitionsDir, "definitions", `${digest}.json`);
  let bytes: Buffer;
  try {
    bytes = readFileSync(source);
  } catch {
    throw new Error(`downstream-manifest-invalid:${digest}`);
  }
  if (createHash("sha256").update(bytes).digest("hex") !== digest) {
    throw new Error(`downstream-manifest-invalid:${digest}`);
  }
  const dest = join(stateDir, "definitions", `${digest}.json`);
  let existing: Buffer | undefined;
  try {
    existing = readFileSync(dest);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (existing !== undefined) {
    if (existing.equals(bytes)) return;
    throw new Error(`downstream-manifest-conflict:${digest}`);
  }
  mkdirSync(join(stateDir, "definitions"), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(dest, bytes, { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    const raced = readFileSync(dest);
    if (raced.equals(bytes)) return;
    throw new Error(`downstream-manifest-conflict:${digest}`);
  }
}
