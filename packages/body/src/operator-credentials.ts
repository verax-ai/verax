import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { writeFileAtomic } from "./atomic-write.ts";

export const CREDENTIALS_FILE = "operator-credentials.json";
export const REMOVED_DIR = "operator-removed";
export const DEFAULT_OPERATOR_SUB = "operator-1";

export type StoredCredential = {
  id: string;
  publicKey: string;
  counter: number;
  sub: string;
};

export type CredentialStore = {
  credentials: StoredCredential[];
};

export function credentialsPath(stateDir: string): string {
  return join(stateDir, CREDENTIALS_FILE);
}

export function readCredentialsAt(path: string): StoredCredential[] {
  if (!existsSync(path)) return [];
  try {
    const row = JSON.parse(readFileSync(path, "utf8")) as Partial<CredentialStore>;
    if (!Array.isArray(row.credentials)) return [];
    return row.credentials.filter(
      (c): c is StoredCredential =>
        typeof c?.id === "string" &&
        typeof c.publicKey === "string" &&
        typeof c.counter === "number" &&
        typeof c.sub === "string",
    );
  } catch {
    return [];
  }
}

export function removedPath(stateDir: string): string {
  return join(stateDir, REMOVED_DIR);
}

/** The name a removed passkey's mark is filed under. An id can be longer than a file name may be. */
function markOf(id: string): string {
  return createHash("sha256").update(id, "utf8").digest("hex");
}

export type Removed = { has: (id: string) => boolean };

/**
 * The passkeys an administrator has taken away. A removed passkey keeps its
 * row in the credentials file: the approvals it signed are in the ledger, and
 * `verax verify` reads them back under that key. What stops it being used
 * again is a mark in this directory, one file per passkey.
 *
 * A removal creates a file and changes none. Nothing here is read, altered
 * and written back, so two removals at once cannot undo each other, and a
 * counter the body writes a moment later is to another file altogether.
 *
 * Null when something is at the path and cannot be listed. That is not "none
 * removed": see `readCredentials`.
 */
export function readRemoved(stateDir: string): Removed | null {
  let marks: Set<string>;
  try {
    marks = new Set(readdirSync(removedPath(stateDir)));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") return null;
    marks = new Set();
  }
  return { has: (id) => marks.has(markOf(id)) };
}

/** Every row in the file, the removed among them: for rewriting the file, and for asking whether an id was ever enrolled. */
function everyCredential(stateDir: string): StoredCredential[] {
  return readCredentialsAt(credentialsPath(stateDir));
}

/**
 * The passkeys that can be used: those in the file, less the removed. When
 * the list of the removed cannot be read there are none, since any of them
 * might be on it.
 */
export function readCredentials(stateDir: string): StoredCredential[] {
  const removed = readRemoved(stateDir);
  if (!removed) return [];
  return everyCredential(stateDir).filter((c) => !removed.has(c.id));
}

/** Whether this id was ever enrolled here, removed since or not. */
export function everEnrolled(stateDir: string, id: string): boolean {
  return everyCredential(stateDir).some((c) => c.id === id);
}

/**
 * The file is written only when an operator enrolls, so its presence is the
 * answer. Asking whether it parses would read a truncated or mistyped file as
 * "no operator" and reopen the passkey-less flow; the issuer stays closed
 * instead, and a fresh enrollment replaces the file.
 */
export function hasRegisteredOperator(stateDir: string): boolean {
  return existsSync(credentialsPath(stateDir));
}

export function findCredential(stateDir: string, id: string): StoredCredential | null {
  return readCredentials(stateDir).find((c) => c.id === id) ?? null;
}

/**
 * Adds a passkey. An id the file already holds keeps the row it has, removed
 * or not: approvals in the ledger were signed under that key, and a second
 * enrolment must not put another in its place. False when nothing was written.
 */
export function saveCredential(stateDir: string, credential: StoredCredential): boolean {
  const credentials = everyCredential(stateDir);
  if (credentials.some((c) => c.id === credential.id)) return false;
  credentials.push(credential);
  writeFileAtomic(credentialsPath(stateDir), `${JSON.stringify({ credentials })}\n`);
  return true;
}

/**
 * Whether the credentials file can be listed from. `readCredentialsAt` gives
 * no rows for a file that does not parse, which is what a caller deciding
 * whom to let in wants, and not what someone reading a list wants to be told.
 */
export function credentialsReadable(stateDir: string): boolean {
  const path = credentialsPath(stateDir);
  if (!existsSync(path)) return true;
  try {
    return Array.isArray((JSON.parse(readFileSync(path, "utf8")) as Partial<CredentialStore>).credentials);
  } catch {
    return false;
  }
}

export function updateCounter(stateDir: string, id: string, counter: number): boolean {
  const credentials = everyCredential(stateDir);
  const row = credentials.find((c) => c.id === id);
  if (!row) return false;
  if (counter < row.counter) return false;
  if (counter === row.counter && counter > 0) return false;
  row.counter = counter;
  writeFileAtomic(credentialsPath(stateDir), `${JSON.stringify({ credentials })}\n`);
  return true;
}

export type Removal = "removed" | "already-removed" | "unknown" | "unreadable";

/** Takes a passkey out of use. Its row, and so its public key, stays where it was. */
export function removeCredential(stateDir: string, id: string): Removal {
  const removed = readRemoved(stateDir);
  if (!removed) return "unreadable";
  if (!everEnrolled(stateDir, id)) return "unknown";
  if (removed.has(id)) return "already-removed";
  mkdirSync(removedPath(stateDir), { recursive: true, mode: 0o700 });
  try {
    // The name is the mark. The id inside is for whoever reads the directory.
    writeFileSync(join(removedPath(stateDir), markOf(id)), `${id}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (err) {
    // Another removal of the same passkey got there between the look and the write.
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return "already-removed";
    throw err;
  }
  return "removed";
}
