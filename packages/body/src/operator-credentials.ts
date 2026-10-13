import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writeFileAtomic } from "./atomic-write.ts";

export const CREDENTIALS_FILE = "operator-credentials.json";
export const REMOVED_FILE = "operator-removed.json";
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
  return join(stateDir, REMOVED_FILE);
}

/**
 * The ids of the passkeys an administrator has taken away. A removed passkey
 * keeps its row in the credentials file: the approvals it signed are in the
 * ledger, and `verax verify` reads them back under that key. This file is
 * what stops it being used again. `verax operator remove` is its one writer,
 * as the body is the one writer of the credentials file; neither rewrites the
 * other's, so a removal cannot be undone by a counter written a moment later.
 *
 * Null when the file is there and does not read as a list of ids. That is not
 * an empty list: see `readCredentials`.
 */
export function readRemoved(stateDir: string): Set<string> | null {
  const path = removedPath(stateDir);
  if (!existsSync(path)) return new Set();
  try {
    const row = JSON.parse(readFileSync(path, "utf8")) as { removed?: unknown };
    if (!Array.isArray(row.removed) || !row.removed.every((id) => typeof id === "string")) return null;
    return new Set(row.removed as string[]);
  } catch {
    return null;
  }
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

export function saveCredential(stateDir: string, credential: StoredCredential): void {
  const credentials = everyCredential(stateDir);
  const next = credentials.filter((c) => c.id !== credential.id);
  next.push(credential);
  writeFileAtomic(credentialsPath(stateDir), `${JSON.stringify({ credentials: next })}\n`);
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
  writeFileAtomic(removedPath(stateDir), `${JSON.stringify({ removed: [...removed, id] })}\n`);
  return "removed";
}
