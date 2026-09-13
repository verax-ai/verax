import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writeFileAtomic } from "./atomic-write.ts";

export const CREDENTIALS_FILE = "operator-credentials.json";
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

export function readCredentials(stateDir: string): StoredCredential[] {
  const path = credentialsPath(stateDir);
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

export function hasRegisteredOperator(stateDir: string): boolean {
  return readCredentials(stateDir).length > 0;
}

export function findCredential(stateDir: string, id: string): StoredCredential | null {
  return readCredentials(stateDir).find((c) => c.id === id) ?? null;
}

export function saveCredential(stateDir: string, credential: StoredCredential): void {
  const credentials = readCredentials(stateDir);
  const next = credentials.filter((c) => c.id !== credential.id);
  next.push(credential);
  writeFileAtomic(credentialsPath(stateDir), `${JSON.stringify({ credentials: next })}\n`);
}

export function updateCounter(stateDir: string, id: string, counter: number): boolean {
  const credentials = readCredentials(stateDir);
  const row = credentials.find((c) => c.id === id);
  if (!row) return false;
  if (counter < row.counter) return false;
  if (counter === row.counter && counter > 0) return false;
  row.counter = counter;
  writeFileAtomic(credentialsPath(stateDir), `${JSON.stringify({ credentials })}\n`);
  return true;
}
