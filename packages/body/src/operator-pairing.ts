import { createHash, randomInt } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writeFileAtomic } from "./atomic-write.ts";

export const PAIRING_TTL_MS = 5 * 60_000;
export const PAIRING_MAX_ATTEMPTS = 5;
export const PAIRING_FILE = "operator-pairing.json";

export type PairingRecord = {
  hash: string;
  expiresAtMs: number;
  attempts: number;
};

export type PairingCheck =
  | { ok: true }
  | { ok: false; reason: "missing" | "expired" | "mismatch" | "burned" };

export function pairingPath(stateDir: string): string {
  return join(stateDir, PAIRING_FILE);
}

export function hashPairingCode(code: string): string {
  return createHash("sha256").update(code, "utf8").digest("hex");
}

export function mintPairingCode(): string {
  return String(randomInt(0, 100_000_000)).padStart(8, "0");
}

export function writePairing(stateDir: string, record: PairingRecord): void {
  writeFileAtomic(pairingPath(stateDir), `${JSON.stringify(record)}\n`);
}

export function readPairing(stateDir: string): PairingRecord | null {
  const path = pairingPath(stateDir);
  if (!existsSync(path)) return null;
  try {
    const row = JSON.parse(readFileSync(path, "utf8")) as Partial<PairingRecord>;
    if (typeof row.hash !== "string" || typeof row.expiresAtMs !== "number" || typeof row.attempts !== "number") {
      return null;
    }
    return { hash: row.hash, expiresAtMs: row.expiresAtMs, attempts: row.attempts };
  } catch {
    return null;
  }
}

export function beginPairing(stateDir: string, nowMs = Date.now()): { code: string } {
  const code = mintPairingCode();
  writePairing(stateDir, {
    hash: hashPairingCode(code),
    expiresAtMs: nowMs + PAIRING_TTL_MS,
    attempts: 0,
  });
  return { code };
}

export function checkPairing(stateDir: string, code: string, nowMs = Date.now()): PairingCheck {
  const row = readPairing(stateDir);
  if (!row) return { ok: false, reason: "missing" };
  if (row.attempts >= PAIRING_MAX_ATTEMPTS) return { ok: false, reason: "burned" };
  if (nowMs > row.expiresAtMs) return { ok: false, reason: "expired" };
  if (hashPairingCode(code) !== row.hash) {
    writePairing(stateDir, { ...row, attempts: row.attempts + 1 });
    const again = readPairing(stateDir);
    if (again && again.attempts >= PAIRING_MAX_ATTEMPTS) return { ok: false, reason: "burned" };
    return { ok: false, reason: "mismatch" };
  }
  return { ok: true };
}

/** A used pairing is spent so the same code cannot enroll twice. */
export function consumePairing(stateDir: string): void {
  const path = pairingPath(stateDir);
  if (!existsSync(path)) return;
  writeFileAtomic(path, `${JSON.stringify({ hash: "", expiresAtMs: 0, attempts: PAIRING_MAX_ATTEMPTS })}\n`);
}
