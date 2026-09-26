import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Written by `verax install` before the service starts. `/healthz` echoes it. */
export const INSTALL_HEALTH_NONCE = "install-health-nonce";

/** Hex nonce from this install, or null when the file is absent or not that shape. */
export function readInstallHealthNonce(stateDir: string): string | null {
  try {
    const text = readFileSync(join(stateDir, INSTALL_HEALTH_NONCE), "utf8").trim();
    if (!/^[0-9a-f]{64}$/i.test(text)) return null;
    return text.toLowerCase();
  } catch {
    return null;
  }
}

export type HealthHeartbeat = {
  atMs: number;
  lastDecisionN: number;
  lastEffectN: number;
};

export type HealthWitness = {
  class: "self" | "same-org";
  atMs: number;
};

export function readHeartbeat(stateDir: string): HealthHeartbeat | null {
  const path = join(stateDir, "heartbeat.json");
  if (!existsSync(path)) return null;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      atMs?: unknown;
      lastDecisionN?: unknown;
      lastEffectN?: unknown;
    };
    if (typeof raw.atMs !== "number" || !Number.isFinite(raw.atMs)) return null;
    return {
      atMs: raw.atMs,
      lastDecisionN: typeof raw.lastDecisionN === "number" ? raw.lastDecisionN : 0,
      lastEffectN: typeof raw.lastEffectN === "number" ? raw.lastEffectN : 0,
    };
  } catch {
    return null;
  }
}

export function readWitnessPulse(stateDir: string): HealthWitness | null {
  const path = join(stateDir, "witness-status.jsonl");
  if (!existsSync(path)) return null;
  try {
    const lines = readFileSync(path, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l !== "");
    const last = lines[lines.length - 1];
    if (!last) return null;
    const row = JSON.parse(last) as { atMs?: unknown; result?: unknown; class?: unknown };
    if (typeof row.atMs !== "number" || !Number.isFinite(row.atMs)) return null;
    if (row.result === "signed" || row.class === "same-org") {
      return { class: "same-org", atMs: row.atMs };
    }
    if (row.result === "self-fallback" || row.class === "self") {
      return { class: "self", atMs: row.atMs };
    }
    return null;
  } catch {
    return null;
  }
}
