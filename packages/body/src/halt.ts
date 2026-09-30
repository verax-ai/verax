import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";

/**
 * The proxy refuses every call while `<stateDir>/halted` exists; that file is
 * the switch and stays empty. Who flipped it and when goes to
 * `halt-history.jsonl` beside it, one line per halt or resume, so the panel
 * can say "stopped by operator-7 at 14:02" and a resume is not silent.
 *
 * The history is a plain append-only file, not a signed ledger record. The
 * calls refused while halted are signed; the switch itself is not.
 */
export type HaltEvent = { action: "halt" | "resume"; atMs: number; by: string; via: "cli" | "http" };

export type HaltState = { halted: boolean; since?: HaltEvent };

const SWITCH = "halted";
const HISTORY = "halt-history.jsonl";

function cliUser(): string {
  try {
    return userInfo().username || "unknown";
  } catch {
    return "unknown";
  }
}

function appendHistory(stateDir: string, event: HaltEvent): void {
  appendFileSync(join(stateDir, HISTORY), `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
}

function lastHalt(stateDir: string): HaltEvent | undefined {
  let raw: string;
  try {
    raw = readFileSync(join(stateDir, HISTORY), "utf8");
  } catch {
    return undefined;
  }
  const lines = raw.split("\n").filter((line) => line.trim() !== "");
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const row = JSON.parse(lines[i] ?? "") as Partial<HaltEvent>;
      if (row.action === "halt" && typeof row.atMs === "number" && typeof row.by === "string") {
        return { action: "halt", atMs: row.atMs, by: row.by, via: row.via === "http" ? "http" : "cli" };
      }
      if (row.action === "resume") return undefined;
    } catch {
      // A torn last line says nothing about who halted.
    }
  }
  return undefined;
}

export function readHalt(stateDir: string): HaltState {
  if (!existsSync(join(stateDir, SWITCH))) return { halted: false };
  const since = lastHalt(stateDir);
  return since ? { halted: true, since } : { halted: true };
}

/** Halting twice is one halt: the first line keeps saying who stopped it. */
export function haltBody(stateDir: string, by: string, via: HaltEvent["via"], now = Date.now()): HaltState {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  if (!existsSync(join(stateDir, SWITCH))) {
    writeFileSync(join(stateDir, SWITCH), "", { encoding: "utf8", mode: 0o600 });
    appendHistory(stateDir, { action: "halt", atMs: now, by, via });
  }
  return readHalt(stateDir);
}

/** Resuming a body that is not halted changes nothing and writes nothing. */
export function resumeBody(stateDir: string, by: string, via: HaltEvent["via"], now = Date.now()): HaltState {
  if (existsSync(join(stateDir, SWITCH))) {
    rmSync(join(stateDir, SWITCH), { force: true });
    appendHistory(stateDir, { action: "resume", atMs: now, by, via });
  }
  return readHalt(stateDir);
}

export function runHalt(
  stateDir: string,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
): number {
  if (!stateDir) {
    writeErr("verax halt <stateDir>\n");
    return 78;
  }
  haltBody(stateDir, cliUser(), "cli");
  writeErr("halted\n");
  return 0;
}

export function runResume(
  stateDir: string,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
): number {
  if (!stateDir) {
    writeErr("verax resume <stateDir>\n");
    return 78;
  }
  if (!existsSync(join(stateDir, SWITCH))) {
    writeErr("not halted\n");
    return 0;
  }
  resumeBody(stateDir, cliUser(), "cli");
  writeErr("resumed\n");
  return 0;
}
