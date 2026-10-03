import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";

import { canonical } from "@cedulon/core";
import type { ControlSignature } from "@verax-ai/proxy";

/**
 * The proxy refuses every call while `<stateDir>/halted` exists; that file is
 * the switch and stays empty. Who flipped it and when goes to
 * `halt-history.jsonl` beside it, one line per halt or resume, so the panel
 * can say "stopped by operator-7 at 14:02" and a resume is not silent.
 *
 * The history file itself stays plain text. Each line is copied into the
 * ledger as a signed control record (subject `verax.halt` or `verax.resume`)
 * when the body opens, when `POST /api/halt` or `POST /api/resume` returns,
 * or on the next call. A CLI halt is not in the ledger until one of those,
 * and that delay is part of the record rather than something the file hides.
 * Calls refused while halted are signed deny records, and they come after
 * the halt control record in the chain.
 *
 * An HTTP halt or resume made with the operator's passkey carries that
 * assertion on its line, and the control record carries it on from there.
 */
export type HaltEvent = {
  action: "halt" | "resume";
  atMs: number;
  by: string;
  via: "cli" | "http";
  signature?: ControlSignature;
};

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

/**
 * SHA-256 of the newest history line, as the control record names that line
 * (`lineHash`), or `null` when there is none. A signed halt or resume binds
 * this, so its assertion fits only the line it is appended after.
 */
export function historyTail(stateDir: string): string | null {
  let raw: string;
  try {
    raw = readFileSync(join(stateDir, HISTORY), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const lines = raw
    .split("\n")
    .map((line) => line.replace(/\r$/, ""))
    .filter((line) => line.trim() !== "");
  const last = lines[lines.length - 1];
  if (last === undefined) return null;
  return createHash("sha256").update(canonical(last), "utf8").digest("hex");
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
export function haltBody(
  stateDir: string,
  by: string,
  via: HaltEvent["via"],
  now = Date.now(),
  signature?: ControlSignature,
): HaltState {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  if (!existsSync(join(stateDir, SWITCH))) {
    writeFileSync(join(stateDir, SWITCH), "", { encoding: "utf8", mode: 0o600 });
    appendHistory(stateDir, { action: "halt", atMs: now, by, via, ...(signature ? { signature } : {}) });
  }
  return readHalt(stateDir);
}

/**
 * Resuming a body that is not halted changes nothing and writes nothing.
 * The line goes to the history before the switch is removed: if it cannot be
 * written, the append throws and the body stays halted, rather than running
 * again with no record of who let it.
 */
export function resumeBody(
  stateDir: string,
  by: string,
  via: HaltEvent["via"],
  now = Date.now(),
  signature?: ControlSignature,
): HaltState {
  if (existsSync(join(stateDir, SWITCH))) {
    appendHistory(stateDir, { action: "resume", atMs: now, by, via, ...(signature ? { signature } : {}) });
    rmSync(join(stateDir, SWITCH), { force: true });
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
