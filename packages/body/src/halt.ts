import { createHash } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";

import { canonical } from "@cedulon/core";
import type { ControlSignature } from "@verax-ai/proxy";
import { closeIncidentsOnResume } from "./incidents.ts";
import { markHistoryUnavailable } from "./memory-store.ts";

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
 * A memory integrity failure uses `via: "integrity"` and
 * `by: "verax:memory-integrity"`.
 */
export type HaltEvent = {
  action: "halt" | "resume";
  atMs: number;
  by: string;
  via: "cli" | "http" | "integrity";
  signature?: ControlSignature;
  /** Integrity halt only: the incident this switch is bound to. */
  eventId?: string;
  triggerCode?: string;
  memoryHead?: { seq: number; lastHash: string };
};

export type HaltState = { halted: boolean; since?: HaltEvent };

const SWITCH = "halted";
const HISTORY = "halt-history.jsonl";

function oneLine(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err);
  return text.replace(/[\r\n]+/g, " ").slice(0, 300);
}

function cliUser(): string {
  try {
    return userInfo().username || "unknown";
  } catch {
    return "unknown";
  }
}

function appendHistory(stateDir: string, event: HaltEvent): void {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const fd = openSync(join(stateDir, HISTORY), "a", 0o600);
  try {
    writeSync(fd, `${JSON.stringify(event)}\n`, null, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
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

function haltVia(raw: unknown): HaltEvent["via"] {
  if (raw === "http" || raw === "integrity") return raw;
  return "cli";
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
        const event: HaltEvent = { action: "halt", atMs: row.atMs, by: row.by, via: haltVia(row.via) };
        if (typeof row.eventId === "string" && row.eventId !== "") event.eventId = row.eventId;
        if (typeof row.triggerCode === "string" && row.triggerCode !== "") event.triggerCode = row.triggerCode;
        const head = row.memoryHead;
        if (head && typeof head === "object" && typeof head.seq === "number" && typeof head.lastHash === "string") {
          event.memoryHead = { seq: head.seq, lastHash: head.lastHash };
        }
        return event;
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
  incident?: Pick<HaltEvent, "eventId" | "triggerCode" | "memoryHead">,
): HaltState {
  try {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    if (!existsSync(join(stateDir, SWITCH))) {
      writeFileSync(join(stateDir, SWITCH), "", { encoding: "utf8", mode: 0o600 });
      appendHistory(stateDir, {
        action: "halt",
        atMs: now,
        by,
        via,
        ...(signature ? { signature } : {}),
        ...(incident?.eventId ? { eventId: incident.eventId } : {}),
        ...(incident?.triggerCode ? { triggerCode: incident.triggerCode } : {}),
        ...(incident?.memoryHead ? { memoryHead: incident.memoryHead } : {}),
      });
    }
  } catch (err) {
    process.stderr.write(`verax: halt: ${oneLine(err)}\n`);
    if (!existsSync(join(stateDir, SWITCH))) {
      markHistoryUnavailable(stateDir);
    } else {
      throw err;
    }
  }
  return readHalt(stateDir);
}

/**
 * Resuming a body that is not halted changes nothing and writes nothing.
 * Undelivered incidents are verified/re-signed and written to the outbox, or
 * marked closed-pending-delivery with an atomic write. If that mark cannot be
 * written, this throws and the body stays halted. The history line is
 * appended after the mark: if the append throws, the body stays halted
 * rather than running again with no record of who let it. Then the switch
 * is removed. A later integrity halt is a new event. Pending outbox files stay.
 */
export function resumeBody(
  stateDir: string,
  by: string,
  via: HaltEvent["via"],
  now = Date.now(),
  signature?: ControlSignature,
  keysDir?: string | null,
): HaltState {
  if (existsSync(join(stateDir, SWITCH))) {
    closeIncidentsOnResume(stateDir, keysDir);
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
  try {
    resumeBody(stateDir, cliUser(), "cli", Date.now(), undefined, process.env.VERAX_KEYS_DIR);
  } catch (err) {
    writeErr(`resume-failed: ${oneLine(err)}\n`);
    return 1;
  }
  writeErr("resumed\n");
  return 0;
}
