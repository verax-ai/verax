import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { signDecisionRecord } from "@cedulon/core";
import type { EffectRow } from "@cedulon/effect-extract";
import type { SignedDecisionRecord } from "@cedulon/core";

import { sha256Canonical } from "./hash.ts";
import type { LedgerWriter } from "./ledger.ts";
import type { ControlInput, DecisionInputs, InputsLog, RecordSigner } from "./types.ts";

/**
 * Same file names as `packages/body/src/halt.ts`. The history file stays plain
 * text; this module copies each line into the ledger as a signed control record.
 * A CLI halt is not in the ledger until the body opens, the HTTP door syncs,
 * or the next call. That delay is real.
 *
 * The body is the only ledger writer, and the ledger lock keeps it that way.
 * After this proxy opens, no other process appends decisions. The first sync
 * reads the ledger once; later syncs trust the snapshot held in the proxy
 * closure and only reread `halt-history.jsonl` when its size or mtime changed
 * or the `halted` switch appeared or disappeared.
 *
 * A switch with no history halt is one `via: "file"` halt. Deleting that
 * switch while the last control record is still a halt, and while history has
 * no resume that closes that window, is one symmetric `via: "file"` resume.
 * The proxy catches a sync throw, leaves this snapshot unloaded, and lets the
 * call continue; halt and rate limits stay fail-closed on their own path.
 */
const HALT_SWITCH = "halted";
const HALT_HISTORY = "halt-history.jsonl";

const CONTROL_EFFECT = "verax.control";

type Via = ControlInput["via"];
type Action = ControlInput["action"];

type ParsedLine = {
  action: Action;
  atMs: number;
  by: string;
  via: Via;
  line: number;
};

/** `null` means `halt-history.jsonl` was absent. Content is not part of the stamp. */
type HistoryStamp = { size: number; mtimeMs: number } | null;

type Recorded = {
  mismatched: boolean;
  hasMismatch: boolean;
  seenMismatch: boolean;
  resumeFrom: number;
  maxLine: number;
  maxAfterAck: number;
  fileHaltCovers: boolean;
  /** Last control allow is a halt, so a halt window is open. */
  openHalt: boolean;
  hashesByLine: Map<number, string[]>;
};

export type ControlMemory = {
  loaded: boolean;
  recorded: Recorded;
  stamp: HistoryStamp;
  haltedPresent: boolean | null;
};

export function createControlMemory(): ControlMemory {
  return {
    loaded: false,
    recorded: {
      mismatched: false,
      hasMismatch: false,
      seenMismatch: false,
      resumeFrom: 0,
      maxLine: -1,
      maxAfterAck: -1,
      fileHaltCovers: false,
      openHalt: false,
      hashesByLine: new Map(),
    },
    stamp: null,
    haltedPresent: null,
  };
}

/**
 * True when the history file and the switch look as they did at the last sync,
 * so there is nothing to record. Cheap enough to run before taking the ledger
 * queue: waiting a turn behind the previous call's durable writes only to find
 * nothing changed doubled the cost of a call. Only `syncHaltControl` updates
 * `memory`, inside the queue, and it checks again there.
 */
export function controlUnchanged(stateDir: string, memory: ControlMemory): boolean {
  return (
    memory.loaded &&
    sameStamp(memory.stamp, historyStamp(stateDir)) &&
    memory.haltedPresent === existsSync(join(stateDir, HALT_SWITCH))
  );
}

export async function syncHaltControl(opts: {
  stateDir: string;
  now: () => number;
  nonce: () => string;
  policyHash: string;
  recordSigner: RecordSigner;
  inputsLog: InputsLog;
  decisions: () => Promise<SignedDecisionRecord[]>;
  memory: ControlMemory;
  writer: LedgerWriter;
}): Promise<void> {
  const stamp = historyStamp(opts.stateDir);
  const haltedPresent = existsSync(join(opts.stateDir, HALT_SWITCH));
  const memory = opts.memory;
  if (memory.loaded && sameStamp(memory.stamp, stamp) && memory.haltedPresent === haltedPresent) {
    return;
  }

  const history = readHistory(opts.stateDir);
  if (!memory.loaded) {
    memory.recorded = await readRecorded(opts, history);
    memory.loaded = true;
  } else {
    markMismatch(memory.recorded, history);
  }
  const recorded = memory.recorded;

  try {
    let cursor: number;
    if (recorded.mismatched && !recorded.hasMismatch) {
      await writeMismatch(opts, history.length);
      recorded.hasMismatch = true;
      recorded.seenMismatch = true;
      recorded.resumeFrom = history.length;
      recorded.maxAfterAck = history.length - 1;
      cursor = history.length;
    } else if (recorded.mismatched) {
      cursor = recorded.maxAfterAck + 1;
    } else {
      cursor = recorded.maxLine + 1;
    }

    let wroteHistory = false;
    for (let i = cursor; i < history.length; i += 1) {
      const raw = history[i]!;
      const lineHash = sha256Canonical(raw);
      const known = recorded.hashesByLine.get(i);
      if (known?.includes(lineHash)) continue;
      const event = parseHistoryLine(raw, i);
      if (!event) continue;
      await writeControlAllow(opts, event, lineHash);
      wroteHistory = true;
      noteHistoryAllow(recorded, i, lineHash);
      recorded.openHalt = event.action === "halt";
    }

    const needFile = haltedPresent && lastAction(history) !== "halt";
    if (needFile && (wroteHistory || !recorded.fileHaltCovers)) {
      await writeControlAllow(
        opts,
        { action: "halt", atMs: opts.now(), by: "unknown", via: "file", line: -1 },
        sha256Canonical({ via: "file", line: -1 }),
      );
      recorded.fileHaltCovers = true;
      recorded.openHalt = true;
    }

    // The switch is gone and the last control record is still a halt. A
    // history resume that closed this window has already cleared `openHalt`.
    // One file resume, symmetric with the file halt, and not repeated while
    // the window stays closed.
    if (!haltedPresent && recorded.openHalt) {
      await writeControlAllow(
        opts,
        { action: "resume", atMs: opts.now(), by: "unknown", via: "file", line: -1 },
        sha256Canonical({ via: "file", line: -1 }),
      );
      recorded.fileHaltCovers = false;
      recorded.openHalt = false;
    }

    memory.stamp = stamp;
    memory.haltedPresent = haltedPresent;
  } catch (err) {
    // A partial append is already on disk. Drop the snapshot so the next sync
    // reads the ledger once and does not write that line again.
    memory.loaded = false;
    throw err;
  }
}

function historyStamp(stateDir: string): HistoryStamp {
  try {
    const st = statSync(join(stateDir, HALT_HISTORY));
    return { size: st.size, mtimeMs: st.mtimeMs };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function sameStamp(a: HistoryStamp, b: HistoryStamp): boolean {
  if (a === null || b === null) return a === b;
  return a.size === b.size && a.mtimeMs === b.mtimeMs;
}

function noteHistoryAllow(recorded: Recorded, line: number, lineHash: string): void {
  recorded.fileHaltCovers = false;
  const bag = recorded.hashesByLine.get(line) ?? [];
  bag.push(lineHash);
  recorded.hashesByLine.set(line, bag);
  if (line > recorded.maxLine) recorded.maxLine = line;
  if (recorded.seenMismatch && line >= recorded.resumeFrom && line > recorded.maxAfterAck) {
    recorded.maxAfterAck = line;
  }
}

function markMismatch(recorded: Recorded, history: readonly string[]): void {
  let mismatched = recorded.maxLine > history.length;
  for (const [line, hashes] of recorded.hashesByLine) {
    if (line >= history.length) {
      mismatched = true;
      continue;
    }
    const nowHash = sha256Canonical(history[line]!);
    if (hashes.some((hash) => hash !== nowHash)) mismatched = true;
  }
  recorded.mismatched = mismatched;
}

function readHistory(stateDir: string): string[] {
  let text: string;
  try {
    text = readFileSync(join(stateDir, HALT_HISTORY), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  return text
    .split("\n")
    .map((line) => line.replace(/\r$/, ""))
    .filter((line) => line.trim() !== "");
}

function parseHistoryLine(raw: string, line: number): ParsedLine | null {
  let row: Partial<ParsedLine>;
  try {
    row = JSON.parse(raw) as Partial<ParsedLine>;
  } catch {
    return null;
  }
  if (row.action !== "halt" && row.action !== "resume") return null;
  if (typeof row.atMs !== "number" || typeof row.by !== "string") return null;
  const via: Via = row.via === "http" ? "http" : row.via === "file" ? "file" : "cli";
  return { action: row.action, atMs: row.atMs, by: row.by, via, line };
}

function lastAction(lines: readonly string[]): Action | null {
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const event = parseHistoryLine(lines[i]!, i);
    if (event) return event.action;
  }
  return null;
}

async function readRecorded(
  opts: {
    decisions: () => Promise<SignedDecisionRecord[]>;
    inputsLog: InputsLog;
  },
  history: readonly string[],
): Promise<Recorded> {
  const hashesByLine = new Map<number, string[]>();
  let maxLine = -1;
  let hasMismatch = false;
  let fileHaltCovers = false;
  let openHalt = false;
  let seenMismatch = false;
  let resumeFrom = 0;
  let maxAfterAck = -1;

  for (const decision of await opts.decisions()) {
    const reason = decision.claims.reasonCode;
    const subject = decision.claims.subject;
    const ref = decision.claims.ref;
    if (reason !== "halt-history-mismatch" && subject !== "verax.halt" && subject !== "verax.resume") {
      continue;
    }
    if (typeof ref !== "string") continue;
    const inputs = await opts.inputsLog.get(ref);
    const control = inputs?.control;
    if (reason === "halt-history-mismatch") {
      hasMismatch = true;
      seenMismatch = true;
      resumeFrom = typeof control?.line === "number" ? control.line : 0;
      maxAfterAck = resumeFrom - 1;
      continue;
    }
    if (decision.claims.decision !== "allow" || !control) continue;
    if (control.line === -1 && control.via === "file" && (subject === "verax.halt" || subject === "verax.resume")) {
      const halt = subject === "verax.halt";
      fileHaltCovers = halt;
      openHalt = halt;
      continue;
    }
    if (typeof control.line !== "number" || control.line < 0) continue;
    if (subject !== "verax.halt" && subject !== "verax.resume") continue;
    fileHaltCovers = false;
    openHalt = subject === "verax.halt";
    const bag = hashesByLine.get(control.line) ?? [];
    if (typeof control.lineHash === "string") bag.push(control.lineHash);
    hashesByLine.set(control.line, bag);
    if (control.line > maxLine) maxLine = control.line;
    if (seenMismatch && control.line >= resumeFrom && control.line > maxAfterAck) {
      maxAfterAck = control.line;
    }
  }

  const recorded: Recorded = {
    mismatched: false,
    hasMismatch,
    seenMismatch,
    resumeFrom,
    maxLine,
    maxAfterAck,
    fileHaltCovers,
    openHalt,
    hashesByLine,
  };
  markMismatch(recorded, history);
  return recorded;
}

async function writeMismatch(
  opts: {
    now: () => number;
    nonce: () => string;
    policyHash: string;
    recordSigner: RecordSigner;
    inputsLog: InputsLog;
    writer: LedgerWriter;
  },
  resumeFrom: number,
): Promise<void> {
  const atMs = opts.now();
  const control: ControlInput = {
    action: "halt",
    by: "unknown",
    via: "file",
    atMs,
    line: resumeFrom,
    lineHash: sha256Canonical("halt-history-mismatch"),
  };
  await writeDecision(opts, {
    decision: "deny",
    subject: CONTROL_EFFECT,
    reasonCode: "halt-history-mismatch",
    effectClass: CONTROL_EFFECT,
    effectHash: null,
    requestHash: sha256Canonical({ mismatch: "halt-history", resumeFrom }),
    timestampMs: atMs,
    control,
  });
}

async function writeControlAllow(
  opts: {
    now: () => number;
    nonce: () => string;
    policyHash: string;
    recordSigner: RecordSigner;
    inputsLog: InputsLog;
    writer: LedgerWriter;
  },
  event: ParsedLine,
  lineHash: string,
): Promise<void> {
  const body = {
    action: event.action,
    atMs: event.atMs,
    by: event.by,
    via: event.via,
    line: event.line,
  };
  const bound = sha256Canonical(body);
  const ref = await writeDecision(opts, {
    decision: "allow",
    subject: event.action === "halt" ? "verax.halt" : "verax.resume",
    reasonCode: event.action === "halt" ? "operator-halt" : "operator-resume",
    effectClass: CONTROL_EFFECT,
    effectHash: bound,
    requestHash: bound,
    timestampMs: event.atMs,
    control: { ...body, lineHash },
  });
  const row: EffectRow = {
    ref,
    effectHash: bound,
    effectClass: CONTROL_EFFECT,
    timestampMs: event.atMs,
    actor: event.by,
  };
  await opts.writer.appendEffect(row, "self", bound);
}

async function writeDecision(
  opts: {
    nonce: () => string;
    policyHash: string;
    recordSigner: RecordSigner;
    inputsLog: InputsLog;
    writer: LedgerWriter;
  },
  row: {
    decision: "allow" | "deny";
    subject: string;
    reasonCode: string;
    effectClass: string;
    effectHash: string | null;
    requestHash: string;
    timestampMs: number;
    control: ControlInput;
  },
): Promise<string> {
  const ref = opts.nonce();
  const inputs: DecisionInputs = {
    principal: { brain: "verax-proxy", scopes: [] },
    inputs: [],
    control: row.control,
  };
  const inputsHash = sha256Canonical(inputs);
  await opts.inputsLog.append(ref, inputs);
  await opts.writer.appendDecisionChained((prevRecordHash) =>
    signDecisionRecord(
      {
        decider: "verax-proxy",
        subject: row.subject,
        requestHash: row.requestHash,
        policyHash: opts.policyHash,
        inputsHash,
        decision: row.decision,
        reasonCode: row.reasonCode,
        ref,
        effectHash: row.effectHash,
        effectClass: row.effectClass,
        timestampMs: row.timestampMs,
        nonce: ref,
        prevRecordHash,
      },
      opts.recordSigner.privateKeyPem,
      opts.recordSigner.publicKeyPem,
    ),
  );
  return ref;
}
