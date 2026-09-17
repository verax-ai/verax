import { join } from "node:path";
import { appendDurable, ledgerFs } from "./ledger.ts";
import type { DecisionInputs, InputsLog } from "./types.ts";

type Row = { ref: string; inputs: DecisionInputs };

export class MemoryInputsLog implements InputsLog {
  private readonly rows = new Map<string, DecisionInputs>();

  async append(ref: string, inputs: DecisionInputs): Promise<void> {
    this.rows.set(ref, inputs);
  }

  async get(ref: string): Promise<DecisionInputs | null> {
    return this.rows.get(ref) ?? null;
  }
}

export class FileInputsLog implements InputsLog {
  private readonly dir: string;
  private readonly resolve: (() => { active: string; all: string[] }) | undefined;
  private readonly note: ((ref: string, inputs: DecisionInputs) => void) | undefined;

  constructor(
    dir: string,
    resolve?: () => { active: string; all: string[] },
    note?: (ref: string, inputs: DecisionInputs) => void,
  ) {
    this.dir = dir;
    this.resolve = resolve;
    this.note = note;
  }

  private paths(): { active: string; all: string[] } {
    if (this.resolve) return this.resolve();
    const root = join(this.dir, "inputs.jsonl");
    return { active: root, all: [root] };
  }

  async append(ref: string, inputs: DecisionInputs): Promise<void> {
    await appendDurable(this.paths().active, `${JSON.stringify({ ref, inputs })}\n`);
    // Handed to the ledger in memory: the decision that follows needs the
    // principal for its index line and must not read this file back.
    this.note?.(ref, inputs);
  }

  async get(ref: string): Promise<DecisionInputs | null> {
    let found: DecisionInputs | null = null;
    for (const path of this.paths().all) {
      let text: string;
      try {
        text = await ledgerFs.readFile(path, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw err;
      }
      for (const line of text.split("\n")) {
        if (line === "") continue;
        const row = JSON.parse(line) as Row;
        if (row.ref === ref) found = row.inputs;
      }
    }
    return found;
  }
}

const STASH = Symbol.for("verax.inputsLog");

export function inputsLogFor(ledger: object): InputsLog {
  const bag = ledger as {
    dir?: unknown;
    inputsPaths?: () => { active: string; all: string[] };
    noteInputs?: (ref: string, inputs: DecisionInputs) => void;
    [STASH]?: InputsLog;
  };
  if (bag[STASH]) return bag[STASH];
  const resolve = typeof bag.inputsPaths === "function" ? () => bag.inputsPaths!() : undefined;
  const note = typeof bag.noteInputs === "function" ? (ref: string, inputs: DecisionInputs) => bag.noteInputs!(ref, inputs) : undefined;
  const log = typeof bag.dir === "string" ? new FileInputsLog(bag.dir, resolve, note) : new MemoryInputsLog();
  bag[STASH] = log;
  return log;
}
