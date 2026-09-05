import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { appendDurable } from "./ledger.ts";
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

  constructor(dir: string) {
    this.dir = dir;
  }

  async append(ref: string, inputs: DecisionInputs): Promise<void> {
    await appendDurable(join(this.dir, "inputs.jsonl"), `${JSON.stringify({ ref, inputs })}\n`);
  }

  async get(ref: string): Promise<DecisionInputs | null> {
    let text: string;
    try {
      text = await readFile(join(this.dir, "inputs.jsonl"), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
    let found: DecisionInputs | null = null;
    for (const line of text.split("\n")) {
      if (line === "") continue;
      const row = JSON.parse(line) as Row;
      if (row.ref === ref) found = row.inputs;
    }
    return found;
  }
}

const STASH = Symbol.for("verax.inputsLog");

export function inputsLogFor(ledger: object): InputsLog {
  const bag = ledger as { dir?: unknown; [STASH]?: InputsLog };
  if (bag[STASH]) return bag[STASH];
  const log = typeof bag.dir === "string" ? new FileInputsLog(bag.dir) : new MemoryInputsLog();
  bag[STASH] = log;
  return log;
}
