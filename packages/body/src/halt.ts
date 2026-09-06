import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function runHalt(
  stateDir: string,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
): number {
  if (!stateDir) {
    writeErr("verax halt <stateDir>\n");
    return 78;
  }
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  writeFileSync(join(stateDir, "halted"), "", { encoding: "utf8", mode: 0o600 });
  writeErr("halted\n");
  return 0;
}
