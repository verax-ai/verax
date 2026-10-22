import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Process-wide halt gate. The on-disk switch is `<stateDir>/halted`; when that
 * file cannot be written the proxy still refuses every tool for the rest of
 * this process. The set lives on `globalThis` so source and dist copies of
 * this module share one flag.
 */
const FLAG = Symbol.for("verax.process-halt");
export const HALT_SWITCH = "halted";

type HaltBag = { dirs: Set<string> };

function bag(): HaltBag {
  const g = globalThis as typeof globalThis & { [FLAG]?: HaltBag };
  const existing = g[FLAG];
  if (existing) return existing;
  const created: HaltBag = { dirs: new Set<string>() };
  g[FLAG] = created;
  return created;
}

function keyOf(stateDir: string): string {
  return resolve(stateDir);
}

export function haltSwitchPath(stateDir: string): string {
  return join(stateDir, HALT_SWITCH);
}

export function isHaltedSwitchFile(stateDir: string): boolean {
  try {
    return statSync(haltSwitchPath(stateDir)).isFile();
  } catch {
    return false;
  }
}

export function markProcessHalted(stateDir: string): void {
  bag().dirs.add(keyOf(stateDir));
}

export function isProcessHalted(stateDir: string): boolean {
  return bag().dirs.has(keyOf(stateDir));
}

export function clearProcessHalted(stateDir: string): void {
  bag().dirs.delete(keyOf(stateDir));
}

/** If the process flag is set and the switch path is free, write the empty file. */
export function persistHaltedSwitch(stateDir: string): boolean {
  if (isHaltedSwitchFile(stateDir)) return true;
  if (!isProcessHalted(stateDir)) return false;
  const path = haltSwitchPath(stateDir);
  try {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    if (existsSync(path)) return false;
    writeFileSync(path, "", { encoding: "utf8", mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

export function isProxyHalted(stateDir: string): boolean {
  persistHaltedSwitch(stateDir);
  return isHaltedSwitchFile(stateDir) || isProcessHalted(stateDir);
}
