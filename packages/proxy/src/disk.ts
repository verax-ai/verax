import { statfsSync } from "node:fs";

const DEFAULT_DISK_FREE_BYTES = 64 * 1024 * 1024;

export function defaultDiskFreeBytes(): number {
  return DEFAULT_DISK_FREE_BYTES;
}

/** Injected by tests. Production uses statfs on stateDir. */
export const diskProbe = {
  failAppend: false,
  freeBytes(dir: string): number {
    const s = statfsSync(dir);
    return Number(s.bavail) * Number(s.bsize);
  },
};
