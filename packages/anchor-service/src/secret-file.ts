/**
 * Checks for signing-key and token-map files: regular files only, no symlinks,
 * and on POSIX no group/other read or write. Errors name the class of problem,
 * never the file contents.
 */
import { lstatSync, type Stats } from "node:fs";

export type SecretStat = Pick<Stats, "mode"> & {
  isSymbolicLink: () => boolean;
  isFile: () => boolean;
};

export type AssertSecretFileOpts = {
  /** Test-only: substitute for lstatSync. Not exposed through the CLI. */
  lstat?: (path: string) => SecretStat;
  /** Test-only: substitute for process.platform. */
  platform?: NodeJS.Platform;
};

export function assertSecretFile(path: string, label: string, opts?: AssertSecretFileOpts): void {
  const lstat = opts?.lstat ?? lstatSync;
  const platform = opts?.platform ?? process.platform;
  let st: SecretStat;
  try {
    st = lstat(path);
  } catch {
    throw new Error(`cannot read ${label}`);
  }
  if (st.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link`);
  }
  if (!st.isFile()) {
    throw new Error(`${label} must be a regular file`);
  }
  if (platform !== "win32") {
    const mode = st.mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(`${label} must not be readable or writable by group or others`);
    }
  }
}
