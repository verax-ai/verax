/**
 * Checks for signing-key and token-map files: regular files only, no symlinks,
 * and on POSIX no group/other read or write. Errors name the class of problem,
 * never the file contents.
 */
import { lstatSync } from "node:fs";

export function assertSecretFile(path: string, label: string): void {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(path);
  } catch {
    throw new Error(`cannot read ${label}`);
  }
  if (st.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link`);
  }
  if (!st.isFile()) {
    throw new Error(`${label} must be a regular file`);
  }
  if (process.platform !== "win32") {
    const mode = st.mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(`${label} must not be readable or writable by group or others`);
    }
  }
}
