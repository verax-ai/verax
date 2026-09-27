import { chmodSync, openSync, readFileSync, writeSync } from "node:fs";

/**
 * Append this process's stdout and stderr to `file`.
 * POSIX: the file is mode 0600 (umask cannot widen it).
 * Windows: CreateFile sets no explicit DACL, so the new file inherits the
 * parent directory ACL. The state directory's service ACL is that parent.
 */
export function attachBodyLog(file: string): { ok: true } | { ok: false; reason: string } {
  let fd: number;
  try {
    fd = openSync(file, "a", 0o600);
  } catch (err) {
    return { ok: false, reason: `cannot open log file ${file}: ${(err as Error).message}` };
  }
  if (process.platform !== "win32") {
    try {
      chmodSync(file, 0o600);
    } catch {
      // The platform does not honour the mode bit.
    }
  }
  const append = (chunk: string | Uint8Array, encoding?: BufferEncoding): void => {
    try {
      const buf = typeof chunk === "string" ? Buffer.from(chunk, encoding ?? "utf8") : Buffer.from(chunk);
      writeSync(fd, buf);
    } catch {
      // A full disk must not hide the line already going to the console.
    }
  };
  tee(process.stdout, append);
  tee(process.stderr, append);
  return { ok: true };
}

function tee(
  stream: NodeJS.WriteStream,
  append: (chunk: string | Uint8Array, encoding?: BufferEncoding) => void,
): void {
  const original = stream.write.bind(stream);
  stream.write = ((
    chunk: string | Uint8Array,
    encoding?: BufferEncoding | ((err?: Error | null) => void),
    cb?: (err?: Error | null) => void,
  ): boolean => {
    if (typeof encoding === "function") {
      append(chunk);
      return original(chunk, encoding);
    }
    append(chunk, encoding);
    return original(chunk, encoding, cb);
  }) as typeof stream.write;
}

/** Last `n` lines, or null when the file cannot be read. A trailing newline is not an extra line. */
export function readLogTail(file: string, n: number): string | null {
  try {
    const text = readFileSync(file, "utf8");
    const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    const tail = lines.slice(-n).join("\n");
    return tail === "" ? "" : `${tail}\n`;
  } catch {
    return null;
  }
}
