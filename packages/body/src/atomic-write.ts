import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Replace a file's contents in one step, so a reader sees the old bytes or the
 * new ones and never a half-written file.
 *
 * Writing in place is not that: measured on 11 Sep 2026, a reader polling this
 * path every 20 ms while the file was rewritten 60 times got 12 unparseable
 * reads. The listen file is read by another process - that is its whole job -
 * and a torn read becomes `null`, which the caller cannot tell from "nothing
 * is running".
 *
 * The rename needs the retry. On Windows it fails with EPERM while a reader
 * holds the destination open, and in the same measurement 26 of 60 plain
 * renames failed that way. Retrying briefly lost none of them and still let no
 * torn read through.
 *
 * The temporary name carries this process and a random suffix. A fixed `.tmp`
 * next to the destination is what two writers, or a crashed writer, collide
 * on.
 */
const napper = new Int32Array(new SharedArrayBuffer(4));

/**
 * Sleep without spinning. The first version of the retry below burned the
 * processor between attempts, which is the worst thing to do while waiting for
 * another process to let go of a file: under the unit suite's own load the
 * spin starved the reader it was waiting on, the retries ran out in 200 ms,
 * and the write threw EPERM. Atomics.wait yields the core instead.
 */
function napSync(ms: number): void {
  Atomics.wait(napper, 0, 0, ms);
}

export function writeFileAtomic(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  writeFileSync(tmp, text, { encoding: "utf8", mode: 0o600 });
  try {
    for (let attempt = 0; ; attempt += 1) {
      try {
        renameSync(tmp, path);
        chmodSync(path, 0o600);
        return;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        // Two seconds of patience. A reader holds this file for microseconds
        // when the machine is idle; the budget is for the machine that is not.
        if (attempt >= 100 || (code !== "EPERM" && code !== "EACCES" && code !== "EBUSY")) {
          throw err;
        }
        napSync(20);
      }
    }
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // rename may already have moved it
    }
    throw err;
  }
}
