/**
 * Durable in-flight marks: "this ref started running".
 *
 * The in-memory registry that stops a second run dies with the process. On the
 * approved path an `allow` does not mean the tool ran — it means the operator
 * said yes — so a restarted body cannot tell "approved, never started" from
 * "approved, started, crashed before the effect". Without that distinction it
 * has to either run everything twice or run nothing at all.
 *
 * A mark is one empty file per ref, created before `inner` and removed after
 * the effect is written. One file per ref rather than a shared log because two
 * refs may start and finish at the same moment: file create and unlink need no
 * lock, a shared append-only log would need a compaction pass and would race.
 *
 * A mark left behind by a crash is exactly the signal wanted: it outlives the
 * process, and the retry that finds it answers `outcome-unknown` instead of
 * running the tool a second time.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const KLASOR = "in-flight";

/** Ref may carry a tenant prefix and any path character; the name never does. */
function markPath(stateDir: string, ref: string): string {
  const ad = createHash("sha256").update(ref, "utf8").digest("hex").slice(0, 32);
  return join(stateDir, KLASOR, `${ad}.start`);
}

/**
 * Called before `inner` runs. A failure here must not block the call.
 *
 * The stamp is wall-clock time and not the proxy's injected `now`: a mark is
 * not a ledger row, and taking a tick from a deterministic clock would shift
 * every timestamp recorded after it — the golden ledger caught exactly that.
 */
export function markStarted(stateDir: string, ref: string, subject: string): void {
  try {
    mkdirSync(join(stateDir, KLASOR), { recursive: true, mode: 0o700 });
    // The body is for a human reading the directory after a crash; nothing parses it.
    writeFileSync(markPath(stateDir, ref), `${JSON.stringify({ ref, subject, atMs: Date.now() })}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
  } catch {
    // A missing mark degrades to today's behaviour, it does not deny the call.
  }
}

/** Called once the effect row is written, on success and on failure alike. */
export function markEnded(stateDir: string, ref: string): void {
  try {
    rmSync(markPath(stateDir, ref), { force: true });
  } catch {
    // Leaving a stale mark makes the next retry cautious, never wrong.
  }
}

/** True when a run started and no end was recorded: the outcome is unknown. */
export function startedWithoutEnd(stateDir: string, ref: string): boolean {
  try {
    return existsSync(markPath(stateDir, ref));
  } catch {
    return false;
  }
}
