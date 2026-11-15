/**
 * Child process helper: try to take the store lock once and print held or
 * refused. Used by the multi-process stale-lock takeover race.
 */
import { acquireStoreLock } from "../packages/anchor-service/src/store-lock.ts";

const storePath = process.env.VERAX_ANCHOR_SVC_STORE?.trim() ?? "";
if (storePath === "") {
  process.stderr.write("VERAX_ANCHOR_SVC_STORE is required\n");
  process.exit(64);
}
const beatRaw = process.env.VERAX_ANCHOR_SVC_LOCK_BEAT_MS?.trim() ?? "40";
const lockBeatMs = Number(beatRaw);
if (!Number.isInteger(lockBeatMs) || lockBeatMs < 20 || lockBeatMs > 60_000) {
  process.stderr.write("VERAX_ANCHOR_SVC_LOCK_BEAT_MS must be an integer 20..60000\n");
  process.exit(64);
}

try {
  const lock = acquireStoreLock(storePath, { lockBeatMs });
  process.stdout.write("held\n");
  const stop = (): void => {
    lock.release();
    process.exit(0);
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  // Keep the event loop alive (do not unref) so the parent can observe a live holder.
  setInterval(() => {}, 60_000);
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.startsWith("store already locked:") || msg.startsWith("store lock takeover gate is present")) {
    process.stdout.write("refused\n");
    process.exit(0);
  }
  process.stderr.write(`${msg}\n`);
  process.exit(1);
}
