/**
 * Child process helper: start the hosted anchor service and print one ready
 * line, then stay up until the parent kills it. Used by the cross-process
 * store-lock test so the holder is not the same Node process as the test.
 */
import { loadConfig, startService } from "../packages/anchor-service/src/index.ts";

const beatRaw = process.env.VERAX_ANCHOR_SVC_LOCK_BEAT_MS?.trim() ?? "40";
const lockBeatMs = Number(beatRaw);
if (!Number.isInteger(lockBeatMs) || lockBeatMs < 20 || lockBeatMs > 60_000) {
  process.stderr.write("VERAX_ANCHOR_SVC_LOCK_BEAT_MS must be an integer 20..60000\n");
  process.exit(64);
}

const config = loadConfig();
const running = await startService(config, { lockBeatMs });
process.stdout.write(`ready ${running.url}\n`);
