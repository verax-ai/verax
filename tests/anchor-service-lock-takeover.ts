/**
 * Child helper for a deterministic stale-lock takeover: pause at a named point
 * until a go-file appears. Argv only (never environment) for the pause point.
 *
 * Usage:
 *   node … anchor-service-lock-takeover.ts <storePath> <beatMs> <pausePoint> <syncDir>
 * pausePoint: after-stale-before-gate | inside-gate-before-recheck |
 *             inside-gate-before-removal | none
 */
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  acquireStoreLock,
  type TakeoverPausePoint,
} from "../packages/anchor-service/src/store-lock.ts";

const storePath = process.argv[2] ?? "";
const beatMs = Number(process.argv[3] ?? "");
const pausePointArg = process.argv[4] ?? "none";
const syncDir = process.argv[5] ?? "";
const id = process.argv[6] ?? "x";

if (storePath === "" || syncDir === "") {
  process.stderr.write("usage: storePath beatMs pausePoint syncDir id\n");
  process.exit(64);
}
if (!Number.isInteger(beatMs) || beatMs < 20 || beatMs > 60_000) {
  process.stderr.write("beatMs must be an integer 20..60000\n");
  process.exit(64);
}

const pausePoint: TakeoverPausePoint | "none" =
  pausePointArg === "after-stale-before-gate" ||
  pausePointArg === "inside-gate-before-recheck" ||
  pausePointArg === "inside-gate-before-removal"
    ? pausePointArg
    : "none";
function sleepMs(ms: number): void {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    /* spin; keep the pause synchronous inside takeOverStale */
  }
}

function waitForGo(point: string): void {
  writeFileSync(join(syncDir, `paused-${id}-${point}`), "1", "utf8");
  const go = join(syncDir, `go-${id}-${point}`);
  const deadline = Date.now() + 15_000;
  while (!existsSync(go)) {
    if (Date.now() > deadline) {
      process.stderr.write(`timed out waiting for ${go}\n`);
      process.exit(1);
    }
    sleepMs(20);
  }
}

try {
  const lock = acquireStoreLock(storePath, {
    lockBeatMs: beatMs,
    pauseAt:
      pausePoint === "none"
        ? undefined
        : (point) => {
            if (point === pausePoint) waitForGo(point);
          },
  });
  process.stdout.write(`held ${id}\n`);
  const stop = (): void => {
    lock.release();
    process.exit(0);
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  setInterval(() => {}, 60_000);
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.startsWith("store already locked:") || msg.startsWith("store lock takeover gate is present")) {
    process.stdout.write(`refused ${id}\n`);
    process.stdout.write(`${msg}\n`);
    process.exit(0);
  }
  process.stderr.write(`${msg}\n`);
  process.exit(1);
}
