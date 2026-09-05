import { FileLedger } from "../src/ledger.ts";

const dir = process.env.VERAX_LOCK_DIR;
if (!dir) {
  process.stderr.write("missing VERAX_LOCK_DIR\n");
  process.exit(2);
}

function holdUntilStdinCloses(): Promise<void> {
  return new Promise((resolve) => {
    const done = () => resolve();
    process.stdin.on("end", done);
    process.stdin.on("close", done);
    process.stdin.resume();
  });
}

try {
  const ledger = new FileLedger(dir);
  process.stdout.write(`OPENED:${process.pid}\n`);
  await holdUntilStdinCloses();
  ledger.close();
  process.exit(0);
} catch (err) {
  process.stdout.write(`ERR:${err instanceof Error ? err.message.split("\n")[0] : "unknown"}\n`);
  process.exit(0);
}
