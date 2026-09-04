import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { FileLedger } from "../src/ledger.ts";

const dir = process.env.VERAX_LOCK_DIR;
if (!dir) {
  process.stderr.write("missing VERAX_LOCK_DIR\n");
  process.exit(2);
}

writeFileSync(join(dir, `ready-${process.pid}`), "1\n");
const go = join(dir, "GO");
while (!existsSync(go)) {
  /* wait for the sibling */
}

try {
  const ledger = new FileLedger(dir);
  process.stdout.write("OPENED\n");
  await new Promise((resolve) => setTimeout(resolve, 2500));
  ledger.close();
  process.exit(0);
} catch (err) {
  process.stdout.write(`ERR:${err instanceof Error ? err.message : "unknown"}\n`);
  process.exit(0);
}
