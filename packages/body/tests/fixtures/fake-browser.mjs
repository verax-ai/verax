#!/usr/bin/env node
// Stays alive until killed. Writes its pid so the desktop test can close it.
import { writeFileSync } from "node:fs";

const dest = process.env.VERAX_FAKE_BROWSER_PID;
if (!dest) {
  process.stderr.write("fake-browser missing VERAX_FAKE_BROWSER_PID\n");
  process.exit(2);
}
writeFileSync(dest, String(process.pid), { encoding: "utf8" });
setInterval(() => {}, 1 << 30);
