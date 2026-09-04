import { closeSync, openSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";

const path = process.env.VERAX_LOCK_PATH;
const ready = process.env.VERAX_READY_PATH;
if (!path || !ready) {
  process.stderr.write("missing VERAX_LOCK_PATH or VERAX_READY_PATH\n");
  process.exit(2);
}

if (process.platform === "win32") {
  // Node openSync shares delete, so rename succeeds. FileShare.None surfaces EBUSY.
  const ps = [
    "$fs = [System.IO.File]::Open($env:VERAX_LOCK_PATH, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)",
    "[System.IO.File]::WriteAllText($env:VERAX_READY_PATH, '1')",
    "Start-Sleep -Milliseconds 60",
    "$fs.Dispose()",
  ].join("; ");
  const child = spawn("powershell.exe", ["-NoProfile", "-Command", ps], {
    env: process.env,
    stdio: "inherit",
  });
  const code = await new Promise<number>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (exit) => resolve(exit ?? 1));
  });
  process.exit(code);
}

const fd = openSync(path, "r+");
writeFileSync(ready, "1\n");
await new Promise((resolve) => setTimeout(resolve, 60));
closeSync(fd);
