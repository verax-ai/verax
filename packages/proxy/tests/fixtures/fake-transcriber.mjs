#!/usr/bin/env node
// Stand-in for a local speech-to-text command (tests only).
// argv: <file> <mode> [<report.json>]
//   ok    prints the transcript in transcript-tr.txt (a real large-v3-turbo transcript
//         of a synthetic Turkish recording that carries test values only)
//   empty prints nothing; fail exits 1; slow waits 10 s, then prints
//   tree  starts a child that holds the file open for 30 s, as a launcher such
//         as Windows' py.exe leaves python.exe behind, then waits like slow
//   escape starts a child outside its process group that keeps stdout open
//         for 30 s, then waits like slow
// With a report path it writes what it was given, so a test can check the file
// it read, its size, and that the file is gone after the call.

import { spawn } from "node:child_process";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [file, mode = "ok", report] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));

let holderPid;
if (mode === "tree") {
  const holder = spawn(
    process.execPath,
    ["-e", "require('node:fs').openSync(process.argv[1], 'r'); setTimeout(() => {}, 30000)", file],
    { stdio: "ignore" },
  );
  holderPid = holder.pid;
}
if (mode === "escape") {
  const escaped = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], {
    detached: true,
    stdio: ["ignore", "inherit", "ignore"],
  });
  escaped.unref();
  holderPid = escaped.pid;
}

if (report) {
  const bytes = readFileSync(file);
  writeFileSync(
    report,
    JSON.stringify({
      file,
      size: bytes.length,
      base64: bytes.toString("base64"),
      dirMode: statSync(dirname(file)).mode & 0o777,
      ...(holderPid !== undefined ? { holderPid } : {}),
    }),
    "utf8",
  );
}

const transcript = readFileSync(join(here, "transcript-tr.txt"), "utf8");

if (mode === "fail") process.exit(1);
if (mode === "empty") process.exit(0);
if (mode === "slow" || mode === "tree" || mode === "escape") {
  setTimeout(() => {
    process.stdout.write(transcript);
  }, 10_000);
} else {
  process.stdout.write(transcript);
}
