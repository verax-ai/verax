#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runApprove } from "./approve-cli.ts";
import { desktopMain } from "./desktop.ts";
import { doctorExit, runDoctor } from "./doctor.ts";
import { runHalt } from "./halt.ts";
import { main } from "./main.ts";
import { runOperator } from "./operator-cli.ts";
import { runReconcile } from "./reconcile-cli.ts";
import { runUnlock } from "./unlock.ts";
import { runWitness } from "./witness.ts";

const HELP = `verax - the body an agent asks before it acts, and the ledger it answers from.

Usage: verax <command> [options]

  (no command)         serve the body over MCP stdio, or HTTP when VERAX_PORT is set
  doctor [--json]      check the configuration this process would run with
  approve <args>       approve a waiting request from this machine
  operator <args>      enrol an operator and manage their passkeys
  reconcile <args>     compare the ledger against a statement
  witness <stateDir>   run the witness alongside a body
  halt <stateDir>      stop the body from allowing anything further
  unlock [--force] <stateDir>   clear a stale ledger lock
  desktop <args>       open the local panel

  --help, -h           print this
  --version, -v        print the version

Serving needs VERAX_ISSUER, VERAX_JWKS_URL and VERAX_AUDIENCE; \`verax doctor\`
names what is missing. Records stay on this machine, under VERAX_STATE_DIR.
`;

function version(): string {
  // The published package answers with its own version, not a copy of it.
  const here = dirname(fileURLToPath(import.meta.url));
  for (const path of [join(here, "..", "package.json"), join(here, "..", "..", "package.json")]) {
    try {
      const raw = JSON.parse(readFileSync(path, "utf8")) as { name?: string; version?: string };
      if (raw.name === "@verax-ai/body" && typeof raw.version === "string") return raw.version;
    } catch {
      // try the next candidate: the file layout differs between src and dist.
    }
  }
  return "unknown";
}

const argv = process.argv.slice(2);
// Asking what this is must work before it is configured. Without this, the
// first thing a published `verax --help` said was that three environment
// variables were missing.
if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
  process.stdout.write(HELP);
  process.exit(0);
}
if (argv[0] === "--version" || argv[0] === "-v") {
  process.stdout.write(`${version()}\n`);
  process.exit(0);
}
if (argv[0] === "approve") {
  process.exit(await runApprove(argv));
}
if (argv[0] === "operator") {
  process.exit(await runOperator(argv));
}
if (argv[0] === "halt") {
  const stateDir = argv[1];
  if (!stateDir) {
    process.stderr.write("verax halt <stateDir>\n");
    process.exit(78);
  }
  process.exit(runHalt(stateDir));
}
if (argv[0] === "unlock") {
  const force = argv.includes("--force");
  const stateDir = argv.slice(1).find((a) => a !== "--force");
  if (!stateDir) {
    process.stderr.write("verax unlock [--force] <stateDir>\n");
    process.exit(78);
  }
  process.exit(runUnlock(stateDir, (s) => process.stderr.write(s), { force }));
}
if (argv[0] === "doctor") {
  const json = argv.includes("--json");
  const checks = runDoctor(process.env, process.argv);
  if (json) {
    process.stdout.write(`${JSON.stringify({ checks })}\n`);
  } else {
    for (const c of checks) {
      process.stdout.write(`${c.level}\t${c.id}\t${c.detail}\n`);
    }
  }
  process.exit(doctorExit(checks));
}
if (argv[0] === "reconcile") {
  process.exit(runReconcile(argv));
}
if (argv[0] === "desktop") {
  process.exit(await desktopMain(argv));
}
if (argv[0] === "witness") {
  const stateDir = argv[1];
  if (!stateDir) {
    process.stderr.write("verax witness <stateDir>\n");
    process.exit(78);
  }
  await runWitness(stateDir);
  process.exit(0);
}

await main();
