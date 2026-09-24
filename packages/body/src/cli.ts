#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runApprove } from "./approve-cli.ts";
import { runDemo } from "./demo.ts";
import { desktopMain } from "./desktop.ts";
import { doctorExit, runDoctor } from "./doctor.ts";
import { loadEnvFile, runInitLocal } from "./init-local.ts";
import { runHalt } from "./halt.ts";
import { main } from "./main.ts";
import { runOperator } from "./operator-cli.ts";
import { runReconcile } from "./reconcile-cli.ts";
import { runVerify } from "./verify-cli.ts";
import { runUnlock } from "./unlock.ts";
import { runWitness } from "./witness.ts";

const HELP = `verax - the body an agent asks before it acts, and the ledger it answers from.

Usage: verax <command> [options]

  (no command)         serve MCP over Streamable HTTP at /mcp on VERAX_BIND (default 127.0.0.1:8787)
  serve [--env-file <file>]  same as serving, after loading KEY=VALUE lines from that file
  init --local <stateDir> [--force] [--days N] [--port N]
                       write a loopback key, one agent token, and verax.env
  doctor [--json]      check the configuration this process would run with
  demo [--keep]        run a loopback body against a temporary ledger and print what it recorded
       [--with-conarium]  also fetch Conarium with npx, attach it as a child, and put a masked read through the gate
  approve <args>       approve a waiting request from this machine
  operator <args>      enrol an operator and manage their passkeys
  reconcile <args>     compare the ledger against a statement
  verify <stateDir>    read a ledger back without a body: signatures, chain,
                       effect binding, and which key answered
  witness <stateDir>   run the witness alongside a body
  halt <stateDir>      stop the body from allowing anything further
  unlock [--force] <stateDir>   clear a stale ledger lock
  desktop <args>       open the local panel, joining the body that holds the ledger if one is up

  --help, -h           print this
  --version, -v        print the version

Serving needs VERAX_ISSUER, one of VERAX_JWKS_URL or VERAX_JWKS_FILE, VERAX_AUDIENCE,
VERAX_STATE_DIR and VERAX_POLICY_FILE; \`verax doctor\` names what is missing.
Records stay on this machine, under VERAX_STATE_DIR.
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
if (argv[0] === "demo") {
  process.exit(
    await runDemo(argv, process.env, {
      stdout: process.stdout,
      stderr: process.stderr,
      stdin: process.stdin,
      isTTY: Boolean(process.stdin.isTTY),
    }),
  );
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
if (argv[0] === "init") {
  process.exit(await runInitLocal(argv.slice(1)));
}
if (argv[0] === "serve") {
  const fileFlag = argv.indexOf("--env-file");
  if (fileFlag !== -1) {
    const file = argv[fileFlag + 1];
    if (!file || file.startsWith("-")) {
      process.stderr.write("verax serve --env-file <file>\n");
      process.exit(78);
    }
    const loaded = loadEnvFile(file);
    if (!loaded.ok) {
      process.stderr.write(`${loaded.reason}\n`);
      process.exit(78);
    }
  }
  await main();
  // main() returns once the server is listening. The open socket keeps the
  // process up; this promise stops the rest of the dispatcher from running.
  await new Promise(() => {});
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
if (argv[0] === "verify") {
  process.exit(await runVerify(argv.slice(1)));
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
