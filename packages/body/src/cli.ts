#!/usr/bin/env node
import { readFileSync, realpathSync } from "node:fs";
import path, { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runApprove } from "./approve-cli.ts";
import { attachBodyLog } from "./body-log.ts";
import { runDemo } from "./demo.ts";
import { doctorBodyLog, doctorExit, runDoctor } from "./doctor.ts";
import { clearVeraxEnv, envFileJwksMissing, loadEnvFile, runInitLocal } from "./init-local.ts";
import { clearCliCodeCheckPassed, defaultElevated, directoryAccess, doctorStateTarget, elevatedCommandCodeRefusal, linuxNodeLabelCheck, linuxSelinuxCheck, liveInstalledChecks, markCliCodeCheckPassed, runInstall, runUninstall, SystemToolError, unreadableSentence } from "./install.ts";
import { runHalt, runResume } from "./halt.ts";
import { main } from "./main.ts";
import { runOperator } from "./operator-cli.ts";
import { runReconcile } from "./reconcile-cli.ts";
import { runVerify } from "./verify-cli.ts";
import { runUnlock } from "./unlock.ts";
import { runWitness } from "./witness.ts";

const HELP = `verax - the body an agent asks before it acts, and the ledger it answers from.

Usage: verax <command> [options]

  (no command)         serve MCP over Streamable HTTP at /mcp on VERAX_BIND (default 127.0.0.1:8787)
  serve [--env-file <file>] [--log-file <file>]
                       same as serving, after loading KEY=VALUE lines from that file.
                       --log-file appends this process's stdout and stderr
  init --local <stateDir> [--force] [--days N] [--port N]
                       write a loopback key, one agent token, and verax.env
  install [--port N] [--days N] [--force]
                       copy this body to an administrator-owned directory and run it
                       as another account. Needs an elevated shell, and this program
                       must live in a directory only an administrator can change.
                       On Windows the agent token is under %ProgramData%\\Verax\\agent-token\\<SID>\\.
                       On Linux and macOS a process running as the invoking user writes ~/.verax/agent.token.
  uninstall [--keep-state]
                       stop that body and remove its code. Needs an elevated shell
                       and the same administrator-owned copy.
  doctor [--json]      check the configuration this process would run with
  demo [--keep]        run a loopback body against a temporary ledger and print what it recorded
       [--with-conarium]  also fetch Conarium with npx, attach it as a child, and put a masked read through the gate
  approve <args>       approve a waiting request from this machine.
                       On Windows the panel with a passkey is how a held call is approved.
                       An elevated CLI approve is a fallback from a separate administrator
                       account, not this account elevated:
                       "%ProgramFiles%\\verax-cli\\verax.cmd" approve.
                       Linux and macOS the root-owned Node, for example
                       sudo /opt/verax-node/<dir>/bin/node /opt/verax-cli/lib/node_modules/@verax-ai/body/dist/cli.js approve
                       or sudo /usr/bin/node with that same cli.js.
  operator <args>      enrol an operator and manage their passkeys
  reconcile <args>     compare the ledger against a statement
  verify <stateDir>    read a ledger back without a body: signatures, chain,
                       effect binding, and which key answered
  witness <stateDir>   run the witness alongside a body
  halt <stateDir>      stop the body from allowing anything further
  resume <stateDir>    lift a halt; who and when go to halt-history.jsonl
  unlock [--force] <stateDir>   clear a stale ledger lock

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

export type CliHooks = {
  elevated?: () => boolean;
  codeProbe?: (dir: string) => boolean;
  /** True when that Node path can be changed by the invoking user. See `NodeTrustProbe`. */
  execPathProbe?: (file: string) => boolean;
  /** Defaults to `process.execArgv` for the elevated preload check. */
  execArgv?: readonly string[];
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  stdout?: { write(s: string): unknown };
  stderr?: { write(s: string): unknown };
};

function isCliEntry(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  // npm starts the CLI through a symbolic link (`bin/verax`, `node_modules/.bin/verax`): compare
  // real paths, or a linked start runs nothing and exits 0.
  try {
    return realpathSync(path.resolve(entry)) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

/**
 * One gate for every command except `--help` and `--version`. An elevated
 * process refuses code the invoking user can change before the command runs.
 * Install and approve keep their own check for direct callers; the flag stops
 * a second check in this process.
 */
export async function runCli(argv: string[], hooks: CliHooks = {}): Promise<number> {
  const stdout = hooks.stdout ?? process.stdout;
  const stderr = hooks.stderr ?? process.stderr;
  const platform = hooks.platform ?? process.platform;
  const env = hooks.env ?? process.env;
  if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
    stdout.write(HELP);
    return 0;
  }
  if (argv[0] === "--version" || argv[0] === "-v") {
    stdout.write(`${version()}\n`);
    return 0;
  }
  let isElevated = false;
  try {
    isElevated = hooks.elevated ? hooks.elevated() : defaultElevated(platform);
  } catch (err) {
    if (err instanceof SystemToolError) {
      stderr.write(`${err.message}\n`);
      return 78;
    }
    throw err;
  }
  if (isElevated) {
    const refusal = elevatedCommandCodeRefusal(platform, env, hooks.codeProbe, {
      execPathProbe: hooks.execPathProbe,
      execArgv: hooks.execArgv,
    });
    if (refusal) {
      stderr.write(refusal.endsWith("\n") ? refusal : `${refusal}\n`);
      return 78;
    }
    markCliCodeCheckPassed();
  }
  try {
    if (isElevated && argv[0] === "demo" && argv.includes("--with-conarium")) {
      stderr.write(
        "refusing: demo --with-conarium fetches and runs code with npx; run it from a terminal that is not elevated\n",
      );
      return 78;
    }
    return await dispatchCli(argv, stdout, stderr, env);
  } finally {
    clearCliCodeCheckPassed();
  }
}

async function dispatchCli(
  argv: string[],
  stdout: { write(s: string): unknown },
  stderr: { write(s: string): unknown },
  env: NodeJS.ProcessEnv,
): Promise<number> {
  if (argv[0] === "demo") {
    return runDemo(argv, env, {
      stdout,
      stderr,
      stdin: process.stdin,
      isTTY: Boolean(process.stdin.isTTY),
    });
  }
  if (argv[0] === "approve") {
    return runApprove(argv);
  }
  if (argv[0] === "operator") {
    return runOperator(argv);
  }
  if (argv[0] === "halt") {
    const stateDir = argv[1];
    if (!stateDir) {
      stderr.write("verax halt <stateDir>\n");
      return 78;
    }
    return runHalt(stateDir, (s) => stderr.write(s));
  }
  if (argv[0] === "resume") {
    const stateDir = argv[1];
    if (!stateDir) {
      stderr.write("verax resume <stateDir>\n");
      return 78;
    }
    return runResume(stateDir, (s) => stderr.write(s));
  }
  if (argv[0] === "unlock") {
    const force = argv.includes("--force");
    const stateDir = argv.slice(1).find((a) => a !== "--force");
    if (!stateDir) {
      stderr.write("verax unlock [--force] <stateDir>\n");
      return 78;
    }
    return runUnlock(stateDir, (s) => stderr.write(s), { force });
  }
  if (argv[0] === "init") {
    return runInitLocal(argv.slice(1));
  }
  if (argv[0] === "install") {
    return runInstall(argv);
  }
  if (argv[0] === "uninstall") {
    return runUninstall(argv);
  }
  if (argv[0] === "serve") {
    const logFlag = argv.indexOf("--log-file");
    if (logFlag !== -1) {
      const logPath = argv[logFlag + 1];
      if (!logPath || logPath.startsWith("-")) {
        stderr.write("verax serve --log-file <file>\n");
        return 78;
      }
      const attached = attachBodyLog(logPath);
      if (!attached.ok) {
        stderr.write(`${attached.reason}\n`);
        return 78;
      }
      stderr.write("verax serve starting\n");
    }
    const fileFlag = argv.indexOf("--env-file");
    if (fileFlag !== -1) {
      const file = argv[fileFlag + 1];
      if (!file || file.startsWith("-")) {
        stderr.write("verax serve --env-file <file>\n");
        return 78;
      }
      clearVeraxEnv(process.env);
      const loaded = loadEnvFile(file);
      if (!loaded.ok) {
        stderr.write(`${loaded.reason}\n`);
        return 78;
      }
      const missingJwks = envFileJwksMissing(process.env);
      if (missingJwks) {
        stderr.write(`${missingJwks}\n`);
        return 78;
      }
    }
    await main();
    // main() returns once the server is listening. The open socket keeps the
    // process up; this promise stops the rest of the dispatcher from running.
    await new Promise(() => {});
  }
  if (argv[0] === "doctor") {
    const json = argv.includes("--json");
    const target = doctorStateTarget(env);
    if (target && directoryAccess(target) === "unreadable") {
      stderr.write(`${unreadableSentence(target, "doctor")}\n`);
      return 77;
    }
    const nodeLabel = process.platform === "linux" ? linuxNodeLabelCheck() : null;
    const checks = [
      ...runDoctor(env, process.argv),
      ...liveInstalledChecks(),
      ...(process.platform === "linux" ? [linuxSelinuxCheck()] : []),
      ...(nodeLabel ? [nodeLabel] : []),
    ];
    const bodyLog = target ? doctorBodyLog(target) : "";
    if (json) {
      stdout.write(`${JSON.stringify(target ? { checks, bodyLog } : { checks })}\n`);
    } else {
      for (const c of checks) {
        stdout.write(`${c.level}\t${c.id}\t${c.detail}\n`);
      }
      if (bodyLog !== "") stdout.write(bodyLog);
    }
    return doctorExit(checks);
  }
  if (argv[0] === "reconcile") {
    return runReconcile(argv, (s) => stderr.write(s));
  }
  if (argv[0] === "verify") {
    return runVerify(argv.slice(1), (s) => stdout.write(`${s}\n`));
  }
  if (argv[0] === "desktop") {
    stderr.write("desktop-not-in-0.4.0: the desktop panel ships in 0.4.1\n");
    return 64;
  }
  if (argv[0] === "witness") {
    const stateDir = argv[1];
    if (!stateDir) {
      stderr.write("verax witness <stateDir>\n");
      return 78;
    }
    await runWitness(stateDir);
    return 0;
  }
  const head = argv[0];
  if (head !== undefined && !head.startsWith("--")) {
    stderr.write(`unknown command: ${head}\n`);
    stderr.write(HELP);
    return 64;
  }
  // `main()` reads `--inventory`. Any other leading flag is not a serve option.
  if (head !== undefined && head.startsWith("--") && head !== "--inventory") {
    stderr.write(`unknown option: ${head}\n`);
    stderr.write(HELP);
    return 64;
  }
  await main();
  // main() returns once the server is listening. The open socket keeps the
  // process up, the same way as `serve`.
  await new Promise(() => {});
  return 0;
}

if (isCliEntry()) {
  process.exit(await runCli(process.argv.slice(2)));
}
