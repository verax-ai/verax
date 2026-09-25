#!/usr/bin/env node
// Installs what npm would publish, from a directory that is not this one, and
// asks the installed thing to speak. The repository tree proves nothing here:
// Node does not run TypeScript out of node_modules, so a package whose entry
// points at src/*.ts installs cleanly and then fails on first import.
//
// Run: node --experimental-strip-types scripts/pack-smoke.ts

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { packReportFiles } from "./pack-report.ts";

const PACKAGES = ["@verax-ai/inventory", "@verax-ai/proxy", "@verax-ai/body"] as const;

// npm and npx are scripts on Windows and need a shell; node is an executable
// whose path holds a space, and a shell would split it.
function run(cmd: string, args: string[], cwd: string): { status: number; out: string; stdout: string } {
  const shell = process.platform === "win32" && cmd !== process.execPath;
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", shell });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, stdout: r.stdout ?? "" };
}

const failures: string[] = [];
function check(ok: boolean, what: string, detail = ""): void {
  process.stdout.write(`${ok ? "ok  " : "FAIL"} ${what}${detail ? ` - ${detail}` : ""}\n`);
  if (!ok) failures.push(what);
}

const repo = process.cwd();
const packDir = mkdtempSync(join(tmpdir(), "verax-pack-"));
const tarballs = new Map<string, string>();

for (const name of PACKAGES) {
  const packed = run("npm", ["pack", "-w", name, "--pack-destination", packDir, "--silent"], repo);
  check(packed.status === 0, `npm pack ${name}`, packed.status === 0 ? "" : packed.out.slice(0, 400));
  const file = readdirSync(packDir).find((f) => f.startsWith(name.replace("@", "").replace("/", "-")));
  if (!file) {
    check(false, `tarball for ${name}`);
    continue;
  }
  tarballs.set(name, join(packDir, file));
  const listing = run("npm", ["pack", "--dry-run", "--json", "-w", name], repo);
  const { files, why } = packReportFiles(listing.stdout, name);
  check(files.length > 0, `${name}: npm lists the packed files`, why);
  check(!files.some((f) => /^(src|tests)\//.test(f)), `${name}: no sources or tests in the tarball`);
  check(
    !files.some((f) => f.endsWith(".ts") && !f.endsWith(".d.ts")),
    `${name}: no TypeScript entry files`,
    files.filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts")).join(" "),
  );
  check(files.includes("dist/index.js"), `${name}: ships dist/index.js`);
  // npm renders README.md as the package page and shows nothing without it;
  // the license text has to travel with what it licenses.
  check(files.includes("README.md"), `${name}: ships README.md`);
  check(files.includes("LICENSE"), `${name}: ships LICENSE`);
  check(!files.some((f) => /(^|\/)state\/|\.pem$|dev-token/.test(f)), `${name}: no keys or state`);
}

// A consumer that is not this repository. The two libraries are pinned through
// overrides because they are not on the registry yet; body asks for them by name.
const consumer = mkdtempSync(join(tmpdir(), "verax-consumer-"));
writeFileSync(
  join(consumer, "package.json"),
  `${JSON.stringify(
    {
      name: "verax-pack-smoke",
      private: true,
      version: "1.0.0",
      type: "module",
      dependencies: { "@verax-ai/body": `file:${tarballs.get("@verax-ai/body")}` },
      overrides: {
        "@verax-ai/proxy": `file:${tarballs.get("@verax-ai/proxy")}`,
        "@verax-ai/inventory": `file:${tarballs.get("@verax-ai/inventory")}`,
      },
    },
    null,
    2,
  )}\n`,
  "utf8",
);

const install = run("npm", ["install", "--silent", "--no-audit", "--no-fund"], consumer);
check(install.status === 0, "clean install of the published packages", install.out.slice(0, 600));

const help = run("npx", ["--no-install", "verax", "--help"], consumer);
check(help.status === 0 && /Usage: verax/.test(help.out), "verax --help from the installed bin", help.out.slice(0, 300));

const version = run("npx", ["--no-install", "verax", "--version"], consumer);
check(/^\d+\.\d+\.\d+/.test(version.out.trim()), "verax --version prints a version", version.out.trim().slice(0, 80));

const demo = run("npx", ["--no-install", "verax", "demo"], consumer);
check(demo.status === 0, "verax demo from the installed bin exits 0 without a TTY", demo.out.slice(0, 400));

writeFileSync(join(consumer, "probe.mjs"), 'import("@verax-ai/body").then(() => console.log("imported"));\n', "utf8");
const probe = run(process.execPath, ["probe.mjs"], consumer);
check(probe.status === 0 && /imported/.test(probe.out), "importing @verax-ai/body in a plain Node process", probe.out.slice(0, 300));

// The installed bin, never this repository's sources. On Windows npx is a
// script, so it needs a shell; the same rule as run().
function spawnVerax(args: string[], env: NodeJS.ProcessEnv): ChildProcess {
  const shell = process.platform === "win32";
  return spawn(shell ? "npx.cmd" : "npx", ["--no-install", "verax", ...args], {
    cwd: consumer,
    env,
    shell,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function envFromState(stateDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("VERAX_")) delete env[key];
  }
  for (const line of readFileSync(join(stateDir, "verax.env"), "utf8").split(/\r?\n/)) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (m) env[m[1]] = m[2];
  }
  env.VERAX_BIND = "127.0.0.1:0";
  return env;
}

function stopChild(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 5_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

function listen(env: NodeJS.ProcessEnv): Promise<{ child: ChildProcess; port: number }> {
  return new Promise((resolve, reject) => {
    const child = spawnVerax(["serve"], env);
    let err = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(new Error(`no listen: ${err.slice(0, 400)}`));
    }, 15_000);
    const onExit = (code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`exit ${code}: ${err.slice(0, 400)}`));
    };
    child.once("exit", onExit);
    child.stderr?.on("data", (chunk: Buffer | string) => {
      err += String(chunk);
      const m = /listening [^\s:]+:(\d+)/.exec(err);
      if (!m || settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("exit", onExit);
      resolve({ child, port: Number(m[1]) });
    });
  });
}

type ToolReply = { status: number; isError: boolean; text: string };

function toolText(body: string): { isError: boolean; text: string } {
  const candidates = [body.trim()];
  for (const line of body.split(/\r?\n/)) {
    const data = /^data:\s*(.*)$/.exec(line.trim());
    if (data?.[1] && data[1] !== "[DONE]") candidates.push(data[1]);
  }
  for (const raw of candidates) {
    try {
      const msg = JSON.parse(raw) as {
        result?: { isError?: boolean; content?: Array<{ text?: string }> };
        error?: { message?: string };
      };
      if (msg.error) return { isError: true, text: msg.error.message ?? "jsonrpc-error" };
      if (!msg.result) continue;
      const text = (msg.result.content ?? []).map((part) => part.text ?? "").join("");
      return { isError: msg.result.isError === true, text };
    } catch {
      // not this candidate
    }
  }
  return { isError: true, text: body.slice(0, 300) };
}

async function toolsCall(port: number, token: string, params: Record<string, unknown>): Promise<ToolReply> {
  const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params }),
  });
  const parsed = toolText(await res.text());
  return { status: res.status, isError: parsed.isError, text: parsed.text };
}

const stateDir = mkdtempSync(join(tmpdir(), "verax-pack-state-"));
let serving: ChildProcess | undefined;
try {
  const init = run("npx", ["--no-install", "verax", "init", "--local", stateDir], consumer);
  const tokenPath = join(stateDir, "local-issuer", "agent.token");
  const token = existsSync(tokenPath) ? readFileSync(tokenPath, "utf8").trim() : "";
  check(init.status === 0 && token.startsWith("eyJ"), "verax init --local writes the agent token", init.out.slice(0, 300));

  if (init.status === 0 && token.startsWith("eyJ")) {
    try {
      const up = await listen(envFromState(stateDir));
      serving = up.child;
      const health = await fetch(`http://127.0.0.1:${up.port}/healthz`);
      check(health.status === 200, "verax serve answers /healthz", `status ${health.status}`);
      await health.arrayBuffer();

      const allowed = await toolsCall(up.port, token, {
        name: "memory.put",
        arguments: {
          id: "pack-smoke-note",
          body: { text: "installed" },
          source: { kind: "pack-smoke" },
          validUntilMs: Date.now() + 60 * 60 * 1000,
        },
      });
      check(
        allowed.status === 200 && allowed.isError === false,
        "memory.put the default local policy allows",
        `status ${allowed.status} ${allowed.text.slice(0, 200)}`,
      );

      const denied = await toolsCall(up.port, token, {
        name: "message.send",
        arguments: { to: "ops@example.invalid", text: "no" },
      });
      check(
        denied.status === 200 && denied.isError === true && denied.text.includes("denied:"),
        "a call the default local policy denies is denied",
        `status ${denied.status} ${denied.text.slice(0, 200)}`,
      );
    } catch (err) {
      check(false, "verax serve from the installed bin", err instanceof Error ? err.message : "serve failed");
    }
  }
} finally {
  if (serving) await stopChild(serving);
}

const verified = run("npx", ["--no-install", "verax", "verify", stateDir, "--json"], consumer);
let verdict = "";
let decisions = 0;
let ok = false;
try {
  const parsed = JSON.parse(verified.stdout) as { ok?: boolean; decisions?: number };
  ok = parsed.ok === true;
  decisions = typeof parsed.decisions === "number" ? parsed.decisions : 0;
  verdict = `ok=${parsed.ok} decisions=${parsed.decisions}`;
} catch {
  verdict = verified.out.slice(0, 300);
}
check(verified.status === 0 && ok && decisions >= 2, "verax verify --json ok with at least 2 decisions", verdict);

rmSync(stateDir, { recursive: true, force: true });
rmSync(packDir, { recursive: true, force: true });
rmSync(consumer, { recursive: true, force: true });

process.stdout.write(`\npack-smoke: ${failures.length === 0 ? "green" : `${failures.length} failed`}\n`);
process.exit(failures.length === 0 ? 0 : 1);
