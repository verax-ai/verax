import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { haltBody } from "./halt.ts";
import { readHeartbeat } from "./health-extras.ts";
import { isLoopbackHost } from "./config.ts";

const USAGE = "usage: verax watch <stateDir> | --url <https://host/healthz> --token-file <path> [--max-silence 30s] [--once] [--on-silence halt|exec] [--exec <command>]";
type WatchOptions = { stateDir?: string; url?: string; tokenFile?: string; maxSilenceMs: number; once: boolean; action: "halt" | "exec"; command?: string[] };
export type WatchHooks = {
  stdout?: { write(s: string): unknown };
  stderr?: { write(s: string): unknown };
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  fetch?: typeof fetch;
  spawn?: (command: string, args: readonly string[], options: SpawnOptions) => ChildProcess;
};

/** Split operator-supplied argv; no expansion, pipes, redirects or shell. */
export function commandArgv(text: string): string[] {
  const args: string[] = [];
  let word = "", quote = "", started = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (ch === "\0" || ch === "\n" || ch === "\r") throw new Error("invalid command");
    if (ch === "\\" && (text[i + 1] === quote || text[i + 1] === "\\" || (!quote && /[\s"']/.test(text[i + 1] ?? "")))) {
      word += text[++i]; started = true;
    } else if (quote) {
      if (ch === quote) quote = "";
      else word += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch; started = true;
    } else if (/\s/.test(ch)) {
      if (started) { args.push(word); word = ""; started = false; }
    } else { word += ch; started = true; }
  }
  if (quote) throw new Error("unclosed command quote");
  if (started) args.push(word);
  if (!args[0]) throw new Error("empty command");
  return args;
}

function options(argv: readonly string[]): WatchOptions {
  const result: WatchOptions = { maxSilenceMs: 30_000, once: false, action: "halt" };
  const seen = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (!arg.startsWith("-")) {
      if (result.stateDir) throw new Error("one state directory required");
      result.stateDir = arg;
      continue;
    }
    if (seen.has(arg)) throw new Error("duplicate option");
    seen.add(arg);
    if (arg === "--once") { result.once = true; continue; }
    if (!["--url", "--token-file", "--max-silence", "--on-silence", "--exec"].includes(arg)) throw new Error("unknown option");
    const value = argv[++i];
    if (!value || value.startsWith("--")) throw new Error("missing option value");
    if (arg === "--url") result.url = value;
    if (arg === "--token-file") result.tokenFile = value;
    if (arg === "--exec") result.command = commandArgv(value);
    if (arg === "--on-silence") {
      if (value !== "halt" && value !== "exec") throw new Error("invalid silence action");
      result.action = value;
    }
    if (arg === "--max-silence") {
      const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value);
      if (!match) throw new Error("duration needs ms, s, m or h");
      result.maxSilenceMs = Number(match[1]) * ({ ms: 1, s: 1000, m: 60_000, h: 3_600_000 }[match[2]!]!);
      if (!Number.isFinite(result.maxSilenceMs) || result.maxSilenceMs < 1 || result.maxSilenceMs / 3 > 2_147_483_647) throw new Error("duration out of range");
    }
  }
  if (Boolean(result.stateDir) === Boolean(result.url)) throw new Error("choose local or URL mode");
  if (result.url) {
    const url = new URL(result.url);
    if (url.username || url.password || url.hash || url.search || url.pathname !== "/healthz"
      || !(url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHost(url.hostname)))) throw new Error("HTTPS required except on loopback; use /healthz without credentials");
    if (!result.tokenFile) throw new Error("token file required");
  } else if (result.tokenFile) throw new Error("token file requires URL mode");
  if ((result.action === "exec") !== Boolean(result.command)) throw new Error("exec action requires --exec command");
  return result;
}

export function silenceReason(atMs: unknown, now: number, maxSilenceMs: number): string | null {
  if (typeof atMs !== "number" || !Number.isFinite(atMs)) return "heartbeat-unreadable";
  if (atMs > now + 60_000) return "heartbeat-in-future";
  if (now - atMs > maxSilenceMs) return "heartbeat-stale";
  return null;
}

async function remoteBeat(opts: WatchOptions, hooks: WatchHooks): Promise<unknown> {
  try {
    const token = readFileSync(opts.tokenFile!, "utf8").trim();
    if (!token || /[\r\n]/.test(token)) return undefined;
    const timeout = AbortSignal.timeout(Math.max(1, Math.min(10_000, Math.floor(opts.maxSilenceMs / 3))));
    const signal = hooks.signal ? AbortSignal.any([hooks.signal, timeout]) : timeout;
    const response = await (hooks.fetch ?? fetch)(opts.url!, { headers: { authorization: `Bearer ${token}` }, redirect: "error", signal });
    if (!response.ok) return undefined;
    const body = await response.json() as { heartbeat?: { atMs?: unknown } };
    return body?.heartbeat?.atMs;
  } catch {
    // Do not print transport errors: a header or token may be embedded in them.
    return undefined;
  }
}

async function execute(opts: WatchOptions, reason: string, hooks: WatchHooks): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const child = (hooks.spawn ?? spawn)(opts.command![0]!, opts.command!.slice(1), {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "ignore", "inherit"],
        env: { ...(hooks.env ?? process.env), VERAX_WATCH_REASON: reason },
      });
      child.once("error", () => resolve(false));
      child.once("close", (code) => resolve(code === 0));
    } catch { resolve(false); }
  });
}

export async function runWatch(argv: readonly string[], hooks: WatchHooks = {}): Promise<number> {
  const stdout = hooks.stdout ?? process.stdout;
  const stderr = hooks.stderr ?? process.stderr;
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) { stdout.write(`${USAGE}\n`); return 0; }
  let opts: WatchOptions;
  try { opts = options(argv); } catch { stderr.write(`${USAGE}\n`); return 2; }
  let silent = false;
  while (!hooks.signal?.aborted) {
    const atMs = opts.url ? await remoteBeat(opts, hooks) : readHeartbeat(opts.stateDir!)?.atMs;
    if (hooks.signal?.aborted) break;
    const now = (hooks.now ?? Date.now)();
    const reason = silenceReason(atMs, now, opts.maxSilenceMs);
    if (reason && !silent) {
      silent = true;
      let actionResult = "halted";
      if (opts.action === "exec") {
        actionResult = await execute(opts, reason, hooks) ? "exec-ok" : "exec-failed";
      } else if (opts.url) {
        actionResult = "remote halt is out of scope";
      } else {
        try { haltBody(opts.stateDir!, "verax-watch", "cli", now); }
        catch { actionResult = "halt-failed"; }
      }
      stdout.write(`${JSON.stringify({ event: "silence", atMs: now, reason, action: opts.action, actionResult })}\n`);
      if (actionResult === "halt-failed") { stderr.write("verax-watch: could not persist halt\n"); return 3; }
      if (opts.url && opts.action === "halt") return 3;
    } else if (!reason && silent) {
      silent = false;
      stdout.write(`${JSON.stringify({ event: "recovery", atMs: now })}\n`);
      // Recovery never removes the halt; only an operator resumes the body.
    }
    if (opts.once) return reason ? 3 : 0;
    try {
      const ms = Math.max(1, Math.floor(opts.maxSilenceMs / 3));
      if (hooks.sleep) await hooks.sleep(ms);
      else await delay(ms, undefined, hooks.signal ? { signal: hooks.signal } : {});
    } catch (err) {
      if (!hooks.signal?.aborted) throw err;
    }
  }
  return 0;
}
