import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, unlinkSync } from "node:fs";
import { get } from "node:http";
import { createConnection, createServer, type Server } from "node:net";
import { basename, dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DESKTOP_PARENT_PID } from "./desktop-parent.ts";
import {
  defaultExec,
  foreignAclPrincipals,
  posixOthersCanReplace,
  readSddlBatch,
  restrictToOwnerWin32,
  sddlOwner,
  systemToolEnv,
  systemToolPath,
  toolArgv,
  windowsDirectorySids,
  windowsInvokingSid,
  windowsUserCanWrite,
} from "./install.ts";
import { hasRegisteredOperator } from "./operator-credentials.ts";
import { pidAlive, readLockFile } from "./unlock.ts";

// With VERAX_DESKTOP_TRACE=1 each startup step writes one stderr line with the
// milliseconds since this module loaded. Windows CI has waited ~87 s before the
// issuer port opened; these lines say which step held it.
const traceZero = Date.now();
function trace(step: string): void {
  if (process.env.VERAX_DESKTOP_TRACE === "1") process.stderr.write(`desktop-trace ${step} ${Date.now() - traceZero}ms\n`);
}

/** One stderr line when this state has no enrolled operator. */
export const DESKTOP_PASSKEY_HINT =
  "the panel reads the ledger after a passkey sign-in; run verax operator enroll\n";

/**
 * The credentials file is written only when an operator enrolls. Its presence
 * is the whole answer; a missing file means the panel's audit doors will
 * refuse the session that has no passkey.
 */
export function desktopPasskeyHint(stateDir: string): string | null {
  return hasRegisteredOperator(stateDir) ? null : DESKTOP_PASSKEY_HINT;
}

const here = dirname(fileURLToPath(import.meta.url));

export function resolveRepoRoot(): string {
  return join(here, "..", "..", "..");
}

export const DESKTOP_CLONE_ONLY =
  "verax desktop runs from a clone of github.com/verax-ai/verax; it is not in the npm package\n";

export function desktopCloneError(root: string): string | null {
  if (!existsSync(join(root, "scripts", "dev-issuer.mjs")) || !existsSync(join(root, "apps", "panel"))) {
    return DESKTOP_CLONE_ONLY;
  }
  return null;
}

export type DesktopOpts = {
  stateDir: string;
  panelPort: number;
  issuerPort: number;
  bodyPort: number;
  browser?: string;
  inventoryFile?: string;
};

/** Newest modification time under a file or directory, ignoring build output. */
function newestUnder(path: string, since: number): boolean {
  let entry;
  try {
    entry = statSync(path);
  } catch {
    return false;
  }
  if (!entry.isDirectory()) return entry.mtimeMs > since;
  let names;
  try {
    names = readdirSync(path, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const name of names) {
    if (name.name === "node_modules" || name.name === "dist" || name.name.startsWith(".")) continue;
    if (newestUnder(join(path, name.name), since)) return true;
  }
  return false;
}

/**
 * True when the panel has no build, or when a watched source is newer than the
 * one it has. The launcher used to skip the build whenever `dist/index.html`
 * existed, so a session served whatever had been built once: editing the panel
 * and reopening it showed the previous app, with no sign that it was stale.
 */
export function panelBuildNeeded(distIndex: string, sourceRoots: readonly string[]): boolean {
  let builtAt: number;
  try {
    builtAt = statSync(distIndex).mtimeMs;
  } catch {
    return true;
  }
  return sourceRoots.some((root) => newestUnder(root, builtAt));
}

/** UNC share or a Win32 device path (`\\?\`, `\\.\`, `\\?\UNC\`, `//host`): all start with two separators. */
export function desktopStateUncOrDevice(stateDir: string): boolean {
  return stateDir.replaceAll("/", "\\").startsWith("\\\\");
}

export function parseDesktopArgs(
  argv: string[],
  platform: NodeJS.Platform = process.platform,
): DesktopOpts | { error: string } {
  const rest = argv.slice(1);
  let stateDir = "";
  let panelPort = 5173;
  let issuerPort = Number(process.env.VERAX_DEV_ISSUER_PORT ?? "8790");
  let bodyPort = 8787;
  let browser: string | undefined;
  let inventoryFile: string | undefined;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i]!;
    if (a === "--state") {
      stateDir = rest[++i] ?? "";
      continue;
    }
    if (a === "--port") {
      panelPort = Number(rest[++i]);
      continue;
    }
    if (a === "--issuer-port") {
      issuerPort = Number(rest[++i]);
      continue;
    }
    if (a === "--body-port") {
      bodyPort = Number(rest[++i]);
      continue;
    }
    if (a === "--browser") {
      browser = rest[++i];
      continue;
    }
    if (a === "--inventory") {
      inventoryFile = rest[++i];
      continue;
    }
    if (a.startsWith("-")) return { error: `flag-unknown:${a}` };
  }
  if (!stateDir) return { error: "usage" };
  // Resolved against this process's cwd. The children start with cwd = repoRoot,
  // so a relative --state or --inventory would otherwise be created somewhere
  // other than the path this check judged. A relative name under a UNC cwd
  // resolves onto that share, so the device check sees both strings.
  const resolvedState = resolve(stateDir);
  if (platform === "win32" && (desktopStateUncOrDevice(stateDir) || desktopStateUncOrDevice(resolvedState))) {
    return { error: "desktop-state-unc" };
  }
  if (![panelPort, issuerPort, bodyPort].every((n) => Number.isInteger(n) && n > 0 && n < 65536)) {
    return { error: "port-invalid" };
  }
  return {
    stateDir: resolvedState,
    panelPort,
    issuerPort,
    bodyPort,
    browser,
    inventoryFile: inventoryFile === undefined ? undefined : resolve(inventoryFile),
  };
}

export function portOpen(port: number, host = "127.0.0.1"): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host });
    sock.once("connect", () => {
      sock.end();
      resolve(true);
    });
    sock.once("error", () => resolve(false));
  });
}

function bindLoopback(port: number, host: string): Promise<"free" | "busy" | "unsupported"> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRNOTAVAIL" || err.code === "EAFNOSUPPORT") resolve("unsupported");
      else resolve("busy");
    });
    server.listen({ port, host, ipv6Only: host === "::1" }, () => {
      server.close(() => resolve("free"));
    });
  });
}

/**
 * Bind 127.0.0.1 and [::1], then close both. True only when this process held
 * 127.0.0.1 and [::1] was free or this host has no IPv6 loopback. A connect
 * probe is not this: whoever is already listening would answer it.
 */
export function desktopPortFree(port: number): Promise<boolean> {
  return bindLoopback(port, "127.0.0.1").then(async (v4) => {
    if (v4 !== "free") return false;
    const v6 = await bindLoopback(port, "::1");
    return v6 !== "busy";
  });
}

/** True when a socket can bind [::1]. False when the host has no IPv6 loopback. */
export function ipv6LoopbackAvailable(): Promise<boolean> {
  return bindLoopback(0, "::1").then((held) => held !== "unsupported");
}

/**
 * Hold `[::1]:port` and pipe each accepted socket to `127.0.0.1:port`.
 * `unsupported` means this host cannot bind the IPv6 loopback.
 */
export function forwardIpv6Loopback(port: number): Promise<
  { ok: true; server: Server } | { ok: false; reason: "busy" | "unsupported" }
> {
  return new Promise((resolve) => {
    let settled = false;
    const server = createServer((inbound) => {
      const upstream = createConnection({ host: "127.0.0.1", port });
      const drop = () => {
        inbound.destroy();
        upstream.destroy();
      };
      inbound.on("error", drop);
      upstream.on("error", drop);
      inbound.pipe(upstream);
      upstream.pipe(inbound);
    });
    server.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      if (err.code === "EADDRNOTAVAIL" || err.code === "EAFNOSUPPORT") resolve({ ok: false, reason: "unsupported" });
      else resolve({ ok: false, reason: "busy" });
    });
    server.listen({ port, host: "::1", ipv6Only: true }, () => {
      if (settled) {
        server.close();
        return;
      }
      settled = true;
      resolve({ ok: true, server });
    });
  });
}

function listeningPort(server: Server): number | null {
  const addr = server.address();
  return addr && typeof addr !== "string" ? addr.port : null;
}

export function desktopPortBusyLine(name: DesktopChildName, port: number, ipv6 = false): string {
  return ipv6 ? `desktop-port-busy:${name}:${port}:ipv6\n` : `desktop-port-busy:${name}:${port}\n`;
}

/** JWKS document the dev issuer rewrites under the state directory on every start. */
export function issuerJwksPinPath(stateDir: string): string {
  return join(stateDir, "dev-issuer", "jwks.json");
}

/** Drop a file left by an earlier run. A missing file is the state we want. */
export function discardStaleFile(file: string): void {
  try {
    unlinkSync(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

/** JWK members that carry private or symmetric key material. A pin is public verification material. */
const JWK_PRIVATE_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi", "k"]);

function jwkCarriesPrivateMaterial(key: unknown): boolean {
  if (key === null || typeof key !== "object") return false;
  return Object.keys(key).some((field) => JWK_PRIVATE_FIELDS.has(field));
}

/**
 * The pin is the file the issuer just wrote. Compact JSON, or a throw when
 * it is not a key set. Nothing is fetched. A symlink for `dev-issuer` or for
 * the pin file is refused, and so is any key that carries private material:
 * those fail closed instead of being stripped out.
 */
export function readIssuerJwksPin(stateDir: string): string {
  if (devIssuerIsLink(stateDir)) throw new Error("desktop-jwks-pin-failed");
  const pinPath = issuerJwksPinPath(stateDir);
  let text: string;
  try {
    const st = lstatSync(pinPath);
    if (st.isSymbolicLink() || !st.isFile()) throw new Error("desktop-jwks-pin-failed");
    text = readFileSync(pinPath, "utf8");
  } catch (err) {
    if (err instanceof Error && err.message === "desktop-jwks-pin-failed") throw err;
    throw new Error("desktop-jwks-pin-failed");
  }
  try {
    const parsed = JSON.parse(text) as { keys?: unknown };
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.keys) || parsed.keys.length === 0) {
      throw new Error("desktop-jwks-pin-failed");
    }
    if (parsed.keys.some((key) => jwkCarriesPrivateMaterial(key))) throw new Error("desktop-jwks-pin-failed");
    return JSON.stringify({ keys: parsed.keys });
  } catch (err) {
    if (err instanceof Error && err.message === "desktop-jwks-pin-failed") throw err;
    throw new Error("desktop-jwks-pin-failed");
  }
}

export function issuerReadyLine(port: number): string {
  return `dev-issuer listening on http://127.0.0.1:${port}/`;
}

export function bodyReadyLine(port: number): string {
  return `listening 127.0.0.1:${port}`;
}

export function panelReadyLine(port: number): string {
  return `http://127.0.0.1:${port}`;
}

export function childStillAlive(child: { exitCode: number | null; signalCode: NodeJS.Signals | null }): boolean {
  return child.exitCode === null && child.signalCode === null;
}

/** GET /healthz on the loopback port; true only for a 200. */
export function healthzUp(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = get({ host: "127.0.0.1", port, path: "/healthz", timeout: 3_000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.once("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.once("error", () => resolve(false));
  });
}

export type DesktopMode =
  | { mode: "spawn" }
  | { mode: "attach"; pid: number }
  | { error: "desktop-body-locked"; pid: number; lockPort: number | null };

function listenerArgv(port: number, platform: NodeJS.Platform): string[] | null {
  if (platform === "win32") {
    // netstat, not Get-NetTCPConnection: loading the NetTCPIP module in PowerShell took long
    // enough on a busy machine to time the lookup out, and a timed-out lookup is no listener.
    return toolArgv("netstat", ["-ano", "-p", "TCP"], "win32");
  }
  if (platform === "darwin") {
    return toolArgv("lsof", ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fp"], "darwin");
  }
  if (platform === "linux") {
    return toolArgv("ss", ["-ltnpH", `sport = :${port}`], "linux");
  }
  return null;
}

function onlyPid(pids: readonly number[]): number | null {
  const unique = [...new Set(pids)];
  return unique.length === 1 ? unique[0]! : null;
}

/** Pid listening on 127.0.0.1:`port`, or null when the tool names nobody or more than one pid. */
export function loopbackListenPid(port: number, platform: NodeJS.Platform = process.platform): number | null {
  if (!Number.isInteger(port) || port <= 0 || port >= 65536) return null;
  const argv = listenerArgv(port, platform);
  const file = argv?.[0];
  if (!argv || !file) return null;
  const ran = spawnSync(file, argv.slice(1), {
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 30_000,
    env: systemToolEnv(platform),
  });
  if (ran.error) return null;
  const text = (ran.stdout ?? "").replace(/\u0000/g, "").replace(/^\uFEFF/, "");
  if (platform === "darwin") return onlyPid(lsofPids(text));
  return onlyPid(loopbackPids(text, port));
}

function loopbackPids(text: string, port: number): number[] {
  const pids: number[] = [];
  const at = new RegExp(`(?:^|[\\s\\[])127\\.0\\.0\\.1:${port}(?!\\d)`);
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "") continue;
    // netstat -ano: "TCP  127.0.0.1:<port>  0.0.0.0:0  <state>  <pid>". The state word is localized;
    // a listening socket is the one whose foreign address is 0.0.0.0:0.
    const win = /^TCP\s+127\.0\.0\.1:(\d+)\s+0\.0\.0\.0:0\s+\S+\s+(\d+)$/i.exec(line);
    if (win) {
      if (Number(win[1]) === port) pids.push(Number(win[2]));
      continue;
    }
    if (!at.test(line)) continue;
    const found = /pid=(\d+)/.exec(line);
    if (found) pids.push(Number(found[1]));
  }
  return pids;
}

function lsofPids(text: string): number[] {
  const pids: number[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const found = /^p(\d+)$/.exec(raw.trim());
    if (found) pids.push(Number(found[1]));
  }
  return pids;
}

/**
 * One ledger, one body. The desktop used to build its own issuer and body on
 * every open, which on a machine whose body starts at logon put the window on
 * a second, empty ledger: the panel looked broken while the real decisions sat
 * in the directory the lock names. So the lock is read first. A live lock that
 * records this port, whose pid is the listener on 127.0.0.1 there, is
 * `attach`. 0.4.0 does not join that body: `runDesktop` stops before it
 * claims a port or starts a child. A later release may join again, once that
 * body is supervised. A 200 from /healthz is not the check. Any other live
 * lock stops the desktop: `desktop-body-locked:<pid>:<port or unknown>`. A
 * lock with no port is that stop until the body is started again. A dead or
 * unreadable lock is left for `verax unlock`, which is only for a dead lock.
 */
export async function desktopMode(
  stateDir: string,
  bodyPort: number,
  listenerPid: (port: number) => number | null = loopbackListenPid,
): Promise<DesktopMode> {
  const lockPath = join(stateDir, "ledger.lock");
  if (!existsSync(lockPath)) return { mode: "spawn" };
  const lock = readLockFile(lockPath);
  if (!lock || !pidAlive(lock.pid)) return { mode: "spawn" };
  const lockPort = lock.port ?? null;
  if (lockPort === null || lockPort !== bodyPort) {
    return { error: "desktop-body-locked", pid: lock.pid, lockPort };
  }
  let heard: number | null;
  try {
    heard = listenerPid(bodyPort);
  } catch {
    heard = null;
  }
  if (heard !== lock.pid) return { error: "desktop-body-locked", pid: lock.pid, lockPort };
  return { mode: "attach", pid: lock.pid };
}

export type DesktopChildName = "issuer" | "body" | "panel";

export type SupervisedChild = {
  name: DesktopChildName;
  /** Registers the listener invoked when this child exits. May run it immediately if it already has. */
  onExit: (listener: () => void) => void;
};

/**
 * The first of the issuer, the body or the panel to exit stops the rest.
 * A later exit does not stop again. `stillWatching` is false once this run
 * is shutting down on purpose, so those exits are not a child failure.
 */
export function superviseDesktopChildren(
  children: readonly SupervisedChild[],
  stopAll: () => void,
  stillWatching: () => boolean = () => true,
): Promise<DesktopChildName> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (name: DesktopChildName) => {
      if (done || !stillWatching()) return;
      done = true;
      stopAll();
      resolve(name);
    };
    for (const child of children) child.onExit(() => finish(child.name));
  });
}

export function desktopChildExitedLine(name: DesktopChildName): string {
  return `desktop-child-exited:${name}\n`;
}

export type DesktopSpawnName = DesktopChildName | "browser";

/**
 * Stand-in for `process` so a test can emit SIGHUP, SIGBREAK, an uncaught
 * exception, or `exit` without signalling this process. `platform` chooses
 * SIGHUP (anything but win32) or SIGBREAK (win32).
 */
export type DesktopSignalHost = {
  once: (event: string, listener: () => void) => void;
  on: (event: string, listener: () => void) => void;
  removeListener: (event: string, listener: () => void) => void;
  exit: (code: number) => void;
  platform?: NodeJS.Platform;
};

/** Test seam. Production leaves this unset and spawns the real children. */
export type DesktopHooks = {
  spawn?: (
    name: DesktopSpawnName,
    cmd: string,
    args: string[],
    env: NodeJS.ProcessEnv,
    cwd: string,
  ) => ChildProcess;
  /** Caps issuer, body, and panel readiness waits. The CLI uses the built-in budgets. */
  readyMs?: number;
  /** Replaces the listener-pid lookup. */
  listenerPid?: (port: number) => number | null;
  /** Replaces the Windows owner ACL call on the state directory and the browser profile. */
  restrictOwner?: (dir: string) => void;
  /** Replaces `process.platform` for the directory owner check. */
  platform?: NodeJS.Platform;
  /** Replaces the Windows owner-SID and invoking-SID lookup. */
  windowsDirectoryOwner?: (dir: string) => { ownerSid?: string; invokingSid?: string };
  /** Replaces the Windows DACL read. The text is the SDDL `windowsUserCanWrite` already judges. */
  windowsDirectoryDacl?: (dir: string) => string;
  /**
   * Replaces the ancestor DACL read. When set, each ancestor is judged with
   * `windowsUserCanWrite(..., { ancestor: true })`. When a leaf owner or leaf
   * DACL hook is set and this is not, ancestors are not read from the machine.
   */
  windowsAncestorDacl?: (dir: string) => string;
  /** Replaces `killTree` for the children this run started. */
  kill?: (pid: number | undefined) => void;
  /** Called with the capped stdout/stderr kept for one child. */
  childOutput?: (name: DesktopSpawnName, stored: string) => void;
  /** Replaces `process` for stop handlers. Production uses this process. */
  signals?: DesktopSignalHost;
};

type DesktopDirectoryOpts = {
  platform?: NodeJS.Platform;
  windowsDirectoryOwner?: (dir: string) => { ownerSid?: string; invokingSid?: string };
  windowsDirectoryDacl?: (dir: string) => string;
  windowsAncestorDacl?: (dir: string) => string;
};

const DIRECTORY_WRITABLE_BY_OTHERS = "the directory was writable by others; use a new directory";

function refuseDesktopDirectory(dir: string, detail?: string): never {
  throw new Error(detail === undefined ? `desktop-dir-refused:${dir}` : `desktop-dir-refused:${dir}\n${detail}`);
}

/** `dev-issuer` planted as a symlink or junction. A missing entry is not that. */
function devIssuerIsLink(dir: string): boolean {
  try {
    return lstatSync(join(dir, "dev-issuer")).isSymbolicLink();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw err;
  }
}

/** An SDDL, or null with the first line of what the read returned instead. */
type WindowsAcl = { sddl: string | null; why: string };

/**
 * SDDL of every path from one PowerShell process (the installer's batch
 * reader). One process per path timed out on a loaded Windows runner: the
 * ancestor walk alone reads four to six directories.
 */
function readWindowsAcls(paths: readonly string[]): Map<string, WindowsAcl> {
  const read = readSddlBatch(defaultExec, paths);
  trace(`acl-read n=${paths.length}`);
  const out = new Map<string, WindowsAcl>();
  for (const p of paths) {
    const hit = read.get(p);
    const text = (hit?.text ?? "").replace(/^\uFEFF/, "").trim();
    if (hit && hit.status === 0 && text !== "") {
      const aliased = /(?:[OG]:|;)L[AG](?=[)OGDS:]|$)/.test(text);
      out.set(p, { sddl: aliased ? expandLocalAccountAliases(text, localAccountSids()) : text, why: "" });
    } else {
      out.set(p, { sddl: null, why: text.split(/\r?\n/)[0]?.slice(0, 200) || "no answer" });
    }
  }
  return out;
}

let localAccounts: { LA?: string; LG?: string } | null = null;

/** This machine's built-in Administrator and Guest SIDs, which an SDDL writes as `LA` and `LG`. Empty when the lookup fails. */
function localAccountSids(): { LA?: string; LG?: string } {
  if (localAccounts) return localAccounts;
  trace("local-account-sids-start");
  const ran = defaultExec(
    toolArgv(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[Security.Principal.SecurityIdentifier]::new('LA').Value; [Security.Principal.SecurityIdentifier]::new('LG').Value",
      ],
      "win32",
    ),
  );
  const sids = (ran.status ?? 1) === 0 ? (ran.stdout ?? "").match(/S-1-5-21-[0-9-]+/g) ?? [] : [];
  trace("local-account-sids");
  localAccounts = sids.length === 2 && sids[0]!.endsWith("-500") && sids[1]!.endsWith("-501") ? { LA: sids[0], LG: sids[1] } : {};
  return localAccounts;
}

/**
 * The account SIDs in place of the `LA` / `LG` aliases, so the built-in
 * Administrator's own entry compares equal to its SID (a GitHub Windows
 * runner runs as that account). An alias with no SID given is left, and the
 * judge treats it as someone else.
 */
export function expandLocalAccountAliases(sddl: string, sids: { LA?: string; LG?: string }): string {
  const sid = (alias: string): string | undefined => (alias === "LA" ? sids.LA : alias === "LG" ? sids.LG : undefined);
  return sddl
    .replace(/([OG]:)(LA|LG)(?=[OGDS]:|$)/g, (whole, field: string, alias: string) => {
      const full = sid(alias);
      return full ? `${field}${full}` : whole;
    })
    .replace(/;(LA|LG)\)/g, (whole, alias: string) => {
      const full = sid(alias);
      return full ? `;${full})` : whole;
    });
}

function unreadable(why: string): string {
  return why === "" ? "" : ` (${why})`;
}

/** Who the refused DACL names, so the operator (and a CI log) can see which entry was judged to be someone else. */
function aclWho(sddl: string, you: string): string {
  const others = foreignAclPrincipals(sddl, you);
  return ` (owner ${sddlOwner(sddl) ?? "unknown"}; other entries ${others.length > 0 ? others.join(", ") : "none"}; you ${you || "unknown"})`;
}

/** Last bytes kept from a child so a long log cannot grow without a bound. */
export const DESKTOP_CHILD_OUTPUT_CAP = 64 * 1024;

/** Keep the tail. A ready line at the end of a large chunk stays inside the cap. */
export function rememberChildOutput(current: string, chunk: string, cap = DESKTOP_CHILD_OUTPUT_CAP): string {
  if (cap <= 0) return "";
  if (chunk.length >= cap) return chunk.slice(chunk.length - cap);
  if (current.length + chunk.length <= cap) return current + chunk;
  return (current + chunk).slice(current.length + chunk.length - cap);
}

function foldDesktopPath(p: string): string {
  if (process.platform !== "win32") return p.length > 1 ? p.replace(/\/+$/, "") : p;
  let s = p.replaceAll("/", "\\");
  const lower = s.toLowerCase();
  if (lower.startsWith("\\\\?\\unc\\")) s = `\\\\${s.slice(8)}`;
  else if (lower.startsWith("\\\\?\\")) s = s.slice(4);
  s = s.toLowerCase();
  if (s.length > 3) s = s.replace(/\\+$/, "");
  return s;
}

function ancestorPaths(dir: string): string[] {
  const out: string[] = [];
  let cur = resolve(dir);
  for (let i = 0; i < 64; i += 1) {
    const parent = dirname(cur);
    if (parent === cur) break;
    out.push(parent);
    cur = parent;
  }
  return out;
}

/**
 * An intermediate link makes the real path differ from the path as given.
 * 8.3 names are expanded with `realpathSync.native` on each component that is
 * not a link, then compared case-insensitively on Windows. A missing leaf is
 * the real path of the parent plus the leaf name. The leaf itself being a
 * link is left to the directory check.
 */
function intermediateLink(dir: string): string | null {
  const abs = resolve(dir);
  const root = parse(abs).root;
  const segs = abs.slice(root.length).split(/[\\/]/).filter((seg) => seg.length > 0);
  let cursor = root;
  let expanded = root;
  for (let i = 0; i < segs.length; i += 1) {
    const next = join(cursor, segs[i]!);
    const leaf = i === segs.length - 1;
    let st: ReturnType<typeof lstatSync>;
    try {
      st = lstatSync(next);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        expanded = join(expanded, ...segs.slice(i));
        break;
      }
      throw err;
    }
    if (st.isSymbolicLink()) {
      if (leaf) return null;
      return next;
    }
    try {
      expanded = realpathSync.native(next);
    } catch {
      return next;
    }
    cursor = next;
  }
  let real: string;
  try {
    real = realpathSync.native(abs);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    const parent = dirname(abs);
    try {
      real = join(realpathSync.native(parent), basename(abs));
    } catch {
      return null;
    }
  }
  if (foldDesktopPath(expanded) !== foldDesktopPath(real)) return dirname(abs);
  return null;
}

function refusePosixAncestors(dir: string): void {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;
  for (const ancestor of ancestorPaths(dir)) {
    let st: ReturnType<typeof lstatSync> | undefined;
    try {
      st = lstatSync(ancestor);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      refuseDesktopDirectory(dir, `ancestor ${ancestor} could not be read`);
    }
    if (!st) continue;
    const ownerIsOperator = st.uid === 0 || st.uid === uid;
    if (
      posixOthersCanReplace(
        { uid: ownerIsOperator ? 0 : st.uid, mode: st.mode, symlink: st.isSymbolicLink() },
        true,
      )
    ) {
      refuseDesktopDirectory(dir, `ancestor ${ancestor} can be replaced by another user`);
    }
  }
}

function ancestorInvokingSid(dir: string, opts?: DesktopDirectoryOpts): string {
  const hooked = opts?.windowsDirectoryOwner?.(dir).invokingSid?.trim().toUpperCase() ?? "";
  if (hooked !== "") return hooked;
  if (opts?.windowsDirectoryOwner || opts?.windowsDirectoryDacl || opts?.windowsAncestorDacl) return "";
  try {
    return windowsInvokingSid()?.trim().toUpperCase() ?? "";
  } catch {
    return "";
  }
}

/** Ancestors that exist. A missing ancestor is skipped; any other stat error is a refusal. */
function presentAncestors(dir: string): string[] {
  return ancestorPaths(dir).filter((ancestor) => {
    try {
      lstatSync(ancestor);
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      return refuseDesktopDirectory(dir, `ancestor ${ancestor} could not be read`);
    }
  });
}

/**
 * True when `dir` is already a real directory. A missing path, a link, or a
 * non-directory stays on the caller's existing path, including a stat error
 * that the later `lstat` still reports.
 */
function isExistingRealDirectory(dir: string): boolean {
  try {
    const st = lstatSync(dir);
    return !st.isSymbolicLink() && st.isDirectory();
  } catch {
    return false;
  }
}

function refuseWindowsAncestors(
  dir: string,
  opts?: DesktopDirectoryOpts,
  preread?: Map<string, WindowsAcl>,
): void {
  if ((opts?.windowsDirectoryDacl || opts?.windowsDirectoryOwner) && !opts?.windowsAncestorDacl) return;
  const svc = ancestorInvokingSid(dir, opts);
  trace("ancestors-invoking-sid");
  const ancestors = ancestorPaths(dir);
  let read: Map<string, WindowsAcl> | null = null;
  if (preread) {
    read = preread;
  } else if (!opts?.windowsAncestorDacl) {
    const present = presentAncestors(dir);
    read = readWindowsAcls(present);
    trace(`ancestors-acl-read n=${present.length}`);
  }
  for (const ancestor of ancestors) {
    let acl: WindowsAcl;
    if (opts?.windowsAncestorDacl) {
      acl = { sddl: opts.windowsAncestorDacl(ancestor), why: "" };
    } else {
      const hit = read?.get(ancestor);
      if (!hit) continue;
      acl = hit;
    }
    if (acl.sddl === null || windowsUserCanWrite(acl.sddl, { ancestor: true, svcSid: svc })) {
      refuseDesktopDirectory(
        dir,
        acl.sddl === null
          ? `ancestor ${ancestor} ACL could not be read${unreadable(acl.why)}`
          : `ancestor ${ancestor} can be replaced by another user${aclWho(acl.sddl, svc)}`,
      );
    }
  }
}

/** Intermediate link, or an ancestor another user can replace. Same rule for a new directory and an existing one. */
function refuseDesktopAncestors(
  dir: string,
  platform: NodeJS.Platform,
  opts?: DesktopDirectoryOpts,
  preread?: Map<string, WindowsAcl>,
): void {
  const link = intermediateLink(dir);
  if (link) refuseDesktopDirectory(dir, `ancestor ${link} is a link`);
  if (platform === "win32") refuseWindowsAncestors(dir, opts, preread);
  else refusePosixAncestors(dir);
}

/**
 * Create `dir` as mode 0700. An existing directory another user could write
 * is refused and left as it is: on POSIX that is `mode & 0o022`, on Windows
 * a DACL `windowsUserCanWrite` accepts for someone other than the owner
 * (passed as `svcSid`), Administrators, or SYSTEM. A directory with only
 * owner access keeps the previous path, including a chmod of group/other
 * read or execute bits down to 0700. `dev-issuer` as a symlink or junction
 * is refused. A symbolic link, or a directory owned by another uid, is
 * refused. On Windows an existing directory is refused unless its owner SID
 * is the invoking SID, Administrators, or SYSTEM. An ancestor another user
 * can replace, or an intermediate link, is refused the same way for a new
 * directory and for one that already exists.
 */
function ensureDesktopDirectory(
  dir: string,
  restrict: (target: string) => void,
  opts?: DesktopDirectoryOpts,
): void {
  const platform = opts?.platform ?? process.platform;
  trace(`dir-start ${basename(dir)}`);
  // An existing directory and the ancestors that already exist share one SDDL
  // read. A path that is not there yet still reads ancestors before mkdir and
  // again after mkdir, so a directory created in between is not missed.
  // Hooked owner and DACL lookups stay on their own calls.
  const noWindowsAclHooks =
    !opts?.windowsDirectoryOwner && !opts?.windowsDirectoryDacl && !opts?.windowsAncestorDacl;
  let preread: Map<string, WindowsAcl> | undefined;
  if (platform === "win32" && noWindowsAclHooks && isExistingRealDirectory(dir)) {
    const link = intermediateLink(dir);
    if (link) refuseDesktopDirectory(dir, `ancestor ${link} is a link`);
    preread = readWindowsAcls([...presentAncestors(dir), dir]);
  }
  refuseDesktopAncestors(dir, platform, opts, preread);
  trace("dir-ancestors");
  let existing: ReturnType<typeof lstatSync> | null = null;
  try {
    existing = lstatSync(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (existing) {
    if (existing.isSymbolicLink() || !existing.isDirectory()) refuseDesktopDirectory(dir);
    if (platform === "win32") {
      // Production passes no hook: owner and DACL come from one SDDL read.
      const daclHook = opts?.windowsDirectoryDacl;
      const leaf = preread
        ? preread.get(dir)
        : !opts?.windowsDirectoryOwner && !daclHook
          ? readWindowsAcls([dir]).get(dir)
          : undefined;
      trace("dir-leaf-acl");
      if (leaf && leaf.sddl === null) {
        refuseDesktopDirectory(dir, `the directory ACL could not be read${unreadable(leaf.why)}; use a new directory`);
      }
      let owner: string;
      let invoking: string;
      if (leaf?.sddl) {
        owner = sddlOwner(leaf.sddl)?.toUpperCase() ?? "";
        invoking = windowsInvokingSid()?.trim().toUpperCase() ?? "";
        trace("dir-invoking-sid");
      } else {
        const found = (opts?.windowsDirectoryOwner ?? windowsDirectorySids)(dir);
        owner = found.ownerSid?.trim().toUpperCase() ?? "";
        invoking = found.invokingSid?.trim().toUpperCase() ?? "";
      }
      // An elevated administrator's new directories are owned by Administrators, not by the user;
      // no other local user can make a directory with that owner, or with SYSTEM.
      const ownerOk = owner === invoking || owner === "S-1-5-32-544" || owner === "S-1-5-18";
      if (owner === "" || invoking === "" || !ownerOk) refuseDesktopDirectory(dir);
      // R16-12 injects the owner and not a DACL.
      if (daclHook || !opts?.windowsDirectoryOwner) {
        const sddl = daclHook ? daclHook(dir) : (leaf?.sddl ?? null);
        // The invoking user's own entry is not "someone else", also when an elevated shell made Administrators the owner.
        if (sddl === null || windowsUserCanWrite(sddl, { svcSid: invoking })) {
          refuseDesktopDirectory(
            dir,
            sddl === null
              ? "the directory ACL could not be read; use a new directory"
              : `${DIRECTORY_WRITABLE_BY_OTHERS}${aclWho(sddl, invoking)}`,
          );
        }
      }
      if (devIssuerIsLink(dir)) {
        refuseDesktopDirectory(dir, "dev-issuer in that directory is a symlink or junction; use a new directory");
      }
      restrict(dir);
      trace("dir-restrict");
      return;
    }
    const uid = typeof process.getuid === "function" ? process.getuid() : existing.uid;
    if (existing.uid !== uid) refuseDesktopDirectory(dir);
    if ((existing.mode & 0o022) !== 0) refuseDesktopDirectory(dir, DIRECTORY_WRITABLE_BY_OTHERS);
    if (devIssuerIsLink(dir)) {
      refuseDesktopDirectory(dir, "dev-issuer in that directory is a symlink or junction; use a new directory");
    }
    if ((existing.mode & 0o077) !== 0) chmodSync(dir, 0o700);
    return;
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // A missing intermediate directory another user created between the first check and mkdir is theirs now.
  refuseDesktopAncestors(dir, platform, opts);
  trace("dir-ancestors-after-mkdir");
  const created = lstatSync(dir);
  if (created.isSymbolicLink() || !created.isDirectory()) refuseDesktopDirectory(dir);
  if (platform === "win32") {
    restrict(dir);
    trace("dir-restrict");
    return;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : created.uid;
  if (created.uid !== uid) refuseDesktopDirectory(dir);
  chmodSync(dir, 0o700);
}

/** Synchronous: `spawnSync` on Windows, `process.kill` elsewhere. An `exit` handler can call it. */
export function killTree(pid: number | undefined): void {
  // POSIX kill(-1) signals every process this user may signal, kill(0) our own group. No child has pid 0 or 1.
  if (pid == null || !Number.isInteger(pid) || pid <= 1) return;
  if (process.platform === "win32") {
    spawnSync(systemToolPath("taskkill", "win32"), ["/T", "/PID", String(pid), "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
    return;
  }
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // gone
    }
  }
}

function keptOr(base: NodeJS.ProcessEnv, key: string, value: string): string {
  const current = base[key]?.trim() ?? "";
  return current !== "" ? current : value;
}

/** Comma-separated origins. An origin already listed is not added again. */
export function mergeAllowedOrigin(existing: string | undefined, origin: string): string {
  const parts = (existing ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item !== "");
  if (!parts.includes(origin)) parts.push(origin);
  return parts.join(",");
}

/** The panel's redirect is its own origin, so the issuer has to be told which port
 *  this run put it on: the allow-list default only holds 5173 and 4173.
 *  The passkey ceremony runs on the issuer (`/authorize` and `/enroll`), so the
 *  RP ID and RP origins name that origin unless the operator already set them. */
export function issuerEnv(
  base: NodeJS.ProcessEnv,
  opts: { stateDir: string; issuerPort: number; panelPort: number },
  audience: string,
  issuerUrl: string,
): NodeJS.ProcessEnv {
  return {
    ...base,
    NODE_ENV: "development",
    VERAX_STATE_DIR: opts.stateDir,
    VERAX_DEV_ISSUER_PORT: String(opts.issuerPort),
    VERAX_AUDIENCE: audience,
    VERAX_ISSUER: issuerUrl,
    VERAX_DEV_REDIRECT_URIS: `http://localhost:${opts.panelPort}/`,
    VERAX_RP_ID: keptOr(base, "VERAX_RP_ID", "localhost"),
    VERAX_RP_ORIGINS: keptOr(base, "VERAX_RP_ORIGINS", issuerUrl),
  };
}

/** Removed from every child. Compared case-insensitively: on Windows `node_options` is `NODE_OPTIONS`. */
const DESKTOP_CHILD_ENV_DROPPED = new Set([
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_REPL_EXTERNAL_MODULE",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "VERAX_DEV_TOKEN",
]);

/**
 * Environment handed to a desktop child. Bootstrap and preload variables are
 * removed. Other `VERAX_*` names are left as given. `NO_COLOR` and `FORCE_COLOR`
 * stay forced off, as they were before this filter.
 */
export function desktopChildEnv(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, NO_COLOR: "1", FORCE_COLOR: "0" };
  for (const key of Object.keys(env)) {
    if (DESKTOP_CHILD_ENV_DROPPED.has(key.toUpperCase())) delete env[key];
  }
  return env;
}

function cleanEnv(): NodeJS.ProcessEnv {
  return desktopChildEnv(process.env);
}

/**
 * `windowsHide` is right for the servers: it keeps a console window off the
 * screen. It is wrong for the browser. On Windows the flag becomes SW_HIDE in
 * the child's STARTUPINFO, and Chrome and Edge honour it for their first
 * window: the process starts, renderers run, the panel answers on its port,
 * and the app window is created hidden. That is the desktop app opening to
 * nothing. The browser must be spawned with the flag off.
 */
function spawnLogged(
  cmd: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
  hideWindow = true,
): ChildProcess {
  return spawn(cmd, args, {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: hideWindow,
    detached: process.platform !== "win32",
  });
}

function defaultBrowser(): string | null {
  const edge = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  const chrome = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
  ];
  for (const p of edge) if (existsSync(p)) return p;
  for (const p of chrome) if (existsSync(p)) return p;
  return null;
}

/**
 * First launched script, or its parent, that someone else can replace.
 * Null when every path is a real file or directory held tightly enough to run.
 * `detail` is the second line of the refusal: who can write, or why the path
 * could not be judged. `read`, when set, is the one Windows DACL read;
 * otherwise that read is `readWindowsAcls` of the whole list.
 */
export function desktopCodeRefusal(
  paths: readonly string[],
  platform: NodeJS.Platform,
  read?: (p: readonly string[]) => Map<string, { sddl: string | null }>,
  invoking?: string,
): { path: string; detail: string } | null {
  for (const p of paths) {
    let st: ReturnType<typeof lstatSync>;
    try {
      st = lstatSync(p);
    } catch {
      return { path: p, detail: " (could not be read)" };
    }
    if (st.isSymbolicLink() || (!st.isDirectory() && !st.isFile())) {
      return { path: p, detail: " (is a link or not a regular file)" };
    }
    if (platform === "win32") continue;
    const uid = typeof process.getuid === "function" ? process.getuid() : 0;
    if ((st.uid !== uid && st.uid !== 0) || (st.mode & 0o022) !== 0) {
      return { path: p, detail: ` (owner uid ${st.uid}; mode ${(st.mode & 0o777).toString(8)})` };
    }
  }
  if (platform !== "win32") return null;
  const acls = read !== undefined ? read(paths) : readWindowsAcls(paths);
  const svc = invoking?.trim().toUpperCase() ?? "";
  for (const p of paths) {
    const sddl = acls.get(p)?.sddl ?? null;
    if (sddl === null) return { path: p, detail: " (ACL could not be read)" };
    if (windowsUserCanWrite(sddl, { svcSid: svc })) return { path: p, detail: aclWho(sddl, svc) };
  }
  return null;
}

export async function runDesktop(
  opts: DesktopOpts,
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
  hooks?: DesktopHooks,
): Promise<number> {
  const repoRoot = resolveRepoRoot();
  const cloneOnly = desktopCloneError(repoRoot);
  if (cloneOnly) {
    writeErr(cloneOnly);
    return 78;
  }
  // Before the issuer, the body, or the window: a first run with no operator
  // file otherwise opens a panel that cannot read the ledger and does not say why.
  const passkeyHint = desktopPasskeyHint(opts.stateDir);
  if (passkeyHint) writeErr(passkeyHint);
  // Directories that may already hold the ledger and keys: the grants must be inheritable.
  const restrictOwner = hooks?.restrictOwner ?? ((dir: string) => restrictToOwnerWin32(dir, undefined, true));
  const tokenPath = join(opts.stateDir, "dev-token");
  const issuerScript = join(repoRoot, "scripts", "dev-issuer.mjs");
  const mainTs = join(here, "main.ts");
  const viteJs = join(repoRoot, "node_modules", "vite", "bin", "vite.js");
  const panelDir = join(repoRoot, "apps", "panel");
  const policy = join(repoRoot, "packages", "proxy", "policy", "default.json");
  // Browser-facing origins are localhost: an IP address cannot be a WebAuthn RP ID,
  // and an RP ID of localhost does not match a page on 127.0.0.1. The audience is
  // the same host so the token `aud` and the body's VERAX_AUDIENCE agree; it is
  // not a page. The children bind 127.0.0.1. This process also holds [::1] on
  // those ports and pipes each connection to 127.0.0.1, so a page fetched as
  // localhost cannot land on another local user's socket. Node (the panel
  // proxy, the JWKS URL) uses 127.0.0.1 so it does not follow a resolver that
  // tries ::1 first.
  const audience = `http://localhost:${opts.bodyPort}`;
  const issuerUrl = `http://localhost:${opts.issuerPort}`;
  const panelOrigin = `http://localhost:${opts.panelPort}`;
  const bodyLoopback = `http://127.0.0.1:${opts.bodyPort}`;
  const issuerLoopback = `http://127.0.0.1:${opts.issuerPort}`;
  const kids: ChildProcess[] = [];
  const log = { text: "" };
  const gate = { watch: true };
  const exited: { name: DesktopChildName | null } = { name: null };
  let resolveGone: (name: DesktopChildName) => void = () => {};
  const childGone = new Promise<DesktopChildName>((resolve) => {
    resolveGone = resolve;
  });

  const forwarders: Server[] = [];
  const stopForwarders = () => {
    for (const server of forwarders) {
      server.close();
      server.unref();
    }
    forwarders.length = 0;
  };
  const claimIpv6 = async (port: number): Promise<"held" | "busy" | "unsupported"> => {
    if (forwarders.some((server) => listeningPort(server) === port)) return "held";
    const opened = await forwardIpv6Loopback(port);
    if (!opened.ok) return opened.reason;
    forwarders.push(opened.server);
    return "held";
  };
  const killPid = hooks?.kill ?? killTree;
  const stopAll = () => {
    gate.watch = false;
    stopForwarders();
    for (const c of kids) killPid(c.pid);
  };
  const signalHost: DesktopSignalHost = hooks?.signals ?? (process as unknown as DesktopSignalHost);
  const signalPlatform = hooks?.signals?.platform ?? process.platform;
  let disarmSignals = () => {};
  const launch = (
    name: DesktopSpawnName,
    cmd: string,
    args: string[],
    env: NodeJS.ProcessEnv,
    cwd: string,
    hideWindow = true,
  ): ChildProcess => (hooks?.spawn ? hooks.spawn(name, cmd, args, env, cwd) : spawnLogged(cmd, args, env, cwd, hideWindow));
  const pipe = (name: DesktopSpawnName, child: ChildProcess, own: { text: string }) => {
    const feed = (chunk: Buffer | string) => {
      const text = String(chunk);
      own.text = rememberChildOutput(own.text, text);
      log.text = rememberChildOutput(log.text, text);
      hooks?.childOutput?.(name, own.text);
    };
    child.stdout?.on("data", feed);
    child.stderr?.on("data", feed);
  };
  // Before the wait, so a child that dies during startup is the failure.
  const arm = (name: DesktopChildName, child: ChildProcess) => {
    const note = () => {
      if (!gate.watch || exited.name) return;
      exited.name = name;
      resolveGone(name);
      stopAll();
    };
    if (child.exitCode !== null || child.signalCode !== null) note();
    else child.once("exit", note);
  };
  const waitReady = async (
    child: ChildProcess,
    own: { text: string },
    ready: (text: string) => boolean,
    ms: number,
  ): Promise<"ready" | "exited" | "timeout"> => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      if (exited.name || !childStillAlive(child)) return "exited";
      if (ready(own.text)) return childStillAlive(child) && !exited.name ? "ready" : "exited";
      await new Promise((r) => setTimeout(r, 20));
    }
    if (exited.name || !childStillAlive(child)) return "exited";
    return ready(own.text) ? "ready" : "timeout";
  };
  const ipv4Free = (port: number): Promise<boolean> => bindLoopback(port, "127.0.0.1").then((held) => held === "free");
  const busy = async (name: DesktopChildName, port: number): Promise<boolean> => {
    const v6 = await claimIpv6(port);
    if (v6 === "busy") {
      writeErr(desktopPortBusyLine(name, port, true));
      stopAll();
      return true;
    }
    if (await ipv4Free(port)) return false;
    writeErr(desktopPortBusyLine(name, port));
    stopAll();
    return true;
  };
  const childFailed = (name: DesktopChildName): number => {
    writeErr(desktopChildExitedLine(exited.name ?? name));
    stopAll();
    return 1;
  };

  try {
    disarmSignals = armDesktopStop(signalHost, signalPlatform, stopAll);
    ensureDesktopDirectory(opts.stateDir, restrictOwner, {
      platform: hooks?.platform,
      windowsDirectoryOwner: hooks?.windowsDirectoryOwner,
      windowsDirectoryDacl: hooks?.windowsDirectoryDacl,
      windowsAncestorDacl: hooks?.windowsAncestorDacl,
    });
    // hooks.spawn stands in for the children, so those tests never execute these
    // files. Skip the writability check there. Production, which has no spawn hook, always runs it.
    if (!hooks?.spawn) {
      const codePaths = [issuerScript, dirname(issuerScript), mainTs, dirname(mainTs), viteJs, dirname(viteJs)];
      const codePlatform = hooks?.platform ?? process.platform;
      const invoking = codePlatform === "win32" ? (windowsInvokingSid()?.trim().toUpperCase() ?? "") : undefined;
      const refused = desktopCodeRefusal(codePaths, codePlatform, undefined, invoking);
      if (refused !== null) {
        writeErr(`desktop-code-writable:${refused.path}\n${refused.detail.trim()}\n`);
        stopAll();
        return 1;
      }
    }
    const decided = await desktopMode(opts.stateDir, opts.bodyPort, hooks?.listenerPid);
    trace("mode-decided");
    if ("error" in decided) {
      const named = decided.lockPort === null ? "unknown" : String(decided.lockPort);
      writeErr(`${decided.error}:${decided.pid}:${named}\n`);
      return 1;
    }

    // 0.4.0 does not join a body that is already running on this state directory.
    // The attached body is not supervised: if it dies, another local user can
    // bind 127.0.0.1 on its port and the panel would hand over the operator
    // session. Stop before any port is claimed and before any child starts.
    if (decided.mode === "attach") {
      writeErr(`desktop-body-running:${opts.bodyPort}\n`);
      writeErr(
        "a body is already running on this state directory; use the panel of the desktop that started it, or stop that body first. verax unlock is for a dead lock only\n",
      );
      return 1;
    }

    // Only the ports this run will bind must be free.
    const ports: [DesktopChildName, number][] = [
      ["issuer", opts.issuerPort],
      ["body", opts.bodyPort],
      ["panel", opts.panelPort],
    ];
    for (const [name, port] of ports) {
      if (await busy(name, port)) return 1;
    }

    let token: string | null = null;
    // A token or pin left on disk is the previous run's. This issuer must write both.
      // This file is the dev issuer's --out token, not the install agent token
      // (`%ProgramData%\Verax\agent-token\<SID>\agent.token` or `~/.verax/agent.token`).
      discardStaleFile(tokenPath);
      discardStaleFile(issuerJwksPinPath(opts.stateDir));
      if (await busy("issuer", opts.issuerPort)) return 1;
      trace("issuer-launch");
      const issuer = launch(
        "issuer",
        process.execPath,
        ["--experimental-strip-types", issuerScript, "--out", tokenPath],
        { ...issuerEnv(cleanEnv(), opts, audience, issuerUrl), [DESKTOP_PARENT_PID]: String(process.pid) },
        repoRoot,
      );
      kids.push(issuer);
      arm("issuer", issuer);
      const issuerOut = { text: "" };
      pipe("issuer", issuer, issuerOut);
      const issuerReady = await waitReady(
        issuer,
        issuerOut,
        (text) => text.includes(issuerReadyLine(opts.issuerPort)),
        hooks?.readyMs ?? 15_000,
      );
      trace(`issuer-${issuerReady}`);
      if (issuerReady === "exited") return childFailed("issuer");
      if (issuerReady === "timeout") {
        writeErr("desktop-issuer-timeout\n");
        stopAll();
        return 1;
      }
      // The --out file is the agent credential. It does not carry verax:audit.
      // The panel reads the ledger with the passkey session, not this file.
      let tokenText = "";
      try {
        tokenText = readFileSync(tokenPath, "utf8").trim();
      } catch {
        tokenText = "";
      }
      if (tokenText === "") {
        writeErr("desktop-token-missing\n");
        stopAll();
        return 1;
      }
      token = tokenText;

      // The body verifies with the keys this issuer wrote at start. A fetch of
      // the port would pin whoever answered. VERAX_JWKS_FILE is not this pin:
      // that mode refuses operator scopes. The URL stays so config can load;
      // the pin is what verification uses, and it does not refetch.
      let pinnedJwks: string;
      try {
        pinnedJwks = readIssuerJwksPin(opts.stateDir);
      } catch {
        writeErr("desktop-jwks-pin-failed\n");
        stopAll();
        return 1;
      }

      if (await busy("body", opts.bodyPort)) return 1;
      trace("body-launch");
      const body = launch(
        "body",
        process.execPath,
        ["--experimental-strip-types", mainTs],
        {
          ...cleanEnv(),
          VERAX_STATE_DIR: opts.stateDir,
          VERAX_ISSUER: issuerUrl,
          VERAX_JWKS_URL: `${issuerLoopback}/.well-known/jwks.json`,
          VERAX_JWKS_PIN: pinnedJwks,
          VERAX_AUDIENCE: audience,
          VERAX_BIND: `127.0.0.1:${opts.bodyPort}`,
          VERAX_ALLOWED_ORIGINS: mergeAllowedOrigin(process.env.VERAX_ALLOWED_ORIGINS, panelOrigin),
          VERAX_POLICY_FILE: policy,
          [DESKTOP_PARENT_PID]: String(process.pid),
          ...(opts.inventoryFile ? { VERAX_INVENTORY_FILE: opts.inventoryFile } : {}),
        },
        repoRoot,
      );
      kids.push(body);
      arm("body", body);
      const bodyOut = { text: "" };
      pipe("body", body, bodyOut);
      const bodyReady = await waitReady(
        body,
        bodyOut,
        (text) => text.includes(bodyReadyLine(opts.bodyPort)),
        hooks?.readyMs ?? 15_000,
      );
      trace(`body-${bodyReady}`);
      if (bodyReady === "exited") return childFailed("body");
      if (bodyReady === "timeout") {
        writeErr("desktop-body-timeout\n");
        stopAll();
        return 1;
      }

    const panelSources = [
      join(panelDir, "src"),
      join(panelDir, "index.html"),
      join(panelDir, "vite.config.ts"),
      join(repoRoot, "packages"),
    ];
    if (!hooks?.spawn && panelBuildNeeded(join(panelDir, "dist", "index.html"), panelSources)) {
      trace("panel-build");
      const built = spawnSync(process.execPath, [viteJs, "build"], {
        cwd: panelDir,
        env: { ...cleanEnv(), VERAX_BODY_URL: bodyLoopback },
        encoding: "utf8",
        windowsHide: true,
      });
      if (built.status !== 0) {
        const detail = `${built.stderr ?? ""}\n${built.stdout ?? ""}`.slice(0, 800);
        writeErr(`desktop-panel-build-failed\n${detail}\n`);
        stopAll();
        return 1;
      }
    }

    if (await busy("panel", opts.panelPort)) return 1;
    // vite preview has no parent-pid watch. stopAll kills it with the tree.
    // A launcher killed outright does not run stopAll; the issuer and the body
    // exit when VERAX_DESKTOP_PARENT_PID is gone, and without them this port is idle.
    const panel = launch(
      "panel",
      process.execPath,
      [viteJs, "preview", "--host", "127.0.0.1", "--port", String(opts.panelPort), "--strictPort"],
      {
        ...cleanEnv(),
        VERAX_BODY_URL: bodyLoopback,
      },
      panelDir,
    );
    kids.push(panel);
    arm("panel", panel);
    const panelOut = { text: "" };
    pipe("panel", panel, panelOut);
    const panelReady = await waitReady(
      panel,
      panelOut,
      (text) => text.includes(panelReadyLine(opts.panelPort)),
      hooks?.readyMs ?? 20_000,
    );
    trace(`panel-${panelReady}`);
    if (panelReady === "exited") return childFailed("panel");
    if (panelReady === "timeout") {
      writeErr("desktop-panel-timeout\n");
      stopAll();
      return 1;
    }

    const url = panelOrigin;
    const scriptBrowser = Boolean(opts.browser && /\.(mjs|js|ts)$/.test(opts.browser));
    const browserBin = scriptBrowser ? process.execPath : (opts.browser ?? defaultBrowser());
    if (!browserBin) {
      writeErr("desktop-browser-missing\n");
      stopAll();
      return 1;
    }
    const profileDir = join(opts.stateDir, "browser-profile");
    ensureDesktopDirectory(profileDir, restrictOwner, {
      platform: hooks?.platform,
      windowsDirectoryOwner: hooks?.windowsDirectoryOwner,
      windowsDirectoryDacl: hooks?.windowsDirectoryDacl,
      windowsAncestorDacl: hooks?.windowsAncestorDacl,
    });
    const browserArgv = scriptBrowser
      ? [opts.browser!, url]
      : [
          `--user-data-dir=${profileDir}`,
          "--no-first-run",
          "--no-default-browser-check",
          `--app=${url}`,
          "--window-size=1360,880",
        ];
    trace("browser-launch");
    const browser = launch("browser", browserBin, browserArgv, cleanEnv(), repoRoot, false);
    kids.push(browser);
    pipe("browser", browser, { text: "" });
    if (token !== null && log.text.includes(token)) {
      writeErr("desktop-token-leaked\n");
      stopAll();
      return 1;
    }
    process.stdout.write(
      `desktop-ready issuer=${opts.issuerPort} body=${opts.bodyPort} panel=${opts.panelPort}\n`,
    );
    const closed = new Promise<void>((resolve) => {
      if (browser.exitCode !== null || browser.signalCode !== null) resolve();
      else browser.once("close", () => resolve());
    });
    const childExit = async (name: DesktopChildName): Promise<number> => {
      writeErr(desktopChildExitedLine(name));
      stopAll();
      return 1;
    };
    const exitedEarly = await Promise.race([
      closed.then(() => ({ kind: "browser" as const })),
      childGone.then((name) => ({ kind: "child" as const, name })),
      new Promise<{ kind: "stay" }>((resolve) => {
        setTimeout(() => resolve({ kind: "stay" }), 3_000);
      }),
    ]);
    if (exitedEarly.kind === "child") return childExit(exitedEarly.name);
    if (exitedEarly.kind === "browser") {
      writeErr("desktop-browser-exited-early\n");
      stopAll();
      return 1;
    }
    const ended = await Promise.race([
      closed.then(() => ({ kind: "browser" as const })),
      childGone.then((name) => ({ kind: "child" as const, name })),
    ]);
    if (ended.kind === "child") return childExit(ended.name);
    stopAll();
    return 0;
  } catch (err) {
    stopAll();
    const msg = err instanceof Error ? err.message : "unknown";
    writeErr(`desktop-failed:${msg}\n`);
    return 1;
  } finally {
    disarmSignals();
  }
}

/** SIGHUP on POSIX, SIGBREAK on Windows, plus crash and process exit. `stopAll` is synchronous. */
function armDesktopStop(host: DesktopSignalHost, platform: NodeJS.Platform, stopAll: () => void): () => void {
  const onSignal = () => {
    stopAll();
    host.exit(1);
  };
  const onCrash = () => {
    stopAll();
    host.exit(1);
  };
  const onExit = () => {
    stopAll();
  };
  const paired: [string, () => void][] = [
    ["SIGINT", onSignal],
    ["SIGTERM", onSignal],
    // Node raises SIGHUP on Windows too, when the console window is closed.
    ["SIGHUP", onSignal],
    ...(platform === "win32" ? ([["SIGBREAK", onSignal]] as [string, () => void][]) : []),
    ["uncaughtException", onCrash],
    ["unhandledRejection", onCrash],
  ];
  for (const [event, fn] of paired) host.once(event, fn);
  host.on("exit", onExit);
  return () => {
    for (const [event, fn] of paired) host.removeListener(event, fn);
    host.removeListener("exit", onExit);
  };
}

export async function desktopMain(argv: string[]): Promise<number> {
  const parsed = parseDesktopArgs(argv);
  if ("error" in parsed) {
    process.stderr.write("verax desktop [--state <dir>] [--port 5173] [--browser <cmd>] [--inventory <file>]\n");
    return 78;
  }
  return runDesktop(parsed);
}
