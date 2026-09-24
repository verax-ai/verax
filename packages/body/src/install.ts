import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { get } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EX_CONFIG } from "./config.ts";
import { runInitLocal } from "./init-local.ts";

export const EX_ELEVATION = 77;

export const ELEVATION_LINE = "verax install needs an elevated shell (Administrator / root)";

export function unreadableSentence(dir: string): string {
  return `cannot read ${dir}: run this from an elevated terminal (Administrator / sudo)`;
}

const DEFAULT_DAYS = 30;
const MAX_DAYS = 90;
const DEFAULT_PORT = 8787;
const MIN_PORT = 1024;
const MAX_PORT = 65535;
const HEALTH_WAIT_MS = 20_000;

const LOCAL_SERVICE = "NT AUTHORITY\\LOCAL SERVICE";
const LOCAL_SERVICE_TASK = "NT AUTHORITY\\LOCALSERVICE";
const ADMINISTRATORS = "BUILTIN\\Administrators";
const ADMINISTRATORS_SID = "*S-1-5-32-544";
const SYSTEM_SID = "*S-1-5-18";
const TASK_NAME = "Verax Body";

const WIN32_TOOLS = ["whoami", "icacls", "schtasks", "net", "fsutil", "powershell"] as const;
const LINUX_TOOLS = ["useradd", "chown", "chmod", "id", "getent", "stat", "systemctl"] as const;
const DARWIN_TOOLS = ["dscl", "launchctl", "chown", "chmod", "id", "stat"] as const;
const LINUX_TOOL_DIRS = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] as const;
const DARWIN_TOOL_DIRS = ["/usr/bin", "/usr/sbin", "/bin"] as const;
const SYSTEM_TOOL_NAMES = new Set<string>([...WIN32_TOOLS, ...LINUX_TOOLS, ...DARWIN_TOOLS]);

export class SystemToolError extends Error {
  readonly code = EX_CONFIG;
  constructor(message: string) {
    super(message);
  }
}

/** Basename of a planned or resolved tool, without a Windows `.exe`. */
export function systemToolName(argv0: string): string {
  const base = argv0.split(/[/\\]/).pop() ?? argv0;
  return base.toLowerCase().replace(/\.exe$/, "");
}

function driveRootAbsolute(value: string): boolean {
  if (!path.win32.isAbsolute(value)) return false;
  return /^[A-Za-z]:[\\/]$/.test(path.win32.parse(value).root);
}

function windowsSystemRoot(): string {
  const root = process.env.SystemRoot ?? "C:\\Windows";
  if (!driveRootAbsolute(root)) {
    throw new SystemToolError(`refusing: SystemRoot ${root} is not an absolute path under a drive root`);
  }
  return root;
}

/**
 * Absolute path for a system tool. Windows uses System32 under SystemRoot.
 * Linux and macOS walk fixed directories and never consult PATH.
 * A missing POSIX binary falls back to the first candidate so a plan can name
 * the path; spawning still refuses when that file is absent.
 */
export function systemToolPath(tool: string, platform: NodeJS.Platform = process.platform): string {
  const name = systemToolName(tool);
  if (platform === "win32") {
    const root = windowsSystemRoot();
    if (name === "powershell") {
      return path.win32.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    }
    return path.win32.join(root, "System32", `${name}.exe`);
  }
  const dirs = platform === "darwin" ? DARWIN_TOOL_DIRS : LINUX_TOOL_DIRS;
  for (const dir of dirs) {
    const candidate = `${dir}/${name}`;
    if (existsSync(candidate)) return candidate;
  }
  return `${dirs[0]}/${name}`;
}

/** Absolute paths for every system tool on `platform`. */
export function systemToolTable(platform: NodeJS.Platform = process.platform): Record<string, string> {
  const names = platform === "win32" ? WIN32_TOOLS : platform === "darwin" ? DARWIN_TOOLS : LINUX_TOOLS;
  const table: Record<string, string> = {};
  for (const name of names) table[name] = systemToolPath(name, platform);
  return table;
}

export function requireSystemTool(tool: string, platform: NodeJS.Platform = process.platform): string {
  const resolved = systemToolPath(tool, platform);
  if (!existsSync(resolved)) {
    throw new SystemToolError(`refusing: ${resolved} does not exist`);
  }
  return resolved;
}

/** Env for system-tool spawns. The caller's PATH is not copied. */
export function systemToolEnv(platform: NodeJS.Platform = process.platform): NodeJS.ProcessEnv {
  if (platform === "win32") {
    const env: NodeJS.ProcessEnv = {};
    if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    if (process.env.windir) env.windir = process.env.windir;
    if (process.env.TEMP) env.TEMP = process.env.TEMP;
    if (process.env.TMP) env.TMP = process.env.TMP;
    return env;
  }
  return { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" };
}

function toolArgv(tool: string, args: readonly string[], platform: NodeJS.Platform = process.platform): string[] {
  return [systemToolPath(tool, platform), ...args];
}

type ToolSpawn = (
  file: string,
  args: readonly string[],
  opts: { encoding: "utf8"; windowsHide: true; shell: false; env: NodeJS.ProcessEnv },
) => Pick<SpawnSyncReturns<string>, "status" | "stdout" | "stderr">;

function defaultToolSpawn(
  file: string,
  args: readonly string[],
  opts: { encoding: "utf8"; windowsHide: true; shell: false; env: NodeJS.ProcessEnv },
): Pick<SpawnSyncReturns<string>, "status" | "stdout" | "stderr"> {
  return spawnSync(file, args, opts);
}

function spawnSystemTool(
  tool: string,
  args: readonly string[],
  platform: NodeJS.Platform = process.platform,
): Pick<SpawnSyncReturns<string>, "status" | "stdout" | "stderr"> {
  const file = requireSystemTool(tool, platform);
  return spawnSync(file, args, {
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    env: systemToolEnv(platform),
  });
}

const USER_WRITE_PRINCIPALS = [
  "builtin\\users",
  "nt authority\\authenticated users",
  "everyone",
  "interactive",
  "nt authority\\interactive",
];

export function nodeTrustMessage(nodePath: string): string {
  return `Node at ${nodePath} can be changed by your user account; install Node for all users (nodejs.org installer) and run verax install from that Node`;
}

export type InstallPlatform = "win32" | "linux" | "darwin";

export type PlanOpts = {
  port?: number;
  days?: number;
  force?: boolean;
  /** Trusted Node used to run npm and the service. It is not copied. */
  execPath: string;
  bodyVersion: string;
  npmCli: string;
  stateExists: boolean;
  /** `%ProgramData%\\Verax` (or the Linux code/state parents) already exists. */
  veraxRootExists?: boolean;
  /** `install.json` written by a previous verax install. */
  markerExists?: boolean;
  /** Junction, symlink, or other reparse point. Named in the refusal. */
  reparsePath?: string;
  /** Injected `icacls` text for the Node tree. A user write ACE refuses. */
  nodeIcacls?: string;
  userSid?: string;
  /** Linux: uid and mode of the Node file and each parent. Non-root or group/other-writable refuses. */
  nodeModes?: { uid: number; mode: number }[];
  /** Release-test install from `npm pack` tarballs. Skips the registry and signature audit. */
  fromTarballs?: string;
  tarballFiles?: string[];
  /** Injected icacls text for the tarball directory. A user write ACE refuses. */
  tarballIcacls?: string;
  /** Linux uid/mode of the tarball directory and each tarball. */
  tarballModes?: { uid: number; mode: number }[];
  linuxState?: { exists: boolean; symlink: boolean; owner: string };
  linuxCode?: { exists: boolean; symlink: boolean; owner: string };
};

export type PlanOp =
  | { op: "manifest"; dir: string }
  | { op: "mkdir"; path: string; mode?: number }
  | { op: "argv"; argv: string[]; optional?: boolean; rollbackDir?: string }
  | { op: "write"; path: string; contents: string; mode?: number }
  | { op: "init"; stateDir: string; tokenPath: string; port: number; days: number; force: boolean }
  | { op: "remove"; path: string }
  | { op: "wait-healthz"; port: number; timeoutMs: number }
  | { op: "print"; text: string };

export type InstallPlan =
  | { ok: false; code: number; message: string }
  | { ok: true; ops: PlanOp[]; codeDir: string; stateDir: string; tokenPath: string };

export type ExecResult = { status: number | null; stdout?: string; stderr?: string };

export type InstallIo = {
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
};

export type InstallHooks = {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  elevated?: () => boolean;
  exec?: (argv: string[]) => ExecResult;
  stateExists?: (dir: string) => boolean;
  layout?: { execPath: string; bodyVersion: string; npmCli: string };
  io?: InstallIo;
};

type Paths = { codeDir: string; stateDir: string; tokenPath: string };

function fail(code: number, message: string): InstallPlan {
  return { ok: false, code, message: message.endsWith("\n") ? message : `${message}\n` };
}

export function stateDirFor(platform: NodeJS.Platform | InstallPlatform, env: NodeJS.ProcessEnv = process.env): string {
  if (platform === "win32") {
    const data = env.ProgramData || "C:\\ProgramData";
    return path.win32.join(data, "Verax", "state");
  }
  return "/var/lib/verax";
}

export function codeDirFor(platform: NodeJS.Platform | InstallPlatform, env: NodeJS.ProcessEnv = process.env): string {
  if (platform === "win32") {
    const files = env.ProgramFiles || "C:\\Program Files";
    return path.win32.join(files, "Verax");
  }
  return "/opt/verax";
}

function linuxHome(env: NodeJS.ProcessEnv): { home: string } | { error: string } {
  const user = env.SUDO_USER?.trim() ?? "";
  if (user === "") return { error: "verax install needs SUDO_USER to find the invoking user's home" };
  if (env.VERAX_INVOKING_HOME?.trim()) return { home: env.VERAX_INVOKING_HOME.trim() };
  if (user === "root") return { home: "/root" };
  return { home: `/home/${user}` };
}

function pathsFor(
  platform: InstallPlatform,
  env: NodeJS.ProcessEnv,
): { ok: true; paths: Paths; home: string } | { ok: false; code: number; message: string } {
  if (platform === "darwin") {
    return { ok: false, code: EX_CONFIG, message: "verax install does not run on macOS yet\n" };
  }
  if (platform === "win32") {
    const profile = env.USERPROFILE?.trim() ?? "";
    if (profile === "") return { ok: false, code: EX_CONFIG, message: "verax install needs USERPROFILE for the agent token\n" };
    const paths = {
      codeDir: codeDirFor("win32", env),
      stateDir: stateDirFor("win32", env),
      tokenPath: path.win32.join(profile, ".verax", "agent.token"),
    };
    return { ok: true, paths, home: profile };
  }
  if (platform !== "linux") {
    return { ok: false, code: EX_CONFIG, message: "verax install does not run on this operating system\n" };
  }
  const home = linuxHome(env);
  if ("error" in home) return { ok: false, code: EX_CONFIG, message: `${home.error}\n` };
  const paths = {
    codeDir: "/opt/verax",
    stateDir: "/var/lib/verax",
    tokenPath: path.posix.join(home.home, ".verax", "agent.token"),
  };
  return { ok: true, paths, home: home.home };
}

function cliBinFor(codeDir: string, platform: InstallPlatform): string {
  const p = platform === "win32" ? path.win32 : path.posix;
  return p.join(codeDir, "node_modules", "@verax-ai", "body", "dist", "cli.js");
}

export function npmCliPath(execPath: string, platform: InstallPlatform): string {
  if (platform === "win32") {
    return path.win32.join(path.win32.dirname(execPath), "node_modules", "npm", "bin", "npm-cli.js");
  }
  const prefix = path.posix.dirname(path.posix.dirname(execPath));
  return path.posix.join(prefix, "lib", "node_modules", "npm", "bin", "npm-cli.js");
}

export function ancestry(file: string, platform: InstallPlatform): string[] {
  const p = platform === "win32" ? path.win32 : path.posix;
  const out: string[] = [];
  let cur = file;
  for (let i = 0; i < 64; i += 1) {
    out.push(cur);
    const parent = p.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return out;
}

function aceGrantsWrite(fromColon: string): boolean {
  if (/\(DENY\)/i.test(fromColon)) return false;
  const skip = new Set(["OI", "CI", "IO", "NP", "I"]);
  for (const match of fromColon.matchAll(/\(([^)]+)\)/g)) {
    const token = match[1]!.toUpperCase();
    if (skip.has(token)) continue;
    if (token === "WD" || token === "AD" || token === "GA" || token === "GW") return true;
    if (/[WMF]/.test(token)) return true;
  }
  return false;
}

function principalHit(left: string, principals: string[]): boolean {
  const key = left.toLowerCase();
  return principals.some((p) => key === p || key.endsWith(`\\${p}`) || key.endsWith(` ${p}`));
}

/** True when icacls text grants write to a non-administrator principal. */
export function windowsUserCanWrite(icaclsText: string, opts?: { path?: string; userSid?: string }): boolean {
  const principals = [...USER_WRITE_PRINCIPALS];
  const sid = opts?.userSid?.trim().toLowerCase() ?? "";
  if (sid !== "") principals.push(sid);
  for (const raw of icaclsText.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || /^successfully processed/i.test(line)) continue;
    const mark = line.indexOf(":(");
    if (mark < 0) continue;
    let left = line.slice(0, mark).trim();
    if (opts?.path && left.toLowerCase().startsWith(opts.path.toLowerCase())) {
      left = left.slice(opts.path.length).trim();
    }
    if (!principalHit(left, principals)) continue;
    if (aceGrantsWrite(line.slice(mark))) return true;
  }
  return false;
}

function linuxNodeUntrusted(modes: { uid: number; mode: number }[]): boolean {
  return modes.some((st) => st.uid !== 0 || (st.mode & 0o022) !== 0);
}

function setOwner(dir: string): PlanOp {
  return { op: "argv", argv: toolArgv("icacls", [dir, "/setowner", ADMINISTRATORS_SID, "/T", "/C"], "win32") };
}

function grantService(dir: string, tree: boolean): PlanOp {
  const argv = toolArgv("icacls", [dir], "win32");
  if (tree) argv.push("/T");
  argv.push(
    "/inheritance:r",
    "/grant:r",
    `${LOCAL_SERVICE}:(OI)(CI)F`,
    "/grant:r",
    `${ADMINISTRATORS}:(OI)(CI)F`,
  );
  return { op: "argv", argv };
}

export function successText(
  platform: "win32" | "linux",
  info: { codeDir: string; stateDir: string; tokenPath: string; port: number },
): string {
  const origin = `http://127.0.0.1:${info.port}`;
  const claude =
    platform === "win32"
      ? `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(Get-Content -Raw '${info.tokenPath}')"`
      : `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(cat '${info.tokenPath}')"`;
  const how = platform === "win32" ? "Run as administrator" : "sudo verax approve";
  return [
    `code ${info.codeDir}`,
    `state ${info.stateDir}`,
    `agent token ${info.tokenPath}`,
    "",
    "Claude Code:",
    claude,
    "",
    "Approve held calls from an elevated terminal: verax approve",
    how,
    "",
  ].join("\n");
}

function bounds(opts: PlanOpts): { port: number; days: number } | { error: string } {
  const port = opts.port ?? DEFAULT_PORT;
  const days = opts.days ?? DEFAULT_DAYS;
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    return { error: "--port wants an integer from 1024 to 65535" };
  }
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    return { error: "--days wants an integer from 1 to 90" };
  }
  return { port, days };
}

function winPrincipal(env: NodeJS.ProcessEnv, profile: string): string {
  const user = env.USERNAME?.trim() || path.win32.basename(profile);
  return env.USERDOMAIN?.trim() ? `${env.USERDOMAIN.trim()}\\${user}` : user;
}

function unitText(nodeBin: string, cliBin: string, envFile: string): string {
  return [
    "[Unit]",
    "Description=Verax body",
    "After=network.target",
    "",
    "[Service]",
    "Type=simple",
    "User=verax",
    `ExecStart=${nodeBin} ${cliBin} serve --env-file ${envFile}`,
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ReadWritePaths=/var/lib/verax",
    "ProtectHome=yes",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

function linuxOwnedByUs(fact: { exists: boolean; symlink: boolean; owner: string } | undefined, dir: string): InstallPlan | null {
  if (!fact) return null;
  if (fact.symlink) return fail(EX_CONFIG, `refusing: ${dir} is a symlink`);
  if (fact.exists && fact.owner !== "root" && fact.owner !== "verax") {
    return fail(EX_CONFIG, `refusing: ${dir} is not owned by root or verax`);
  }
  return null;
}

export function planInstall(platform: InstallPlatform, env: NodeJS.ProcessEnv, opts: PlanOpts): InstallPlan {
  const located = pathsFor(platform, env);
  if (!located.ok) return fail(located.code, located.message);
  if (platform === "win32") {
    try {
      systemToolPath("whoami", "win32");
    } catch (err) {
      if (err instanceof SystemToolError) return fail(EX_CONFIG, err.message);
      throw err;
    }
  }
  if (platform !== "win32" && platform !== "linux") {
    return fail(EX_CONFIG, "verax install does not run on this operating system");
  }
  const limited = bounds(opts);
  if ("error" in limited) return fail(EX_CONFIG, limited.error);
  if (opts.nodeIcacls !== undefined && windowsUserCanWrite(opts.nodeIcacls, { userSid: opts.userSid })) {
    return fail(EX_CONFIG, nodeTrustMessage(opts.execPath));
  }
  if (opts.nodeModes !== undefined && linuxNodeUntrusted(opts.nodeModes)) {
    return fail(EX_CONFIG, nodeTrustMessage(opts.execPath));
  }
  if (opts.fromTarballs) {
    if (opts.tarballIcacls !== undefined && windowsUserCanWrite(opts.tarballIcacls, { path: opts.fromTarballs, userSid: opts.userSid })) {
      return fail(EX_CONFIG, tarballTrustMessage(opts.fromTarballs));
    }
    if (opts.tarballModes !== undefined && linuxNodeUntrusted(opts.tarballModes)) {
      return fail(EX_CONFIG, tarballTrustMessage(opts.fromTarballs));
    }
    if (!opts.tarballFiles || opts.tarballFiles.length === 0) {
      return fail(EX_CONFIG, `--from-tarballs ${opts.fromTarballs} has no tarballs`);
    }
  }
  const { paths } = located;
  if (opts.reparsePath) return fail(EX_CONFIG, `refusing: ${opts.reparsePath} is a reparse point`);
  if (platform === "win32") {
    const root = path.win32.dirname(paths.stateDir);
    if (opts.veraxRootExists && !opts.markerExists) {
      return fail(EX_CONFIG, `refusing: ${root} was not created by verax install`);
    }
    if (opts.stateExists && !opts.markerExists) {
      return fail(EX_CONFIG, `refusing: ${paths.stateDir} was not created by verax install`);
    }
  } else {
    const stateOwn = linuxOwnedByUs(opts.linuxState, paths.stateDir);
    if (stateOwn) return stateOwn;
    const codeOwn = linuxOwnedByUs(opts.linuxCode, paths.codeDir);
    if (codeOwn) return codeOwn;
  }
  if (opts.stateExists && !opts.force) return fail(EX_CONFIG, `refusing: ${paths.stateDir} already exists`);
  const cliBin = cliBinFor(paths.codeDir, platform);
  const envFile = (platform === "win32" ? path.win32 : path.posix).join(paths.stateDir, "verax.env");
  const spec = opts.tarballFiles && opts.tarballFiles.length > 0 ? opts.tarballFiles : [`@verax-ai/body@${opts.bodyVersion}`];
  const npmInstall: PlanOp = {
    op: "argv",
    rollbackDir: paths.codeDir,
    argv: [
      opts.execPath,
      opts.npmCli,
      "install",
      "--prefix",
      paths.codeDir,
      "--omit=dev",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      ...spec,
    ],
  };
  const npmAudit: PlanOp = {
    op: "argv",
    rollbackDir: paths.codeDir,
    argv: [opts.execPath, opts.npmCli, "audit", "signatures", "--prefix", paths.codeDir],
  };
  const ops: PlanOp[] = [{ op: "mkdir", path: paths.codeDir, mode: 0o755 }];
  if (platform === "win32") {
    ops.push(setOwner(paths.codeDir), grantService(paths.codeDir, false));
  }
  ops.push(npmInstall);
  if (!opts.fromTarballs) ops.push(npmAudit);
  if (platform === "win32") ops.push(setOwner(paths.codeDir));
  ops.push({ op: "manifest", dir: paths.codeDir }, { op: "mkdir", path: paths.stateDir, mode: 0o700 });
  if (platform === "win32") {
    const markerPath = path.win32.join(path.win32.dirname(paths.stateDir), "install.json");
    const marker = installMarkerText(opts, paths);
    ops.push(
      setOwner(paths.stateDir),
      grantService(paths.stateDir, false),
      { op: "write", path: markerPath, contents: marker, mode: 0o644 },
      setOwner(markerPath),
      grantService(markerPath, false),
    );
  } else {
    ops.push(
      {
        op: "write",
        path: path.posix.join(paths.codeDir, "install.json"),
        contents: installMarkerText(opts, paths),
        mode: 0o644,
      },
      { op: "argv", argv: toolArgv("useradd", ["--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "verax"], "linux") },
      { op: "argv", argv: toolArgv("chown", ["verax:verax", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "linux") },
    );
  }
  ops.push({
    op: "init",
    stateDir: paths.stateDir,
    tokenPath: paths.tokenPath,
    port: limited.port,
    days: limited.days,
    force: Boolean(opts.force),
  });
  if (platform === "win32") {
    ops.push(
      setOwner(paths.stateDir),
      grantService(paths.stateDir, true),
      {
        op: "argv",
        argv: toolArgv("icacls", [paths.tokenPath, "/inheritance:r", "/grant:r", `${winPrincipal(env, located.home)}:(R)`], "win32"),
      },
    );
    const tr = `"${opts.execPath}" "${cliBin}" serve --env-file "${envFile}"`;
    ops.push(
      {
        op: "argv",
        argv: toolArgv("schtasks", [
          "/Create",
          "/TN",
          TASK_NAME,
          "/SC",
          "ONSTART",
          "/RU",
          LOCAL_SERVICE_TASK,
          "/TR",
          tr,
          "/RL",
          "LIMITED",
          "/F",
        ], "win32"),
      },
      { op: "argv", argv: toolArgv("schtasks", ["/Run", "/TN", TASK_NAME], "win32") },
    );
  } else {
    const sudoUser = env.SUDO_USER!.trim();
    const tokenDir = path.posix.dirname(paths.tokenPath);
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["-R", "verax:verax", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chown", [`${sudoUser}:`, tokenDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", tokenDir], "linux") },
      { op: "argv", argv: toolArgv("chown", [`${sudoUser}:`, paths.tokenPath], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0600", paths.tokenPath], "linux") },
      { op: "write", path: "/etc/systemd/system/verax.service", contents: unitText(opts.execPath, cliBin, envFile), mode: 0o644 },
      { op: "argv", argv: toolArgv("systemctl", ["daemon-reload"], "linux") },
      { op: "argv", argv: toolArgv("systemctl", ["enable", "--now", "verax"], "linux") },
    );
  }
  ops.push(
    { op: "wait-healthz", port: limited.port, timeoutMs: HEALTH_WAIT_MS },
    {
      op: "print",
      text: successText(platform, { ...paths, port: limited.port }),
    },
  );
  const bare = bareSidAccount(ops);
  if (bare) return fail(EX_CONFIG, `refusing icacls account ${bare}: a SID needs a leading *`);
  return { ok: true, ops, ...paths };
}

/** icacls treats a bare `S-1-...` as an account name. A SID is `*S-1-...` or a name. */
function bareSidAccount(ops: PlanOp[]): string | null {
  for (const op of ops) {
    if (op.op !== "argv" || systemToolName(op.argv[0] ?? "") !== "icacls") continue;
    for (let i = 0; i < op.argv.length; i += 1) {
      const flag = op.argv[i];
      if (flag !== "/grant" && flag !== "/grant:r" && flag !== "/setowner") continue;
      for (let j = i + 1; j < op.argv.length && !op.argv[j]!.startsWith("/"); j += 1) {
        const account = op.argv[j]!.split(":")[0] ?? "";
        if (account.startsWith("S-1-")) return op.argv[j]!;
      }
    }
  }
  return null;
}

export function planUninstall(
  platform: InstallPlatform,
  env: NodeJS.ProcessEnv,
  opts: { keepState: boolean },
): InstallPlan {
  const located = pathsFor(platform, env);
  if (!located.ok) return fail(located.code, located.message);
  if (platform === "win32") {
    try {
      systemToolPath("schtasks", "win32");
    } catch (err) {
      if (err instanceof SystemToolError) return fail(EX_CONFIG, err.message);
      throw err;
    }
  }
  const { paths } = located;
  const ops: PlanOp[] = [];
  if (platform === "win32") {
    ops.push(
      { op: "argv", argv: toolArgv("schtasks", ["/End", "/TN", TASK_NAME], "win32"), optional: true },
      { op: "argv", argv: toolArgv("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"], "win32"), optional: true },
    );
  } else {
    ops.push(
      { op: "argv", argv: toolArgv("systemctl", ["disable", "--now", "verax"], "linux"), optional: true },
      { op: "remove", path: "/etc/systemd/system/verax.service" },
      { op: "argv", argv: toolArgv("systemctl", ["daemon-reload"], "linux"), optional: true },
    );
  }
  ops.push({ op: "remove", path: paths.codeDir });
  if (!opts.keepState) ops.push({ op: "remove", path: paths.stateDir });
  return { ok: true, ops, ...paths };
}

const ACL_ALLOWED = new Set([
  "nt authority\\local service",
  "nt authority\\localservice",
  "local service",
  "localservice",
  "builtin\\administrators",
  "administrators",
]);

export function foreignAclPrincipals(text: string, stateDir?: string): string[] {
  const found: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || /^successfully processed/i.test(line)) continue;
    const mark = line.indexOf(":(");
    if (mark < 0) continue;
    let left = line.slice(0, mark).trim();
    if (stateDir && left.toLowerCase().startsWith(stateDir.toLowerCase())) {
      left = left.slice(stateDir.length).trim();
    }
    if (left === "" || ACL_ALLOWED.has(left.toLowerCase())) continue;
    found.push(left);
  }
  return found;
}

export function manifestMismatches(manifest: string, hashOf: (rel: string) => string | null): string[] {
  const bad: string[] = [];
  for (const raw of manifest.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const sp = line.indexOf("  ");
    if (sp < 0) continue;
    const hex = line.slice(0, sp).trim();
    const rel = line.slice(sp + 2).trim();
    const got = hashOf(rel);
    if (got === null || got.toLowerCase() !== hex.toLowerCase()) bad.push(rel);
  }
  return bad;
}

export type BoundaryCheck = { id: string; level: "ok" | "fail"; detail: string };

function adminOrSystem(owner: string): boolean {
  const n = owner.trim().toLowerCase();
  return (
    n === "builtin\\administrators" ||
    n === "administrators" ||
    n === "nt authority\\system" ||
    n === "system" ||
    n.endsWith("\\administrators") ||
    n.endsWith("\\system")
  );
}

export function installedBoundaryChecks(input: {
  codeDir: string;
  stateDir: string;
  manifest: string | null;
  hashOf: (rel: string) => string | null;
  aclText?: string;
  mode?: number;
  owner?: string;
  /** Windows owner names for the state and code directories. */
  winOwners?: { state?: string; code?: string };
  markerPresent?: boolean;
  /** `install.json` `source`. `tarballs` is release testing, not the registry. */
  installSource?: string;
  autostart: boolean;
}): BoundaryCheck[] {
  const checks: BoundaryCheck[] = [
    { id: "install-code", level: "ok", detail: `code ${input.codeDir}` },
  ];
  if (input.manifest === null) {
    checks.push({ id: "install-manifest", level: "fail", detail: `MANIFEST.sha256 is missing under ${input.codeDir}` });
  } else {
    const bad = manifestMismatches(input.manifest, input.hashOf);
    if (bad.length === 0) {
      checks.push({ id: "install-manifest", level: "ok", detail: "every file matches MANIFEST.sha256" });
    } else {
      for (const rel of bad) {
        checks.push({ id: "install-manifest", level: "fail", detail: `manifest mismatch ${rel}` });
      }
    }
  }
  if (input.aclText !== undefined) {
    const foreign = foreignAclPrincipals(input.aclText, input.stateDir);
    if (foreign.length === 0) {
      checks.push({ id: "install-acl", level: "ok", detail: "state ACL names only LocalService and Administrators" });
    } else {
      for (const principal of foreign) {
        checks.push({ id: "install-acl", level: "fail", detail: `state ACL names ${principal}` });
      }
    }
  }
  if (input.mode !== undefined) {
    const bits = input.mode & 0o777;
    if (bits !== 0o700) {
      checks.push({ id: "install-mode", level: "fail", detail: `state mode ${bits.toString(8)} is not 0700` });
    } else if (input.owner !== undefined && input.owner !== "verax") {
      checks.push({ id: "install-mode", level: "fail", detail: `state owner ${input.owner} is not verax` });
    } else {
      checks.push({
        id: "install-mode",
        level: "ok",
        detail: input.owner === undefined ? "state mode 0700" : "state mode 0700 owner verax",
      });
    }
  } else if (input.owner !== undefined && input.owner !== "verax") {
    checks.push({ id: "install-mode", level: "fail", detail: `state owner ${input.owner} is not verax` });
  }
  if (input.winOwners !== undefined) {
    const named: [string, string | undefined][] = [
      ["state", input.winOwners.state],
      ["code", input.winOwners.code],
    ];
    for (const [label, owner] of named) {
      if (owner === undefined || owner === "") {
        checks.push({ id: "install-owner", level: "fail", detail: `${label} owner is not Administrators or SYSTEM` });
        continue;
      }
      if (!adminOrSystem(owner)) {
        checks.push({ id: "install-owner", level: "fail", detail: `${label} owner ${owner} is not Administrators or SYSTEM` });
      } else {
        checks.push({ id: "install-owner", level: "ok", detail: `${label} owner ${owner}` });
      }
    }
  }
  if (input.markerPresent === false) {
    checks.push({ id: "install-marker", level: "fail", detail: "install.json is missing" });
  } else if (input.markerPresent === true) {
    checks.push({ id: "install-marker", level: "ok", detail: "install.json is present" });
  }
  if (input.installSource === "tarballs") {
    checks.push({
      id: "install-source",
      level: "fail",
      detail: "code was not installed from the registry (release testing only)",
    });
  }
  checks.push({
    id: "install-autostart",
    level: input.autostart ? "ok" : "fail",
    detail: input.autostart ? "autostart entry exists" : "autostart entry is missing",
  });
  return checks;
}

export function directoryAccess(dir: string): "ok" | "missing" | "unreadable" {
  try {
    accessSync(dir, constants.R_OK);
    return "ok";
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return "missing";
    return "unreadable";
  }
}

export function defaultElevated(platform: NodeJS.Platform = process.platform): boolean {
  if (platform === "win32") {
    const session = spawnSync(requireSystemTool("net", "win32"), ["session"], {
      stdio: "ignore",
      windowsHide: true,
      shell: false,
      env: systemToolEnv("win32"),
    });
    if (session.status === 0) return true;
    const groups = spawnSystemTool("whoami", ["/groups"], "win32");
    return `${groups.stdout ?? ""}`.includes("S-1-16-12288");
  }
  return typeof process.getuid === "function" && process.getuid() === 0;
}

function defaultExec(argv: string[]): ExecResult {
  const head = argv[0] ?? "";
  const name = systemToolName(head);
  if (!SYSTEM_TOOL_NAMES.has(name)) {
    const ran = spawnSync(head, argv.slice(1), { encoding: "utf8", windowsHide: true, shell: false });
    return { status: ran.status, stdout: ran.stdout ?? "", stderr: ran.stderr ?? "" };
  }
  let file: string;
  try {
    file = requireSystemTool(name);
  } catch (err) {
    const message = err instanceof Error ? err.message : "system tool missing";
    return { status: EX_CONFIG, stderr: `${message}\n` };
  }
  const ran = spawnSync(file, argv.slice(1), {
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    env: systemToolEnv(),
  });
  return { status: ran.status, stdout: ran.stdout ?? "", stderr: ran.stderr ?? "" };
}

function packageRootFrom(start: string, name: string): string | null {
  let dir = start;
  for (let i = 0; i < 8; i += 1) {
    const pkg = path.join(dir, "package.json");
    if (existsSync(pkg)) {
      try {
        const parsed = JSON.parse(readFileSync(pkg, "utf8")) as { name?: string };
        if (parsed.name === name) return dir;
      } catch {
        // keep walking
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function runningBodyVersion(): string | null {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = packageRootFrom(here, "@verax-ai/body") ?? path.join(here, "..");
  try {
    const parsed = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { version?: string };
    const version = parsed.version?.trim() ?? "";
    return version === "" ? null : version;
  } catch {
    return null;
  }
}

export function discoverLayout(
  execPath = process.execPath,
  platform: NodeJS.Platform = process.platform,
): { execPath: string; bodyVersion: string; npmCli: string } | { error: string } {
  const bodyVersion = runningBodyVersion();
  if (!bodyVersion) return { error: "verax install cannot read the running body version" };
  const plat: InstallPlatform = platform === "win32" ? "win32" : "linux";
  return { execPath, bodyVersion, npmCli: npmCliPath(execPath, plat) };
}

function parseFlag(argv: readonly string[], name: string): { value?: string; error?: string; force: boolean; keepState: boolean; rest: string[] } {
  let force = false;
  let keepState = false;
  let value: string | undefined;
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (a === "--force") {
      force = true;
      continue;
    }
    if (a === "--keep-state") {
      keepState = true;
      continue;
    }
    if (a === name) {
      const raw = argv[i + 1] ?? "";
      i += 1;
      if (raw === "" || raw.startsWith("-")) return { error: `${name} needs a value`, force, keepState, rest };
      value = raw;
      continue;
    }
    if (a.startsWith("-")) return { error: `flag-unknown:${a}`, force, keepState, rest };
    rest.push(a);
  }
  return { value, force, keepState, rest };
}

function parseInstallArgs(
  argv: readonly string[],
): { port: number; days: number; force: boolean; fromTarballs?: string } | { error: string } {
  const body = argv[0] === "install" ? argv.slice(1) : argv;
  let port = DEFAULT_PORT;
  let days = DEFAULT_DAYS;
  let force = false;
  let fromTarballs: string | undefined;
  for (let i = 0; i < body.length; i += 1) {
    const a = body[i]!;
    if (a === "--force") {
      force = true;
      continue;
    }
    if (a === "--from-tarballs") {
      const raw = body[i + 1] ?? "";
      i += 1;
      if (raw === "" || raw.startsWith("-")) return { error: "--from-tarballs needs a directory" };
      fromTarballs = raw;
      continue;
    }
    if (a === "--port" || a === "--days") {
      const raw = body[i + 1] ?? "";
      i += 1;
      if (!/^[0-9]+$/.test(raw)) {
        return { error: a === "--port" ? "--port wants an integer from 1024 to 65535" : "--days wants an integer from 1 to 90" };
      }
      if (a === "--port") port = Number(raw);
      else days = Number(raw);
      continue;
    }
    return { error: `flag-unknown:${a}` };
  }
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    return { error: "--port wants an integer from 1024 to 65535" };
  }
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    return { error: "--days wants an integer from 1 to 90" };
  }
  return { port, days, force, ...(fromTarballs ? { fromTarballs } : {}) };
}

function hashFile(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function writeManifest(dir: string): void {
  const files: string[] = [];
  const walk = (current: string): void => {
    for (const name of readdirSync(current)) {
      const full = path.join(current, name);
      if (name === "MANIFEST.sha256" && current === dir) continue;
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) files.push(path.relative(dir, full).split(path.sep).join("/"));
    }
  };
  walk(dir);
  files.sort();
  const lines = files.map((rel) => `${hashFile(path.join(dir, ...rel.split("/")))}  ${rel}`);
  writeFileSync(path.join(dir, "MANIFEST.sha256"), `${lines.join("\n")}\n`);
}

function healthOnce(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = get({ host: "127.0.0.1", port, path: "/healthz", timeout: 1_000 }, (res) => {
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

async function waitHealth(port: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await healthOnce(port)) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function execute(plan: Extract<InstallPlan, { ok: true }>, exec: (argv: string[]) => ExecResult, io: InstallIo): Promise<number> {
  for (const step of plan.ops) {
    if (step.op === "mkdir") {
      mkdirSync(step.path, { recursive: true, mode: step.mode ?? 0o755 });
      if (step.mode !== undefined && process.platform !== "win32") {
        try {
          chmodSync(step.path, step.mode);
        } catch {
          // Windows does not honour the mode bit.
        }
      }
      continue;
    }
    if (step.op === "manifest") {
      writeManifest(step.dir);
      continue;
    }
    if (step.op === "argv") {
      if (systemToolName(step.argv[0] ?? "") === "useradd") {
        const id = exec(toolArgv("id", [step.argv[step.argv.length - 1] ?? "verax"], "linux"));
        if ((id.status ?? 1) === EX_CONFIG && !step.optional) {
          io.stderr.write(`${(id.stderr || id.stdout || "").trim()}\n`);
          return EX_CONFIG;
        }
        if (id.status === 0) continue;
      }
      const ran = exec(step.argv);
      if (ran.status === EX_CONFIG && !step.optional) {
        io.stderr.write(`${(ran.stderr || ran.stdout || "").trim()}\n`);
        return EX_CONFIG;
      }
      if ((ran.status ?? 1) !== 0 && !step.optional) {
        if (step.rollbackDir) rmSync(step.rollbackDir, { recursive: true, force: true });
        const detail = (ran.stderr || ran.stdout || "").trim();
        const what = step.argv.includes("signatures")
          ? "npm audit signatures"
          : step.argv.includes("--omit=dev")
            ? "npm install"
            : (step.argv[0] ?? "command");
        io.stderr.write(`${what} failed${detail ? `: ${detail.split("\n")[0]}` : ""}\n`);
        return 1;
      }
      continue;
    }
    if (step.op === "write") {
      mkdirSync(path.dirname(step.path), { recursive: true });
      writeFileSync(step.path, step.contents, { encoding: "utf8", mode: step.mode ?? 0o644 });
      continue;
    }
    if (step.op === "init") {
      const code = await runInitLocal(
        [
          "--local",
          step.stateDir,
          "--days",
          String(step.days),
          "--port",
          String(step.port),
          ...(step.force ? ["--force"] : []),
        ],
        io,
        { tokenPath: step.tokenPath },
      );
      if (code !== 0) return code;
      continue;
    }
    if (step.op === "remove") {
      rmSync(step.path, { recursive: true, force: true });
      continue;
    }
    if (step.op === "wait-healthz") {
      if (!(await waitHealth(step.port, step.timeoutMs))) {
        io.stderr.write(`install-health-timeout:${step.port}\n`);
        return 1;
      }
      continue;
    }
    io.stdout.write(step.text.endsWith("\n") ? step.text : `${step.text}\n`);
  }
  return 0;
}

function invokingEnv(platform: NodeJS.Platform, env: NodeJS.ProcessEnv, exec: (argv: string[]) => ExecResult): NodeJS.ProcessEnv {
  if (platform !== "linux") return env;
  if (env.VERAX_INVOKING_HOME?.trim() || !env.SUDO_USER?.trim()) return env;
  const looked = exec(toolArgv("getent", ["passwd", env.SUDO_USER.trim()], "linux"));
  const home = (looked.stdout ?? "").split(":")[5]?.trim() ?? "";
  if (looked.status === 0 && home !== "") return { ...env, VERAX_INVOKING_HOME: home };
  return env;
}

function installMarkerText(opts: PlanOpts, paths: Paths): string {
  return `${JSON.stringify(
    {
      version: opts.bodyVersion,
      codeDir: paths.codeDir,
      stateDir: paths.stateDir,
      installedAt: new Date().toISOString(),
      source: opts.fromTarballs ? "tarballs" : "registry",
    },
    null,
    2,
  )}\n`;
}

function ourMarker(file: string): boolean {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { version?: unknown; codeDir?: unknown };
    return typeof parsed.version === "string" && typeof parsed.codeDir === "string";
  } catch {
    return false;
  }
}

function pathIsReparse(file: string, exec: (argv: string[]) => ExecResult, platform: NodeJS.Platform): boolean {
  let linked = false;
  try {
    linked = lstatSync(file).isSymbolicLink();
  } catch {
    return false;
  }
  if (linked) return true;
  if (platform !== "win32") return false;
  return exec(toolArgv("fsutil", ["reparsepoint", "query", file], "win32")).status === 0;
}

function linuxFact(dir: string, exec: (argv: string[]) => ExecResult): { exists: boolean; symlink: boolean; owner: string } {
  try {
    lstatSync(dir);
  } catch {
    return { exists: false, symlink: false, owner: "" };
  }
  const owner = exec(toolArgv("stat", ["-c", "%U", dir], "linux"));
  let symlink = false;
  try {
    symlink = lstatSync(dir).isSymbolicLink();
  } catch {
    symlink = false;
  }
  return { exists: true, symlink, owner: (owner.stdout ?? "").trim() };
}

function linuxFileUntrusted(file: string): boolean {
  try {
    const listed = lstatSync(file);
    if (listed.uid !== 0 || (listed.mode & 0o022) !== 0) return true;
    if (listed.isSymbolicLink()) {
      const followed = statSync(file);
      if (followed.uid !== 0 || (followed.mode & 0o022) !== 0) return true;
    }
    return false;
  } catch {
    return true;
  }
}

/** Owner + Administrators + SYSTEM. Throws when whoami or icacls fails. */
export function restrictToOwnerWin32(target: string, spawn: ToolSpawn = defaultToolSpawn): void {
  const whoami = requireSystemTool("whoami", "win32");
  const icacls = requireSystemTool("icacls", "win32");
  const opts = { encoding: "utf8" as const, windowsHide: true as const, shell: false as const, env: systemToolEnv("win32") };
  const who = spawn(whoami, ["/user", "/fo", "csv", "/nh"], opts);
  if ((who.status ?? 1) !== 0) {
    throw new Error(`whoami failed: ${(who.stderr || who.stdout || "").trim()}`);
  }
  const sid = /S-1-[0-9-]+/.exec(who.stdout ?? "")?.[0];
  if (!sid) throw new Error("whoami did not return a SID");
  const ran = spawn(icacls, [target, "/inheritance:r", "/grant:r", `*${sid}:F`, `${ADMINISTRATORS_SID}:F`, `${SYSTEM_SID}:F`], opts);
  if ((ran.status ?? 1) !== 0) {
    throw new Error(`icacls failed: ${(ran.stderr || ran.stdout || "icacls failed").trim()}`);
  }
}

function tarballTrustMessage(target: string): string {
  return `${target} can be changed by a non-administrator; --from-tarballs refuses it`;
}

export function orderTarballs(files: readonly string[]): string[] {
  const rank = (file: string): number => {
    const base = path.basename(file);
    if (base.includes("inventory")) return 0;
    if (base.includes("proxy")) return 1;
    if (base.includes("body")) return 2;
    return 9;
  };
  return [...files].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

function invokingSid(exec: (argv: string[]) => ExecResult): string | undefined {
  const ran = exec(toolArgv("whoami", ["/user"], "win32"));
  return `${ran.stdout ?? ""}`.match(/S-1-[0-9-]+/)?.[0];
}

function markerSource(file: string): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { source?: unknown };
    return typeof parsed.source === "string" ? parsed.source : undefined;
  } catch {
    return undefined;
  }
}

function collectTarballs(
  dirArg: string,
  platform: NodeJS.Platform,
  exec: (argv: string[]) => ExecResult,
  io: InstallIo,
): { dir: string; files: string[]; icacls?: string; modes?: { uid: number; mode: number }[] } | { error: true; code: number } {
  const dir = path.resolve(dirArg);
  let names: string[];
  try {
    names = readdirSync(dir).filter((name) => name.endsWith(".tgz"));
  } catch {
    io.stderr.write(`--from-tarballs ${dir} is not a directory\n`);
    return { error: true, code: EX_CONFIG };
  }
  const files = orderTarballs(names.map((name) => path.join(dir, name)));
  if (files.length === 0) {
    io.stderr.write(`--from-tarballs ${dir} has no tarballs\n`);
    return { error: true, code: EX_CONFIG };
  }
  const targets = [dir, ...files];
  if (platform === "win32") {
    const sid = invokingSid(exec);
    const chunks: string[] = [];
    for (const file of targets) {
      const acl = exec(toolArgv("icacls", [file], "win32"));
      const text = `${acl.stdout ?? ""}\n${acl.stderr ?? ""}`;
      chunks.push(text);
      if ((acl.status ?? 1) !== 0 || windowsUserCanWrite(text, { path: file, userSid: sid })) {
        io.stderr.write(`${tarballTrustMessage(file)}\n`);
        return { error: true, code: EX_CONFIG };
      }
    }
    return { dir, files, icacls: chunks.join("\n") };
  }
  if (platform === "linux") {
    const modes: { uid: number; mode: number }[] = [];
    for (const file of targets) {
      if (linuxFileUntrusted(file)) {
        io.stderr.write(`${tarballTrustMessage(file)}\n`);
        return { error: true, code: EX_CONFIG };
      }
      const st = statSync(file);
      modes.push({ uid: st.uid, mode: st.mode });
    }
    return { dir, files, modes };
  }
  io.stderr.write("--from-tarballs is not supported on this operating system\n");
  return { error: true, code: EX_CONFIG };
}

export async function runInstall(argv: readonly string[], hooks: InstallHooks = {}): Promise<number> {
  const platform = hooks.platform ?? process.platform;
  const env = hooks.env ?? process.env;
  const io = hooks.io ?? { stdout: process.stdout, stderr: process.stderr };
  const elevated = hooks.elevated ?? (() => defaultElevated(platform));
  let isElevated = false;
  try {
    isElevated = elevated();
  } catch (err) {
    if (err instanceof SystemToolError) {
      io.stderr.write(`${err.message}\n`);
      return EX_CONFIG;
    }
    throw err;
  }
  if (!isElevated) {
    io.stderr.write(`${ELEVATION_LINE}\n`);
    return EX_ELEVATION;
  }
  const parsed = parseInstallArgs(argv);
  if ("error" in parsed) {
    io.stderr.write(`${parsed.error}\n`);
    return EX_CONFIG;
  }
  const exec = hooks.exec ?? defaultExec;
  const plannedEnv = invokingEnv(platform, env, exec);
  const discovered = hooks.layout ?? discoverLayout(process.execPath, platform);
  if ("error" in discovered) {
    io.stderr.write(`${discovered.error}\n`);
    return EX_CONFIG;
  }
  const layout = discovered;
  if (platform === "win32" || platform === "linux") {
    const files = [...ancestry(layout.execPath, platform), ...ancestry(layout.npmCli, platform)];
    if (platform === "win32") {
      const sid = invokingSid(exec);
      for (const file of files) {
        const acl = exec(toolArgv("icacls", [file], "win32"));
        const text = `${acl.stdout ?? ""}\n${acl.stderr ?? ""}`;
        if ((acl.status ?? 1) !== 0 || windowsUserCanWrite(text, { path: file, userSid: sid })) {
          io.stderr.write(`${nodeTrustMessage(file)}\n`);
          return EX_CONFIG;
        }
      }
    } else {
      for (const file of files) {
        if (linuxFileUntrusted(file)) {
          io.stderr.write(`${nodeTrustMessage(file)}\n`);
          return EX_CONFIG;
        }
      }
    }
  }
  const stateDir = stateDirFor(platform, plannedEnv);
  const exists = hooks.stateExists ? hooks.stateExists(stateDir) : existsSync(stateDir);
  let veraxRootExists = false;
  let markerExists = false;
  let reparsePath: string | undefined;
  let linuxState: PlanOpts["linuxState"];
  let linuxCode: PlanOpts["linuxCode"];
  if (platform === "win32") {
    const root = path.win32.dirname(stateDir);
    const marker = path.win32.join(root, "install.json");
    markerExists = ourMarker(marker);
    try {
      lstatSync(root);
      veraxRootExists = true;
    } catch {
      veraxRootExists = false;
    }
    if (pathIsReparse(root, exec, platform)) reparsePath = root;
    else if (pathIsReparse(stateDir, exec, platform)) reparsePath = stateDir;
  } else if (platform === "linux") {
    const codeDir = codeDirFor(platform, plannedEnv);
    linuxState = linuxFact(stateDir, exec);
    linuxCode = linuxFact(codeDir, exec);
  }
  const packed = parsed.fromTarballs ? collectTarballs(parsed.fromTarballs, platform, exec, io) : undefined;
  if (packed && "error" in packed) return packed.code;
  const plan = planInstall(platform as InstallPlatform, plannedEnv, {
    ...layout,
    port: parsed.port,
    days: parsed.days,
    force: parsed.force,
    stateExists: exists,
    veraxRootExists,
    markerExists,
    reparsePath,
    linuxState,
    linuxCode,
    ...(packed && !("error" in packed)
      ? { fromTarballs: packed.dir, tarballFiles: packed.files, tarballIcacls: packed.icacls, tarballModes: packed.modes }
      : {}),
  });
  if (!plan.ok) {
    io.stderr.write(plan.message);
    return plan.code;
  }
  return execute(plan, exec, io);
}

export async function runUninstall(argv: readonly string[], hooks: InstallHooks = {}): Promise<number> {
  const platform = hooks.platform ?? process.platform;
  const env = hooks.env ?? process.env;
  const io = hooks.io ?? { stdout: process.stdout, stderr: process.stderr };
  const elevated = hooks.elevated ?? (() => defaultElevated(platform));
  let isElevated = false;
  try {
    isElevated = elevated();
  } catch (err) {
    if (err instanceof SystemToolError) {
      io.stderr.write(`${err.message}\n`);
      return EX_CONFIG;
    }
    throw err;
  }
  if (!isElevated) {
    io.stderr.write("verax uninstall needs an elevated shell (Administrator / root)\n");
    return EX_ELEVATION;
  }
  const body = argv[0] === "uninstall" ? argv.slice(1) : argv;
  const parsed = parseFlag(body, "--unused");
  if (parsed.error) {
    io.stderr.write(`${parsed.error}\n`);
    return EX_CONFIG;
  }
  if (parsed.rest.length > 0) {
    io.stderr.write("verax uninstall [--keep-state]\n");
    return EX_CONFIG;
  }
  const exec = hooks.exec ?? defaultExec;
  const plan = planUninstall(platform as InstallPlatform, invokingEnv(platform, env, exec), { keepState: parsed.keepState });
  if (!plan.ok) {
    io.stderr.write(plan.message);
    return plan.code;
  }
  return execute(plan, exec, io);
}

function hashUnder(dir: string, rel: string): string | null {
  const full = path.join(dir, ...rel.split("/"));
  try {
    return hashFile(full);
  } catch {
    return null;
  }
}

export function liveInstalledChecks(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  exec: (argv: string[]) => ExecResult = defaultExec,
): BoundaryCheck[] {
  const codeDir = codeDirFor(platform, env);
  const stateDir = stateDirFor(platform, env);
  if (!existsSync(codeDir)) return [];
  let manifest: string | null = null;
  try {
    manifest = readFileSync(path.join(codeDir, "MANIFEST.sha256"), "utf8");
  } catch {
    manifest = null;
  }
  if (platform === "win32") {
    const acl = exec(toolArgv("icacls", [stateDir], "win32"));
    const task = exec(toolArgv("schtasks", ["/Query", "/TN", TASK_NAME], "win32"));
    const ownerOf = (dir: string): string => {
      const literal = dir.replaceAll("'", "''");
      const ran = exec(toolArgv("powershell", ["-NoProfile", "-Command", `(Get-Acl -LiteralPath '${literal}').Owner`], "win32"));
      return (ran.stdout ?? "").trim();
    };
    const marker = path.win32.join(path.win32.dirname(stateDir), "install.json");
    return installedBoundaryChecks({
      codeDir,
      stateDir,
      manifest,
      hashOf: (rel) => hashUnder(codeDir, rel),
      aclText: `${acl.stdout ?? ""}\n${acl.stderr ?? ""}`,
      winOwners: { state: ownerOf(stateDir), code: ownerOf(codeDir) },
      markerPresent: ourMarker(marker),
      installSource: markerSource(marker),
      autostart: task.status === 0,
    });
  }
  let mode: number | undefined;
  try {
    mode = statSync(stateDir).mode;
  } catch {
    mode = undefined;
  }
  const owner = exec(toolArgv("stat", ["-c", "%U", stateDir], "linux"));
  const enabled = exec(toolArgv("systemctl", ["is-enabled", "verax"], "linux"));
  return installedBoundaryChecks({
    codeDir,
    stateDir,
    manifest,
    hashOf: (rel) => hashUnder(codeDir, rel),
    mode,
    owner: (owner.stdout ?? "").trim() || undefined,
    installSource: markerSource(path.posix.join(codeDir, "install.json")),
    autostart: enabled.status === 0 || existsSync("/etc/systemd/system/verax.service"),
  });
}

export function doctorStateTarget(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): string | null {
  const named = env.VERAX_STATE_DIR?.trim() ?? "";
  if (named !== "") return named;
  const installed = stateDirFor(platform, env);
  return directoryAccess(installed) === "missing" ? null : installed;
}
