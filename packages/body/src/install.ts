import { spawnSync, type SpawnSyncReturns, type StdioOptions } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  accessSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
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
const HEALTH_WAIT_MS = 60_000;

const VERAX_SVC = "verax-svc";
const ADMINISTRATORS_SID = "*S-1-5-32-544";
const SYSTEM_SID = "*S-1-5-18";
/** Folder owners an unelevated agent cannot become or replace. */
const TRUSTED_FOLDER_OWNER_SIDS = new Set(["S-1-5-32-544", "S-1-5-18"]);
const TASK_NAME = "Verax Body";
const DARWIN_USER = "_verax";
const DARWIN_LABEL = "com.verax-ai.body";
const DARWIN_ROOT = "/Library/Verax";
const DARWIN_CODE = "/Library/Verax/code";
const DARWIN_STATE_PARENT = "/Library/Application Support/Verax";
const DARWIN_STATE = "/Library/Application Support/Verax/state";
const DARWIN_MARKER = "/Library/Verax/install.json";
const DARWIN_PLIST = "/Library/LaunchDaemons/com.verax-ai.body.plist";

const WIN32_TOOLS = ["whoami", "icacls", "schtasks", "net", "fsutil", "powershell"] as const;
const LINUX_TOOLS = ["useradd", "userdel", "groupdel", "chown", "chmod", "id", "getent", "stat", "systemctl", "journalctl", "getenforce", "ps", "ausearch"] as const;
const DARWIN_TOOLS = ["dscl", "launchctl", "chown", "chmod", "id", "stat", "plutil"] as const;
const LINUX_TOOL_DIRS = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] as const;
/** Fixed paths. A plan must name these even when the binary is absent on the machine that built the plan. */
const DARWIN_TOOL_PATHS: Record<(typeof DARWIN_TOOLS)[number], string> = {
  dscl: "/usr/bin/dscl",
  launchctl: "/bin/launchctl",
  chown: "/usr/sbin/chown",
  chmod: "/bin/chmod",
  id: "/usr/bin/id",
  stat: "/usr/bin/stat",
  plutil: "/usr/bin/plutil",
};
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
 * Linux walks fixed directories and never consults PATH.
 * macOS uses the fixed table (dscl, launchctl, chown, chmod, id, stat, plutil).
 * A missing Linux binary falls back to the first candidate so a plan can name
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
  if (platform === "darwin") {
    const fixed = DARWIN_TOOL_PATHS[name as (typeof DARWIN_TOOLS)[number]];
    if (!fixed) throw new SystemToolError(`refusing: ${name} is not a macOS install tool`);
    return fixed;
  }
  for (const dir of LINUX_TOOL_DIRS) {
    const candidate = `${dir}/${name}`;
    if (existsSync(candidate)) return candidate;
  }
  return `${LINUX_TOOL_DIRS[0]}/${name}`;
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

/** Windows default. Without `.EXE`, PowerShell treats a native binary as a document and a pipeline exits 0. */
const WIN32_PATHEXT = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";

/** Stderr lines from a generated PowerShell script. A line with this prefix is a failed step even when the process exits 0. */
export const PS_ERROR_MARK = "verax-ps-error:";

/**
 * Env for system-tool spawns. The caller's PATH is not copied.
 * TEMP/TMP are set only to `tempDir`. The caller's TEMP is a user-writable
 * AppData directory and must not receive install files.
 */
export function systemToolEnv(platform: NodeJS.Platform = process.platform, tempDir?: string): NodeJS.ProcessEnv {
  if (platform === "win32") {
    const root = process.env.SystemRoot?.trim() || "C:\\Windows";
    const drive = path.win32.parse(root).root.replace(/[\\/]+$/, "") || "C:";
    const env: NodeJS.ProcessEnv = {
      SystemRoot: process.env.SystemRoot ?? root,
      windir: process.env.windir ?? root,
      PATHEXT: WIN32_PATHEXT,
      ComSpec: path.win32.join(root, "System32", "cmd.exe"),
      SystemDrive: drive,
    };
    if (tempDir) {
      env.TEMP = tempDir;
      env.TMP = tempDir;
    }
    return env;
  }
  const env: NodeJS.ProcessEnv = { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" };
  if (tempDir) env.TMPDIR = tempDir;
  return env;
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

/** Allow-list. A write ACE for any other SID is a non-admin writer. */
const SID_ADMINISTRATORS = "S-1-5-32-544";
const SID_SYSTEM = "S-1-5-18";
const SID_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const TRUSTED_WRITER_SIDS = new Set([SID_ADMINISTRATORS, SID_SYSTEM, SID_TRUSTED_INSTALLER]);

/**
 * SDDL SID strings from the Windows "SID strings" table.
 * A fixed well-known SID is mapped to that SID. A domain-relative alias
 * (DA, DU, …) maps to a marker that is not a trusted writer.
 * An alias absent from this table is not a parse failure: the ACE keeps the
 * raw token as an untrusted SID and the rights decide.
 */
const SDDL_SID: Record<string, string> = {
  AA: "S-1-5-32-579",
  AC: "S-1-15-2-1",
  AN: "S-1-5-7",
  AO: "S-1-5-32-548",
  AP: "untrusted:AP",
  AS: "S-1-18-1",
  AU: "S-1-5-11",
  BA: SID_ADMINISTRATORS,
  BG: "S-1-5-32-546",
  BO: "S-1-5-32-551",
  BU: "S-1-5-32-545",
  CA: "untrusted:CA",
  CD: "S-1-5-32-574",
  CG: "S-1-3-1",
  CN: "untrusted:CN",
  CO: "S-1-3-0",
  CY: "S-1-5-32-569",
  DA: "untrusted:DA",
  DC: "untrusted:DC",
  DD: "untrusted:DD",
  DG: "untrusted:DG",
  DU: "untrusted:DU",
  EA: "untrusted:EA",
  ED: "S-1-5-9",
  EK: "untrusted:EK",
  ER: "S-1-5-32-573",
  ES: "S-1-5-32-576",
  HA: "S-1-5-32-578",
  HI: "S-1-16-12288",
  IS: "S-1-5-32-568",
  IU: "S-1-5-4",
  KA: "untrusted:KA",
  LA: "untrusted:LA",
  LG: "untrusted:LG",
  LS: "S-1-5-19",
  LU: "S-1-5-32-559",
  LW: "S-1-16-4096",
  ME: "S-1-16-8192",
  MP: "S-1-16-8448",
  MS: "S-1-5-32-577",
  MU: "S-1-5-32-558",
  NO: "S-1-5-32-556",
  NS: "S-1-5-20",
  NU: "S-1-5-2",
  OW: "S-1-3-4",
  PA: "untrusted:PA",
  PO: "S-1-5-32-550",
  PS: "S-1-5-10",
  PU: "S-1-5-32-547",
  RA: "S-1-5-32-575",
  RC: "S-1-5-12",
  RD: "S-1-5-32-555",
  RE: "S-1-5-32-552",
  RM: "untrusted:RM",
  RO: "untrusted:RO",
  RS: "S-1-5-32-553",
  RU: "S-1-5-32-554",
  SA: "untrusted:SA",
  SI: "S-1-16-16384",
  SO: "S-1-5-32-549",
  SS: "S-1-18-2",
  SU: "S-1-5-6",
  SY: SID_SYSTEM,
  UD: "S-1-5-84-0-0-0-0-0",
  WD: "S-1-1-0",
  WR: "S-1-5-33",
};

/** Object write/modify. Ancestor checks use a narrower set. FA and FW expand into these bits. */
const OBJECT_WRITE_MASK = 0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
/** Replace or re-point a child. Add-file (0x2) and add-subdirectory (0x4) on an ancestor do not. FA includes these bits; the full FA mask is not ORed in. */
const ANCESTOR_REPLACE_MASK = 0x0040 | 0x10000 | 0x40000 | 0x80000 | 0x10000000;

/** SDDL access rights, two letters each. Not the icacls abbreviation list. */
const SDDL_RIGHTS: Record<string, number> = {
  GA: 0x10000000,
  GR: 0x80000000,
  GW: 0x40000000,
  GX: 0x20000000,
  RC: 0x20000,
  SD: 0x10000,
  WD: 0x40000,
  WO: 0x80000,
  RP: 0x10,
  WP: 0x20,
  CC: 0x1,
  DC: 0x2,
  LC: 0x4,
  SW: 0x8,
  LO: 0x80,
  DT: 0x40,
  CR: 0x100,
  FA: 0x1f01ff,
  FR: 0x120089,
  FW: 0x120116,
  FX: 0x1200a0,
};
/** File ACEs ignore key rights. They are not unknown. */
const SDDL_RIGHTS_IGNORED = new Set(["KA", "KR", "KW", "KX"]);

/**
 * One place on both systems. Intel Homebrew gives `/usr/local` to the user, so a Node under it can be
 * swapped; `/opt` is root-owned on both Mac architectures (Apple Silicon Homebrew owns `/opt/homebrew`).
 * On SELinux hosts `/opt` is labelled `usr_t`, which systemd may start, while `/usr/local/lib` is `lib_t`.
 */
function officialNodeRoot(_platform: "linux" | "darwin"): string {
  return "/opt/verax-node";
}

function officialNodeRemedy(platform: "linux" | "darwin"): string {
  const ver = process.versions.node;
  const arch = process.arch;
  const os = platform === "darwin" ? "darwin" : "linux";
  const name = `node-v${ver}-${os}-${arch}.tar.gz`;
  const base = `https://nodejs.org/dist/v${ver}`;
  const dest = officialNodeRoot(platform);
  const owner = platform === "darwin" ? "root:wheel" : "root:root";
  const check =
    platform === "darwin"
      ? `grep ' ${name}$' SHASUMS256.txt | shasum -a 256 -c -`
      : `grep ' ${name}$' SHASUMS256.txt | sha256sum -c -`;
  const node = `${dest}/node-v${ver}-${os}-${arch}/bin/node`;
  return [
    `curl -fsSL -o ${name} ${base}/${name}`,
    `curl -fsSL -o SHASUMS256.txt ${base}/SHASUMS256.txt`,
    check,
    `sudo mkdir -p ${dest}`,
    `sudo tar -C ${dest} -xzf ${name}`,
    `sudo chown -R ${owner} ${dest}`,
    `sudo chmod -R go-w ${dest}`,
    `sudo ${node} $(which verax) install`,
  ].join("\n");
}

export function nodeTrustMessage(nodePath: string): string {
  return `Node at ${nodePath} can be changed by your user account; install Node for all users (nodejs.org installer) and run verax install from that Node`;
}

function nodeTrustMessageFor(nodePath: string, platform: InstallPlatform): string {
  const head = `Node at ${nodePath} can be changed by your user account`;
  if (platform === "win32") return nodeTrustMessage(nodePath);
  const owner = platform === "darwin" ? "root:wheel" : "root:root";
  const dest = officialNodeRoot(platform);
  return `${head}. An elevated install must not run a Node your account can swap. Download the official tarball and SHASUMS256.txt, check the sha256, and extract as root into ${dest} (${owner}, go-w), then run verax install from that Node:\n${officialNodeRemedy(platform)}`;
}

export type InstallPlatform = "win32" | "linux" | "darwin";

export type PlanOpts = {
  port?: number;
  days?: number;
  force?: boolean;
  /**
   * Test-only. Prefixes the fixed POSIX install roots. Not read from CLI argv.
   * Win32 ignores it.
   */
  posixRoot?: string;
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
  /** sha256 of each tarball at trust-check time. npm installs the private-temp copies. */
  tarballDigests?: { file: string; sha256: string }[];
  linuxState?: { exists: boolean; symlink: boolean; owner: string };
  linuxCode?: { exists: boolean; symlink: boolean; owner: string };
  /** Windows `verax-svc`. Absent means the account is not there yet. */
  winAccount?: { exists: boolean; createdByUs: boolean };
  /** Linux login `verax`. Absent means the account is not there yet. `createdGroup` is the marker's claim that this install's useradd made the group. */
  linuxAccount?: { exists: boolean; createdByUs: boolean; createdGroup?: boolean };
  /** Owner name of an existing `%ProgramData%\\Verax`. */
  winRootOwner?: string;
  /** icacls text of an existing `%ProgramData%\\Verax`. */
  winRootAcl?: string;
  /** `ProfileImagePath` for the invoking SID. A different `USERPROFILE` is refused. */
  profileImagePath?: string;
  /** Home from `getent` or `dscl`. `VERAX_INVOKING_HOME` must match it. */
  invokingHome?: string;
  /** macOS `_verax` uid/gid chosen from the free 200–400 range. */
  darwinAccount?: { uid: number; gid: number; createUser: boolean; createGroup: boolean; recordUser: boolean; recordGroup: boolean };
  darwinState?: { exists: boolean; symlink: boolean };
  /** `/Library/Verax` before this install. */
  darwinRoot?: { exists: boolean; symlink: boolean };
};

export type PlanOp =
  | { op: "manifest"; dir: string }
  | { op: "mkdir"; path: string; mode?: number }
  | { op: "argv"; argv: string[]; optional?: boolean; rollbackDir?: string; stdin?: string; env?: NodeJS.ProcessEnv; cwd?: string }
  | { op: "write"; path: string; contents: string; mode?: number; exclusive?: boolean }
  | { op: "lock-root"; path: string; create: boolean }
  | { op: "init"; stateDir: string; tokenPath: string; port: number; days: number; force: boolean; noOwnerGrant: boolean }
  | { op: "remove"; path: string }
  | { op: "wait-healthz"; port: number; timeoutMs: number }
  | { op: "print"; text: string }
  | { op: "stage-tarballs"; files: { source: string; sha256: string; dest: string }[] }
  | {
      op: "private-temp";
      path: string;
      /** Win32 DACL after inheritance is removed. POSIX omits this. */
      acl?: readonly string[];
      inheritance?: "removed";
      /** Win32 owner SID, starred for icacls (`*S-1-5-32-544`). */
      owner?: string;
      /** POSIX directory mode. Root creates it. */
      mode?: number;
    };

export type InstallPlan =
  | { ok: false; code: number; message: string }
  | { ok: true; ops: PlanOp[]; codeDir: string; stateDir: string; tokenPath: string };

export type ExecResult = { status: number | null; stdout?: string; stderr?: string };

export type ToolExec = (argv: string[], stdin?: string, env?: NodeJS.ProcessEnv, cwd?: string) => ExecResult;

export type InstallIo = {
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
};

export type InstallHooks = {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  elevated?: () => boolean;
  exec?: ToolExec;
  stateExists?: (dir: string) => boolean;
  layout?: { execPath: string; bodyVersion: string; npmCli: string };
  io?: InstallIo;
  /**
   * Test-only. Relocates `/opt/verax`, `/var/lib/verax`, `/etc/systemd/system`,
   * `/Library/Verax`, `/Library/Application Support/Verax`, and
   * `/Library/LaunchDaemons` under this directory. CLI argv cannot set it.
   */
  posixRoot?: string;
  /** Test-only. Replaces `copyFileSync` while staging `--from-tarballs` copies. */
  copyFile?: (source: string, dest: string) => void;
  /** Test-only. Caps the post-start /healthz wait. CLI argv cannot set it. */
  healthTimeoutMs?: number;
};

type Paths = { codeDir: string; stateDir: string; tokenPath: string };

function fail(code: number, message: string): InstallPlan {
  return { ok: false, code, message: message.endsWith("\n") ? message : `${message}\n` };
}

const POSIX_INSTALL_ROOTS = [
  "/Library/Application Support/Verax",
  "/Library/LaunchDaemons",
  "/etc/systemd/system",
  "/Library/Verax",
  "/var/lib/verax",
  "/opt/verax",
] as const;

/** Prefix a fixed POSIX install path. Longest root wins. Unset root returns `fixed`. */
export function relocatePosixPath(fixed: string, posixRoot?: string): string {
  const base = posixRoot?.trim().replace(/\/+$/, "") ?? "";
  if (base === "") return fixed;
  const hit = POSIX_INSTALL_ROOTS.find((root) => fixed === root || fixed.startsWith(`${root}/`));
  return hit ? `${base}${fixed}` : fixed;
}

function fixedPosix(posixRoot?: string) {
  const at = (fixed: string): string => relocatePosixPath(fixed, posixRoot);
  return {
    linuxCode: at("/opt/verax"),
    linuxState: at("/var/lib/verax"),
    systemdUnit: at("/etc/systemd/system/verax.service"),
    darwinRoot: at(DARWIN_ROOT),
    darwinCode: at(DARWIN_CODE),
    darwinStateParent: at(DARWIN_STATE_PARENT),
    darwinState: at(DARWIN_STATE),
    darwinMarker: at(DARWIN_MARKER),
    darwinPlist: at(DARWIN_PLIST),
  };
}

export function stateDirFor(
  platform: NodeJS.Platform | InstallPlatform,
  env: NodeJS.ProcessEnv = process.env,
  posixRoot?: string,
): string {
  if (platform === "win32") {
    const data = env.ProgramData || "C:\\ProgramData";
    return path.win32.join(data, "Verax", "state");
  }
  if (platform === "darwin") return fixedPosix(posixRoot).darwinState;
  return fixedPosix(posixRoot).linuxState;
}

export function codeDirFor(
  platform: NodeJS.Platform | InstallPlatform,
  env: NodeJS.ProcessEnv = process.env,
  posixRoot?: string,
): string {
  if (platform === "win32") {
    const files = env.ProgramFiles || "C:\\Program Files";
    return path.win32.join(files, "Verax");
  }
  if (platform === "darwin") return fixedPosix(posixRoot).darwinCode;
  return fixedPosix(posixRoot).linuxCode;
}

function linuxHome(env: NodeJS.ProcessEnv, resolved?: string): { home: string } | { error: string } {
  const user = env.SUDO_USER?.trim() ?? "";
  if (user === "") return { error: "verax install needs SUDO_USER to find the invoking user's home" };
  const passwd = resolved?.trim() || (user === "root" ? "/root" : `/home/${user}`);
  const given = env.VERAX_INVOKING_HOME?.trim() ?? "";
  if (given !== "" && given !== passwd) {
    return { error: `refusing: VERAX_INVOKING_HOME ${given} is not the home ${passwd}` };
  }
  return { home: passwd };
}

function darwinHome(env: NodeJS.ProcessEnv, resolved?: string): { home: string } | { error: string } {
  const user = env.SUDO_USER?.trim() ?? "";
  if (user === "") return { error: "verax install needs SUDO_USER to find the invoking user's home" };
  const given = env.VERAX_INVOKING_HOME?.trim() ?? "";
  const passwd = resolved?.trim() ?? "";
  if (passwd !== "") {
    if (given !== "" && given !== passwd) {
      return { error: `refusing: VERAX_INVOKING_HOME ${given} is not the home ${passwd}` };
    }
    return { home: passwd };
  }
  if (given !== "") return { home: given };
  if (user === "root") return { home: "/var/root" };
  return { error: "verax install needs the invoking user's home from dscl" };
}

function pathsFor(
  platform: InstallPlatform,
  env: NodeJS.ProcessEnv,
  posixRoot?: string,
  invokingHome?: string,
): { ok: true; paths: Paths; home: string } | { ok: false; code: number; message: string } {
  if (platform === "darwin") {
    const home = darwinHome(env, invokingHome);
    if ("error" in home) return { ok: false, code: EX_CONFIG, message: `${home.error}\n` };
    const fixed = fixedPosix(posixRoot);
    const paths = {
      codeDir: fixed.darwinCode,
      stateDir: fixed.darwinState,
      tokenPath: path.posix.join(home.home, ".verax", "agent.token"),
    };
    return { ok: true, paths, home: home.home };
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
  const home = linuxHome(env, invokingHome);
  if ("error" in home) return { ok: false, code: EX_CONFIG, message: `${home.error}\n` };
  const fixed = fixedPosix(posixRoot);
  const paths = {
    codeDir: fixed.linuxCode,
    stateDir: fixed.linuxState,
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

export type SddlAce = {
  /** `A` includes object and callback allows (`OA`, `XA`, `ZA`). `D` includes `OD` and `XD`. */
  type: "A" | "D";
  flags: Set<string>;
  rights: string;
  sid: string;
  inheritOnly: boolean;
};

/** `icacls` account names are language-specific. Security reads use this SDDL string. */
export function windowsSddlArgv(target: string): string[] {
  const literal = target.replaceAll("'", "''");
  return toolArgv("powershell", [
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    `(Get-Acl -LiteralPath '${literal}').Sddl`,
  ], "win32");
}

function uniquePaths(paths: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const file of paths) {
    if (seen.has(file)) continue;
    seen.add(file);
    out.push(file);
  }
  return out;
}

/**
 * One PowerShell process reads every path. The command carries a base64 UTF-8 JSON
 * array, never a raw path. Stdout is one JSON object: `{ "<path>": "<sddl>" | { "error": "<msg>" } }`.
 */
export function windowsSddlBatchArgv(paths: readonly string[]): string[] {
  const payload = Buffer.from(JSON.stringify(uniquePaths(paths)), "utf8").toString("base64");
  const script = `$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$raw = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${payload}'))
$paths = @($raw | ConvertFrom-Json | ForEach-Object { $_ })
$result = @{}
foreach ($p in $paths) {
  $key = [string]$p
  try {
    $acl = Get-Acl -LiteralPath $key
    $result[$key] = [string]$acl.Sddl
  } catch {
    $err = @{ error = [string]$_.Exception.Message }
    $result[$key] = $err
  }
}
$result | ConvertTo-Json -Compress -Depth 4`;
  return toolArgv("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], "win32");
}

type SddlHit = { status: number; text: string };

function sddlHit(value: unknown): SddlHit {
  if (typeof value === "string") return { status: 0, text: `${value}\n` };
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const error = (value as { error?: unknown }).error;
    if (typeof error === "string") return { status: 1, text: `${error}\n` };
  }
  return { status: 1, text: "" };
}

/** Null when stdout is not the batch object. A missing or failed path is fail-closed inside the map. */
function parseSddlBatch(stdout: string, paths: readonly string[]): Map<string, SddlHit> | null {
  const start = stdout.indexOf("{");
  const end = stdout.lastIndexOf("}");
  if (start < 0 || end < start) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(start, end + 1));
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  const map = new Map<string, SddlHit>();
  for (const file of paths) map.set(file, sddlHit(obj[file]));
  return map;
}

function sddlOrMiss(map: Map<string, SddlHit>, file: string): SddlHit {
  return map.get(file) ?? { status: 1, text: "" };
}

/** One process for every path. A failed process fails every path closed, with the tool text kept for the refusal. */
function readSddlBatch(exec: ToolExec, paths: readonly string[]): Map<string, SddlHit> {
  const wanted = uniquePaths(paths);
  const map = new Map<string, SddlHit>();
  if (wanted.length === 0) return map;
  const ran = exec(windowsSddlBatchArgv(wanted));
  const combined = `${ran.stdout ?? ""}\n${ran.stderr ?? ""}`;
  if ((ran.status ?? 1) !== 0) {
    for (const file of wanted) map.set(file, { status: 1, text: combined });
    return map;
  }
  const parsed = parseSddlBatch(ran.stdout ?? "", wanted);
  if (parsed === null) {
    for (const file of wanted) map.set(file, { status: 1, text: combined });
    return map;
  }
  return parsed;
}

export function canonicalSid(token: string): string | null {
  const raw = token.trim().replace(/^\*/, "");
  if (raw === "") return null;
  if (/^S-1-[0-9-]+$/i.test(raw)) return raw.toUpperCase();
  const alias = SDDL_SID[raw.toUpperCase()];
  return alias ?? null;
}

/** Owner SID from an SDDL `O:` field. Null when the text is not SDDL. */
export function sddlOwner(text: string): string | null {
  const match = /O:((?:S-1-[0-9-]+)|[A-Z]{2})/i.exec(text.replace(/\s+/g, ""));
  if (!match?.[1]) return null;
  return canonicalSid(match[1]);
}

function daclBody(text: string): string | null {
  const flat = text.replace(/\s+/g, "");
  const at = flat.search(/D:/i);
  if (at < 0) return null;
  const rest = flat.slice(at + 2);
  const stop = rest.search(/S:/i);
  return stop < 0 ? rest : rest.slice(0, stop);
}

/** Allow ACEs. A conditional expression is not evaluated; it may be true. */
const ALLOW_ACE_TYPES = new Set(["A", "OA", "XA", "ZA"]);
/** Deny ACEs. They grant nothing, so the writer check skips them. */
const DENY_ACE_TYPES = new Set(["D", "OD", "XD"]);
/** SACL ACE types. In a DACL they are not permissions and are ignored. */
const SACL_ACE_TYPES = new Set(["AU", "AL", "OU", "OL", "ML", "SP", "RA"]);

/** ACE bodies, including a conditional tail with nested parentheses. Null when a `(` is unclosed. */
function aceInners(body: string): string[] | null {
  const inners: string[] = [];
  let i = 0;
  while (i < body.length) {
    if (body[i] !== "(") {
      i += 1;
      continue;
    }
    let depth = 0;
    let closed = false;
    for (let j = i; j < body.length; j += 1) {
      const ch = body[j];
      if (ch === "(") depth += 1;
      else if (ch === ")") {
        depth -= 1;
        if (depth === 0) {
          inners.push(body.slice(i + 1, j));
          i = j + 1;
          closed = true;
          break;
        }
      }
    }
    if (!closed) return null;
  }
  return inners;
}

/** Split one ACE on `;` that sit outside parentheses, so a condition stays one field. */
function aceFields(inner: string): string[] {
  const fields: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i];
    if (ch === "(") depth += 1;
    else if (ch === ")" && depth > 0) depth -= 1;
    else if (ch === ";" && depth === 0) {
      fields.push(inner.slice(start, i));
      start = i + 1;
    }
  }
  fields.push(inner.slice(start));
  return fields;
}

function aceFromFields(type: "A" | "D", fields: string[]): SddlAce {
  const flags = new Set((fields[1] ?? "").toUpperCase().match(/[A-Z]{2}/g) ?? []);
  const rawSid = (fields[5] ?? "").trim().replace(/^\*/, "");
  const sid = canonicalSid(rawSid) ?? `untrusted:${rawSid.toUpperCase()}`;
  return {
    type,
    flags,
    rights: (fields[2] ?? "").toUpperCase(),
    sid,
    inheritOnly: flags.has("IO"),
  };
}

/**
 * Parsed DACL, or `null` when the text has no `D:` section.
 * `unknownType === ""` is a malformed ACE (unclosed `(`). A non-empty value names the type.
 */
function readDacl(text: string): { aces: SddlAce[]; unknownType: string | null } | null {
  const body = daclBody(text);
  if (body === null) return null;
  const inners = aceInners(body);
  if (inners === null) return { aces: [], unknownType: "" };
  const aces: SddlAce[] = [];
  for (const inner of inners) {
    const fields = aceFields(inner);
    const type = (fields[0] ?? "").toUpperCase();
    if (SACL_ACE_TYPES.has(type)) continue;
    if (DENY_ACE_TYPES.has(type)) {
      aces.push(aceFromFields("D", fields));
      continue;
    }
    if (ALLOW_ACE_TYPES.has(type)) {
      aces.push(aceFromFields("A", fields));
      continue;
    }
    return { aces: [], unknownType: type };
  }
  return { aces, unknownType: null };
}

/**
 * DACL ACEs. Inherit-only `(IO)` is flagged and does not apply to the object.
 * `OA` / `XA` / `ZA` are stored as allow; `OD` / `XD` as deny. SACL types are dropped.
 * Any other type fails closed (`null`); the refusal names it.
 */
export function parseSddlAces(text: string): SddlAce[] | null {
  const read = readDacl(text);
  if (read === null || read.unknownType !== null) return null;
  return read.aces;
}

/**
 * One ACE rights field as a 32-bit mask. Hex is taken as written.
 * Letter rights are SDDL codes, two characters at a time (`DC` is FILE_WRITE_DATA, not icacls delete-child).
 * An unknown code fails closed and is named.
 */
export function sddlRightsMask(rights: string): { mask: number } | { unknown: string } {
  const text = rights.toUpperCase().replace(/\s+/g, "");
  let mask = 0;
  for (const part of text.match(/0X[0-9A-F]+/g) ?? []) mask |= Number.parseInt(part.slice(2), 16);
  const words = text.replace(/0X[0-9A-F]+/g, "");
  if (words.length % 2 !== 0) return { unknown: words };
  for (let i = 0; i < words.length; i += 2) {
    const token = words.slice(i, i + 2);
    if (SDDL_RIGHTS_IGNORED.has(token)) continue;
    const bit = SDDL_RIGHTS[token];
    if (bit === undefined) return { unknown: token };
    mask |= bit;
  }
  return { mask: mask >>> 0 };
}

/** First unknown SDDL right in a parsed DACL. Null when every rights field is known, the text is not SDDL, or an ACE type is unknown. */
export function sddlUnknownRight(text: string): string | null {
  const aces = parseSddlAces(text);
  if (aces === null) return null;
  for (const ace of aces) {
    if (aceSkipped(ace)) continue;
    const parsed = sddlRightsMask(ace.rights);
    if ("unknown" in parsed) return parsed.unknown;
  }
  return null;
}

/** First ACE type in the DACL that is not allow, deny, or an ignored SACL type. */
function sddlUnknownAceType(text: string): string | null {
  const read = readDacl(text);
  if (read === null || read.unknownType === null || read.unknownType === "") return null;
  return read.unknownType;
}

/** Inherit-only and deny ACEs do not apply. They are skipped before SID or rights are read. */
function aceSkipped(ace: SddlAce): boolean {
  return ace.inheritOnly || ace.type === "D";
}

function refuseAcl(text: string, message: string): string {
  const base = message.endsWith("\n") ? message.slice(0, -1) : message;
  const aceType = sddlUnknownAceType(text);
  if (aceType) return `${base} untrusted ACL, unknown SDDL ACE type ${aceType}`;
  const token = sddlUnknownRight(text);
  if (!token) return message;
  return `${base} unknown SDDL right ${token}`;
}

function aceWrites(ace: SddlAce, ancestor: boolean): boolean {
  if (aceSkipped(ace) || ace.type !== "A") return false;
  const parsed = sddlRightsMask(ace.rights);
  if ("unknown" in parsed) return true;
  return (parsed.mask & (ancestor ? ANCESTOR_REPLACE_MASK : OBJECT_WRITE_MASK)) !== 0;
}

/**
 * True when SDDL lets a principal other than Administrators, SYSTEM, or
 * TrustedInstaller change this object. Text that is not SDDL is untrusted.
 * An ACE type outside allow, deny, and ignored SACL types is an untrusted ACL.
 * `ancestor: true` counts only replace / re-point rights. `(IO)` does not apply.
 * `svcSid`, when set, is trusted the same way verifyServiceAcl trusts it.
 */
export function windowsUserCanWrite(
  text: string,
  opts?: { path?: string; userSid?: string; ancestor?: boolean; svcSid?: string },
): boolean {
  const aces = parseSddlAces(text);
  if (aces === null) return true;
  const ancestor = opts?.ancestor === true;
  const svc = opts?.svcSid?.trim().replace(/^\*/, "").toUpperCase() ?? "";
  for (const ace of aces) {
    if (!aceWrites(ace, ancestor)) continue;
    if (TRUSTED_WRITER_SIDS.has(ace.sid)) continue;
    if (svc !== "" && ace.sid === svc) continue;
    return true;
  }
  return false;
}

/** Symlink or junction resolved. A missing path stays as given so a later ACL or stat check can refuse it. */
export function resolveTrustPath(file: string, platform: InstallPlatform): string {
  try {
    return platform === "win32" ? realpathSync.native(file) : realpathSync(file);
  } catch {
    return file;
  }
}

export function trustTargets(file: string, platform: InstallPlatform): { path: string; ancestor: boolean }[] {
  return ancestry(resolveTrustPath(file, platform), platform).map((entry, index) => ({
    path: entry,
    ancestor: index > 0,
  }));
}

function linuxNodeUntrusted(modes: { uid: number; mode: number }[]): boolean {
  return modes.some((st) => st.uid !== 0 || (st.mode & 0o022) !== 0);
}

function setOwner(dir: string): PlanOp {
  return { op: "argv", argv: toolArgv("icacls", [dir, "/setowner", ADMINISTRATORS_SID, "/T", "/C"], "win32") };
}

/**
 * Directory grant only. `(OI)(CI)` on a directory propagates to children.
 * Never combine this with `/T`: `/inheritance:r /T` strips every child, and `(OI)(CI)`
 * does not apply to a file, so each file is left with an empty DACL.
 * `principal` is `verax-svc` in the plan; execute rewrites it to `*S-1-...`.
 */
export function windowsDirGrantArgs(dir: string, principal: string, rights: "F" | "RX"): string[] {
  return [
    dir,
    "/inheritance:r",
    "/grant:r",
    `${principal}:(OI)(CI)${rights}`,
    "/grant:r",
    `${ADMINISTRATORS_SID}:(OI)(CI)F`,
    "/grant:r",
    `${SYSTEM_SID}:(OI)(CI)F`,
  ];
}

/** Children inherit the directory DACL. `/reset` carries no `(OI)` or `(CI)` grant. */
export function windowsResetInheritArgs(dir: string): string[] {
  return [`${dir}\\*`, "/reset", "/T", "/C"];
}

function grantService(dir: string, rights: "F" | "RX"): PlanOp {
  return { op: "argv", argv: toolArgv("icacls", windowsDirGrantArgs(dir, VERAX_SVC, rights), "win32") };
}

function resetInherit(dir: string): PlanOp {
  return { op: "argv", argv: toolArgv("icacls", windowsResetInheritArgs(dir), "win32") };
}

/** A file ACE has no `(OI)` or `(CI)`. Those flags are only legal on a directory. */
function grantFile(file: string, principal: string, rights: "F" | "R"): PlanOp {
  const ace = rights === "R" ? `${principal}:(R)` : `${principal}:${rights}`;
  return {
    op: "argv",
    argv: toolArgv("icacls", [
      file,
      "/inheritance:r",
      "/grant:r",
      ace,
      "/grant:r",
      `${ADMINISTRATORS_SID}:F`,
      "/grant:r",
      `${SYSTEM_SID}:F`,
    ], "win32"),
  };
}

/** 32 characters drawn from 32 random bytes. Mixed case and a digit, no shell metacharacters. */
function windowsServicePassword(): string {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digit = "23456789";
  const all = lower + upper + digit;
  const bytes = randomBytes(32);
  return [...bytes]
    .map((b, i) => {
      if (i === 0) return upper[b % upper.length]!;
      if (i === 1) return lower[b % lower.length]!;
      if (i === 2) return digit[b % digit.length]!;
      return all[b % all.length]!;
    })
    .join("");
}

function psSingle(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

/** Script text has no secret. The password is the first stdin line, read by the script. */
function powershellStdin(body: string, password: string, tempDir: string): PlanOp {
  return {
    op: "argv",
    argv: toolArgv("powershell", ["-NoProfile", "-NonInteractive", "-Command", powerShellScript(body)], "win32"),
    stdin: `${password}\n`,
    env: systemToolEnv("win32", tempDir),
  };
}

/**
 * One PowerShell snippet for the install script and the win32 test.
 * Normalises holder tokens to sorted unique strings and compares with
 * Compare-Object. Functions emit strings; they do not return collections,
 * so a one-item result is not unrolled into a bare string.
 * `$prev`, `$want`, and `$got` are the raw token lists. Sets `$prevSet`,
 * `$wantSet`, and `$gotSet`. A mismatch prints previous/expected/after/added/missing
 * and throws; added/missing are also printed when the sets match.
 */
export const LOGON_HOLDER_COMPARE = [
  "function Normalize-LogonHolders([string]$csv) { foreach ($raw in ($csv -split ',')) { $n = $raw.Trim(); if ($n.Length -eq 0) { continue }; if ($n.StartsWith('*')) { $n = $n.Substring(1).Trim() }; if ($n.Length -eq 0) { continue }; if ($n -notmatch '^(?i)S-1-') { try { $n = (New-Object System.Security.Principal.NTAccount($n)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { } }; $n.ToUpperInvariant() } }",
  "$prevSet = [string[]]@((Normalize-LogonHolders (($prev -join ','))) | Sort-Object -Unique)",
  "$wantSet = [string[]]@((Normalize-LogonHolders (($want -join ','))) | Sort-Object -Unique)",
  "$gotSet = [string[]]@((Normalize-LogonHolders (($got -join ','))) | Sort-Object -Unique)",
  "$added = [string[]]@(); $missing = [string[]]@(); $holderEqual = $false",
  "if ($wantSet.Count -gt 0 -and $gotSet.Count -gt 0) { $cmp = @(Compare-Object -ReferenceObject $wantSet -DifferenceObject $gotSet -SyncWindow 0); $holderEqual = $cmp.Count -eq 0; $added = [string[]]@($cmp | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject }); $missing = [string[]]@($cmp | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject }) } elseif ($wantSet.Count -eq 0 -and $gotSet.Count -eq 0) { $holderEqual = $true } else { if ($gotSet.Count -gt 0) { $added = $gotSet }; if ($wantSet.Count -gt 0) { $missing = $wantSet } }",
  "[Console]::Error.WriteLine(('added: ' + ($added -join ','))); [Console]::Error.WriteLine(('missing: ' + ($missing -join ',')))",
  "if (-not $holderEqual) { [Console]::Error.WriteLine(('previous: ' + ($prevSet -join ','))); [Console]::Error.WriteLine(('expected: ' + ($wantSet -join ','))); [Console]::Error.WriteLine(('after: ' + ($gotSet -join ','))); throw 'SeBatchLogonRight is not exactly the previous holders plus the service account' }",
].join("; ");

/**
 * Secedit holder list as a set of upper-case SIDs.
 * Split on commas, trim, drop one leading `*`, map a name through `nameToSid`,
 * keep an unmapped name upper-cased, de-duplicate. A token that already matches
 * `S-1-` is a SID and is not looked up. The install script's
 * `Normalize-LogonHolders` is this function with NTAccount.Translate as the map.
 */
export function normalizeLogonHolders(csv: string, nameToSid: Readonly<Record<string, string>>): string[] {
  const lookup = new Map<string, string>();
  for (const [name, sid] of Object.entries(nameToSid)) lookup.set(name.toUpperCase(), sid);
  const set = new Set<string>();
  for (const raw of csv.split(",")) {
    let n = raw.trim();
    if (n.length === 0) continue;
    if (n.startsWith("*")) n = n.slice(1).trim();
    if (n.length === 0) continue;
    if (!/^S-1-/i.test(n)) {
      const sid = lookup.get(n.toUpperCase());
      if (sid !== undefined) n = sid;
    }
    set.add(n.toUpperCase());
  }
  return [...set].sort();
}

/** Five stderr lines for a holder-set mismatch. `added` is after − expected. */
export function logonHolderMismatchLines(
  previous: readonly string[],
  expected: readonly string[],
  after: readonly string[],
): string[] {
  const expectedSet = new Set(expected);
  const afterSet = new Set(after);
  const added = after.filter((sid) => !expectedSet.has(sid));
  const missing = expected.filter((sid) => !afterSet.has(sid));
  return [
    `previous: ${previous.join(",")}`,
    `expected: ${expected.join(",")}`,
    `after: ${after.join(",")}`,
    `added: ${added.join(",")}`,
    `missing: ${missing.join(",")}`,
  ];
}

/** Terminating errors exit 1. Native calls still need an explicit `$LASTEXITCODE` check. */
export function powerShellScript(body: string): string {
  return [
    "$ErrorActionPreference = 'Stop'",
    "Set-StrictMode -Version 3",
    `try { ${body} } catch { [Console]::Error.WriteLine("${PS_ERROR_MARK} $($_.Exception.Message)"); [Console]::Error.WriteLine($_.Exception.Message); exit 1 }`,
  ].join("; ");
}

function psNative(command: string, tool: string): string {
  return `${command}; if ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine("${PS_ERROR_MARK} ${tool} exited $LASTEXITCODE"); exit $LASTEXITCODE }`;
}

function windowsAccountOps(password: string, create: boolean, tempDir: string): PlanOp[] {
  const user = create
    ? "New-LocalUser -Name 'verax-svc' -Password $sec -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires -Description 'Verax body service account'"
    : "Set-LocalUser -Name 'verax-svc' -Password $sec";
  const cfg = psSingle(path.win32.join(tempDir, "verax-rights.cfg"));
  const db = psSingle(path.win32.join(tempDir, "verax-rights.sdb"));
  const after = psSingle(path.win32.join(tempDir, "verax-rights-after.cfg"));
  const script = [
    "$plain = [Console]::In.ReadLine()",
    "if ([string]::IsNullOrEmpty($plain)) { exit 1 }",
    "$sec = ConvertTo-SecureString -String $plain -AsPlainText -Force",
    user,
    "$sid = (Get-LocalUser -Name 'verax-svc').SID.Value",
    "Remove-LocalGroupMember -SID 'S-1-5-32-545' -Member $sid -ErrorAction SilentlyContinue",
    "Enable-LocalUser -Name 'verax-svc'",
    "$star = '*' + $sid",
    "$secedit = Join-Path $env:SystemRoot 'System32\\secedit.exe'",
    `$cfg = ${cfg}`,
    `$db = ${db}`,
    `$after = ${after}`,
    psNative("& $secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null", "secedit"),
    "$raw = [IO.File]::ReadAllText($cfg)",
    "$flat = [regex]::Replace($raw, '\\\\[ \\t]*\\r?\\n', '')",
    "$prev = @()",
    "if ($flat -match 'SeBatchLogonRight\\s*=\\s*([^\\r\\n]*)') { $prev = @($Matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) }",
    "$want = [System.Collections.Generic.List[string]]::new()",
    "foreach ($h in $prev) { $want.Add($h) }",
    "if (-not ($want -contains $star)) { $want.Add($star) }",
    "$line = 'SeBatchLogonRight = ' + ($want -join ',')",
    "if ($flat -match 'SeBatchLogonRight\\s*=') { $edited = [regex]::Replace($flat, 'SeBatchLogonRight\\s*=\\s*[^\\r\\n]*', $line, 1) } else { $edited = $flat.TrimEnd() + \"`r`n\" + $line + \"`r`n\" }",
    "[IO.File]::WriteAllText($cfg, $edited, [Text.Encoding]::Unicode)",
    psNative("& $secedit /configure /db $db /cfg $cfg /areas USER_RIGHTS | Out-Null", "secedit"),
    psNative("& $secedit /export /cfg $after /areas USER_RIGHTS | Out-Null", "secedit"),
    "$gotText = [regex]::Replace([IO.File]::ReadAllText($after), '\\\\[ \\t]*\\r?\\n', '')",
    "$got = @()",
    "if ($gotText -match 'SeBatchLogonRight\\s*=\\s*([^\\r\\n]*)') { $got = @($Matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) }",
    LOGON_HOLDER_COMPARE,
    "$beforeOther = @([regex]::Matches($flat, '(?m)^\\s*(Se\\w+)\\s*=\\s*([^\\r\\n]*)') | Where-Object { $_.Groups[1].Value -ne 'SeBatchLogonRight' } | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() + '=' + (($_.Groups[2].Value.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',') } | Sort-Object)",
    "$afterOther = @([regex]::Matches($gotText, '(?m)^\\s*(Se\\w+)\\s*=\\s*([^\\r\\n]*)') | Where-Object { $_.Groups[1].Value -ne 'SeBatchLogonRight' } | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() + '=' + (($_.Groups[2].Value.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' } | Sort-Object -Unique) -join ',') } | Sort-Object)",
    "if ($beforeOther.Count -ne $afterOther.Count) { throw 'SeBatchLogonRight is not exactly the previous holders plus the service account' }",
    "for ($i = 0; $i -lt $beforeOther.Count; $i++) { if ($beforeOther[$i] -ne $afterOther[$i]) { throw 'SeBatchLogonRight is not exactly the previous holders plus the service account' } }",
    "[Console]::Out.WriteLine(('SeBatchLogonRight: ' + $gotSet.Count + ' holders, service account added'))",
    "Remove-Item $cfg,$db,$after -ErrorAction SilentlyContinue",
  ].join("; ");
  return [powershellStdin(script, password, tempDir)];
}

function windowsTaskOp(password: string, nodeBin: string, cliBin: string, envFile: string, logFile: string, tempDir: string): PlanOp {
  const argument = `"${cliBin}" serve --env-file "${envFile}" --log-file "${logFile}"`;
  const script = [
    "$plain = [Console]::In.ReadLine()",
    "if ([string]::IsNullOrEmpty($plain)) { exit 1 }",
    `$action = New-ScheduledTaskAction -Execute ${psSingle(nodeBin)} -Argument ${psSingle(argument)}`,
    "$trigger = New-ScheduledTaskTrigger -AtStartup",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)",
    "$sid = (Get-LocalUser -Name 'verax-svc').SID.Value",
    "Register-ScheduledTask -TaskName 'Verax Body' -Action $action -Trigger $trigger -User $sid -Password $plain -RunLevel Limited -Settings $settings -Force",
    "Start-ScheduledTask -TaskName 'Verax Body'",
  ].join("; ");
  return powershellStdin(script, password, tempDir);
}

function xmlEscape(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function plistText(nodeBin: string, cliBin: string, envFile: string, errFile: string, logFile: string): string {
  const args = [nodeBin, cliBin, "serve", "--env-file", envFile, "--log-file", logFile].map((part) => `    <string>${xmlEscape(part)}</string>`);
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    "<dict>",
    "  <key>Label</key>",
    `  <string>${DARWIN_LABEL}</string>`,
    "  <key>UserName</key>",
    `  <string>${DARWIN_USER}</string>`,
    "  <key>GroupName</key>",
    `  <string>${DARWIN_USER}</string>`,
    "  <key>ProgramArguments</key>",
    "  <array>",
    ...args,
    "  </array>",
    "  <key>RunAtLoad</key>",
    "  <true/>",
    "  <key>KeepAlive</key>",
    "  <true/>",
    "  <key>StandardErrorPath</key>",
    `  <string>${xmlEscape(errFile)}</string>`,
    "</dict>",
    "</plist>",
    "",
  ].join("\n");
}

function dscl(args: readonly string[]): PlanOp {
  return { op: "argv", argv: toolArgv("dscl", [".", ...args], "darwin") };
}

export function successText(
  platform: InstallPlatform,
  info: { codeDir: string; stateDir: string; tokenPath: string; port: number },
): string {
  const origin = `http://127.0.0.1:${info.port}`;
  const claude =
    platform === "win32"
      ? `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(Get-Content -Raw '${info.tokenPath}')"`
      : `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(cat '${info.tokenPath}')"`;
  const mcp = [
    "{",
    '  "mcpServers": {',
    '    "verax": {',
    `      "url": "${origin}/mcp",`,
    '      "headers": { "Authorization": "Bearer <token from your issuer>" }',
    "    }",
    "  }",
    "}",
  ].join("\n");
  const approve =
    platform === "win32"
      ? "Run as administrator: verax approve"
      : "Approve held calls from an elevated terminal: sudo verax approve";
  return [
    `code ${info.codeDir}`,
    `state ${info.stateDir}`,
    "service is running",
    `agent token ${info.tokenPath}`,
    "",
    "Claude Code:",
    claude,
    "",
    "Cursor / generic mcp.json:",
    mcp,
    "",
    approve,
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

/** Well-known groups. `whoami` must not hand the token ACE to one of these. */
const GROUP_TOKEN_SIDS = new Set(["S-1-1-0", "S-1-5-11", "S-1-5-32-545"]);

function tokenPrincipalFor(userSid: string | undefined): { principal: string } | { error: string } | null {
  const sid = userSid?.trim().replace(/^\*/, "").toUpperCase() ?? "";
  if (sid === "") return null;
  if (GROUP_TOKEN_SIDS.has(sid)) {
    return { error: `refusing token principal ${sid}: a well-known group is not the invoking user` };
  }
  if (!/^S-1-[0-9-]+$/.test(sid)) return { error: `refusing token principal ${sid}` };
  return { principal: `*${sid}` };
}

function unitText(nodeBin: string, cliBin: string, envFile: string, stateDir: string, logFile: string): string {
  return [
    "[Unit]",
    "Description=Verax body",
    "After=network.target",
    "",
    "[Service]",
    "Type=simple",
    "User=verax",
    `ExecStart=${nodeBin} ${cliBin} serve --env-file ${envFile} --log-file ${logFile}`,
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    `ReadWritePaths=${stateDir}`,
    "ProtectHome=yes",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

function darwinRefuses(
  fact: { exists: boolean; symlink: boolean } | undefined,
  dir: string,
  markerExists: boolean,
): InstallPlan | null {
  if (!fact) return null;
  if (fact.symlink) return fail(EX_CONFIG, `refusing: ${dir} is a symlink`);
  if (fact.exists && !markerExists) return fail(EX_CONFIG, `refusing: ${dir} was not created by verax install`);
  return null;
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
  const posixRoot = platform === "win32" ? undefined : opts.posixRoot;
  const fixed = fixedPosix(posixRoot);
  const located = pathsFor(platform, env, posixRoot, opts.invokingHome);
  if (!located.ok) return fail(located.code, located.message);
  if (platform === "win32") {
    try {
      systemToolPath("whoami", "win32");
    } catch (err) {
      if (err instanceof SystemToolError) return fail(EX_CONFIG, err.message);
      throw err;
    }
  }
  if (platform !== "win32" && platform !== "linux" && platform !== "darwin") {
    return fail(EX_CONFIG, "verax install does not run on this operating system");
  }
  const limited = bounds(opts);
  if ("error" in limited) return fail(EX_CONFIG, limited.error);
  if (opts.nodeIcacls !== undefined && windowsUserCanWrite(opts.nodeIcacls, { userSid: opts.userSid })) {
    return fail(EX_CONFIG, refuseAcl(opts.nodeIcacls, nodeTrustMessageFor(opts.execPath, platform)));
  }
  if (opts.nodeModes !== undefined && linuxNodeUntrusted(opts.nodeModes)) {
    return fail(EX_CONFIG, nodeTrustMessageFor(opts.execPath, platform));
  }
  if (opts.fromTarballs) {
    if (opts.tarballIcacls !== undefined && windowsUserCanWrite(opts.tarballIcacls, { path: opts.fromTarballs, userSid: opts.userSid, ancestor: true })) {
      return fail(EX_CONFIG, refuseAcl(opts.tarballIcacls, tarballTrustMessage(opts.fromTarballs)));
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
    const profile = env.USERPROFILE?.trim() ?? "";
    const fromSid = opts.profileImagePath?.trim() ?? "";
    if (fromSid !== "" && profile !== fromSid) {
      return fail(EX_CONFIG, `refusing: USERPROFILE ${profile} is not ProfileImagePath ${fromSid}`);
    }
    const root = path.win32.dirname(paths.stateDir);
    const ownerBad = opts.winRootOwner !== undefined && !adminOrSystem(opts.winRootOwner);
    const aclBad = opts.winRootAcl !== undefined && rootDaclRejected(opts.winRootAcl);
    if (opts.veraxRootExists && (!opts.markerExists || ownerBad || aclBad)) {
      const why = `refusing: ${root} was not created by verax install`;
      return fail(EX_CONFIG, opts.winRootAcl ? refuseAcl(opts.winRootAcl, why) : why);
    }
    if (opts.stateExists && !opts.markerExists) {
      return fail(EX_CONFIG, `refusing: ${paths.stateDir} was not created by verax install`);
    }
    if (opts.winAccount?.exists && !opts.winAccount.createdByUs) {
      return fail(EX_CONFIG, `refusing: ${VERAX_SVC} already exists and was not created by verax install`);
    }
  } else if (platform === "linux") {
    if (opts.linuxAccount?.exists && !opts.linuxAccount.createdByUs) {
      return fail(EX_CONFIG, "refusing: verax already exists and was not created by verax install");
    }
    const stateOwn = linuxOwnedByUs(opts.linuxState, paths.stateDir);
    if (stateOwn) return stateOwn;
    const codeOwn = linuxOwnedByUs(opts.linuxCode, paths.codeDir);
    if (codeOwn) return codeOwn;
  } else {
    const stateFact = darwinRefuses(opts.darwinState, paths.stateDir, Boolean(opts.markerExists));
    if (stateFact) return stateFact;
    const rootFact = darwinRefuses(opts.darwinRoot, fixed.darwinRoot, Boolean(opts.markerExists));
    if (rootFact) return rootFact;
  }
  if (opts.stateExists && !opts.force) return fail(EX_CONFIG, `refusing: ${paths.stateDir} already exists`);
  const cliBin = cliBinFor(paths.codeDir, platform);
  const envFile = (platform === "win32" ? path.win32 : path.posix).join(paths.stateDir, "verax.env");
  const logFile = (platform === "win32" ? path.win32 : path.posix).join(paths.stateDir, "body.log");
  const winPassword = platform === "win32" ? windowsServicePassword() : "";
  const winCreate = platform === "win32" && !opts.winAccount?.exists;
  const tempDir = privateTempPath(platform, env, posixRoot);
  const pathFor = platform === "win32" ? path.win32 : path.posix;
  const digestOf = new Map((opts.tarballDigests ?? []).map((row) => [row.file, row.sha256]));
  const stagedTarballs =
    opts.fromTarballs && opts.tarballFiles && opts.tarballFiles.length > 0
      ? opts.tarballFiles.map((source) => ({
          source,
          sha256: digestOf.get(source) ?? "",
          dest: pathFor.join(tempDir, pathFor.basename(source)),
        }))
      : [];
  const spec = stagedTarballs.length > 0 ? stagedTarballs.map((row) => row.dest) : [`@verax-ai/body@${opts.bodyVersion}`];
  const npmFiles = npmConfigPaths(tempDir, platform);
  const npmEnv = npmSpawnEnv(platform, opts.execPath, tempDir);
  const npmInstall: PlanOp = {
    op: "argv",
    rollbackDir: paths.codeDir,
    cwd: tempDir,
    env: npmEnv,
    argv: [
      opts.execPath,
      opts.npmCli,
      "install",
      "--prefix",
      paths.codeDir,
      "--omit=dev",
      ...npmFlags(tempDir, platform),
      ...(env.VERAX_INSTALL_DEBUG === "1" ? ["--loglevel", "verbose"] : []),
      ...spec,
    ],
  };
  const npmAudit: PlanOp = {
    op: "argv",
    rollbackDir: paths.codeDir,
    cwd: tempDir,
    env: npmEnv,
    argv: [opts.execPath, opts.npmCli, "audit", "signatures", "--prefix", paths.codeDir, ...npmFlags(tempDir, platform)],
  };
  const tokenWho = platform === "win32" ? tokenPrincipalFor(opts.userSid) : null;
  if (tokenWho && "error" in tokenWho) return fail(EX_CONFIG, tokenWho.error);
  const ops: PlanOp[] = [];
  if (platform === "win32") {
    ops.push({ op: "lock-root", path: path.win32.dirname(paths.stateDir), create: !opts.veraxRootExists });
  }
  ops.push(privateTempPlan(platform, tempDir));
  if (platform === "win32") ops.push(...windowsAccountOps(winPassword, winCreate, tempDir));
  ops.push({ op: "mkdir", path: paths.codeDir, mode: 0o755 });
  if (platform === "win32") {
    ops.push(setOwner(paths.codeDir), grantService(paths.codeDir, "RX"), resetInherit(paths.codeDir));
  }
  ops.push(
    { op: "write", path: npmFiles.userconfig, contents: "", mode: 0o600, exclusive: true },
    { op: "write", path: npmFiles.globalconfig, contents: "", mode: 0o600, exclusive: true },
    ...(stagedTarballs.length > 0 ? [{ op: "stage-tarballs" as const, files: stagedTarballs }] : []),
    npmInstall,
  );
  if (!opts.fromTarballs) ops.push(npmAudit);
  if (platform === "win32") ops.push(setOwner(paths.codeDir), grantService(paths.codeDir, "RX"), resetInherit(paths.codeDir));
  if (platform === "darwin") {
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["-R", "root:wheel", fixed.darwinRoot], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["-R", "go-w", fixed.darwinRoot], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0755", fixed.darwinRoot, paths.codeDir], "darwin") },
    );
  }
  ops.push({ op: "manifest", dir: paths.codeDir });
  if (platform === "darwin") {
    ops.push(
      { op: "mkdir", path: fixed.darwinStateParent, mode: 0o755 },
      { op: "argv", argv: toolArgv("chown", ["root:wheel", fixed.darwinStateParent], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0755", fixed.darwinStateParent], "darwin") },
    );
  }
  ops.push({ op: "mkdir", path: paths.stateDir, mode: 0o700 });
  if (platform === "win32") {
    const markerPath = path.win32.join(path.win32.dirname(paths.stateDir), "install.json");
    const marker = installMarkerText(opts, paths, { createdAccount: true });
    ops.push(
      setOwner(paths.stateDir),
      grantService(paths.stateDir, "F"),
      resetInherit(paths.stateDir),
      { op: "write", path: markerPath, contents: marker, mode: 0o644 },
      setOwner(markerPath),
      grantFile(markerPath, VERAX_SVC, "F"),
    );
  } else if (platform === "linux") {
    ops.push(
      {
        op: "write",
        path: path.posix.join(paths.codeDir, "install.json"),
        contents: installMarkerText(opts, paths, {
          createdUser: true,
          // useradd without -N creates the matching group. A later uninstall removes it only when the marker says so.
          createdGroup: !opts.linuxAccount?.exists || Boolean(opts.linuxAccount?.createdGroup),
        }),
        mode: 0o644,
      },
      ...(!opts.linuxAccount?.exists
        ? [{ op: "argv" as const, argv: toolArgv("useradd", ["--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "verax"], "linux") }]
        : []),
      { op: "argv", argv: toolArgv("chown", ["verax:verax", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "linux") },
    );
  } else {
    const account = opts.darwinAccount ?? { uid: 280, gid: 280, createUser: true, createGroup: true, recordUser: true, recordGroup: true };
    ops.push({
      op: "write",
      path: fixed.darwinMarker,
      contents: installMarkerText(opts, paths, { createdUser: account.recordUser, createdGroup: account.recordGroup }),
      mode: 0o644,
    });
    if (account.createGroup) {
      ops.push(
        dscl(["-create", `/Groups/${DARWIN_USER}`]),
        dscl(["-create", `/Groups/${DARWIN_USER}`, "PrimaryGroupID", String(account.gid)]),
      );
    }
    if (account.createUser) {
      ops.push(
        dscl(["-create", `/Users/${DARWIN_USER}`]),
        dscl(["-create", `/Users/${DARWIN_USER}`, "UniqueID", String(account.uid)]),
        dscl(["-create", `/Users/${DARWIN_USER}`, "PrimaryGroupID", String(account.gid)]),
        dscl(["-create", `/Users/${DARWIN_USER}`, "UserShell", "/usr/bin/false"]),
        dscl(["-create", `/Users/${DARWIN_USER}`, "NFSHomeDirectory", "/var/empty"]),
        dscl(["-create", `/Users/${DARWIN_USER}`, "IsHidden", "1"]),
        dscl(["-create", `/Users/${DARWIN_USER}`, "RealName", "Verax body"]),
      );
    }
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["root:wheel", fixed.darwinMarker], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0644", fixed.darwinMarker], "darwin") },
      { op: "argv", argv: toolArgv("chown", [`${DARWIN_USER}:${DARWIN_USER}`, paths.stateDir], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "darwin") },
    );
  }
  ops.push({
    op: "init",
    stateDir: paths.stateDir,
    tokenPath: paths.tokenPath,
    port: limited.port,
    days: limited.days,
    force: Boolean(opts.force),
    noOwnerGrant: true,
  });
  if (platform === "win32") {
    ops.push(
      resetInherit(paths.stateDir),
      setOwner(paths.stateDir),
      {
        op: "argv",
        argv: toolArgv("icacls", [
          paths.tokenPath,
          "/inheritance:r",
          ...(tokenWho && "principal" in tokenWho ? ["/grant:r", `${tokenWho.principal}:(R)`] : []),
        ], "win32"),
      },
    );
    ops.push(windowsTaskOp(winPassword, opts.execPath, cliBin, envFile, logFile, tempDir));
  } else if (platform === "linux") {
    const sudoUser = env.SUDO_USER!.trim();
    const tokenDir = path.posix.dirname(paths.tokenPath);
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["-R", "verax:verax", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chown", [`${sudoUser}:`, tokenDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", tokenDir], "linux") },
      { op: "argv", argv: toolArgv("chown", [`${sudoUser}:`, paths.tokenPath], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0600", paths.tokenPath], "linux") },
      { op: "write", path: fixed.systemdUnit, contents: unitText(opts.execPath, cliBin, envFile, paths.stateDir, logFile), mode: 0o644 },
      { op: "argv", argv: toolArgv("systemctl", ["daemon-reload"], "linux") },
      { op: "argv", argv: toolArgv("systemctl", ["enable", "--now", "verax"], "linux") },
    );
  } else {
    const sudoUser = env.SUDO_USER!.trim();
    const tokenDir = path.posix.dirname(paths.tokenPath);
    const errFile = path.posix.join(paths.stateDir, "body.err");
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["-R", `${DARWIN_USER}:${DARWIN_USER}`, paths.stateDir], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "darwin") },
      { op: "argv", argv: toolArgv("chown", [`${sudoUser}:`, tokenDir], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0700", tokenDir], "darwin") },
      { op: "argv", argv: toolArgv("chown", [`${sudoUser}:`, paths.tokenPath], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0600", paths.tokenPath], "darwin") },
      { op: "write", path: fixed.darwinPlist, contents: plistText(opts.execPath, cliBin, envFile, errFile, logFile), mode: 0o644 },
      { op: "argv", argv: toolArgv("chown", ["root:wheel", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0644", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("plutil", ["-lint", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("launchctl", ["bootstrap", "system", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("launchctl", ["enable", `system/${DARWIN_LABEL}`], "darwin") },
    );
  }
  ops.push(
    { op: "wait-healthz", port: limited.port, timeoutMs: HEALTH_WAIT_MS },
    {
      op: "print",
      text: successText(platform, { ...paths, port: limited.port }),
    },
  );
  if (platform === "win32") tagWinTemp(ops, tempDir);
  const bare = bareSidAccount(ops);
  if (bare) return fail(EX_CONFIG, `refusing icacls account ${bare}: a SID needs a leading *`);
  return { ok: true, ops, ...paths };
}

const PRIVATE_TEMP_ACL = [ADMINISTRATORS_SID, SYSTEM_SID] as const;

/** Admin-only install scratch. Never the caller's TEMP. */
function privateTempPath(platform: InstallPlatform, env: NodeJS.ProcessEnv, posixRoot?: string): string {
  const id = randomBytes(16).toString("hex");
  if (platform === "win32") {
    const data = env.ProgramData || "C:\\ProgramData";
    return path.win32.join(data, "Verax", `install-tmp-${id}`);
  }
  const prefix = posixRoot?.trim().replace(/\/+$/, "") ?? "";
  if (platform === "darwin") {
    const root = prefix ? `${prefix}${DARWIN_ROOT}` : DARWIN_ROOT;
    return `${root}/.install-tmp-${id}`;
  }
  const parent = prefix ? `${prefix}/var/tmp` : "/var/tmp";
  return `${parent}/verax-install-tmp-${id}`;
}

const NPM_REGISTRY = "https://registry.npmjs.org/";

function npmConfigPaths(tempDir: string, platform: InstallPlatform): { userconfig: string; globalconfig: string; cache: string } {
  const p = platform === "win32" ? path.win32 : path.posix;
  return {
    userconfig: p.join(tempDir, "empty-npmrc"),
    globalconfig: p.join(tempDir, "empty-globalrc"),
    cache: p.join(tempDir, "cache"),
  };
}

/** Flags on every npm invocation. userconfig and globalconfig are empty files in the private temp. */
function npmFlags(tempDir: string, platform: InstallPlatform): string[] {
  const files = npmConfigPaths(tempDir, platform);
  return [
    "--userconfig",
    files.userconfig,
    "--globalconfig",
    files.globalconfig,
    "--registry",
    NPM_REGISTRY,
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--no-update-notifier",
  ];
}

/**
 * Fresh env for npm. Nothing is copied from the caller: no HOME, no npm_config_*, no NPM_CONFIG_*.
 * HOME and the Windows profile dirs are the private temp, so ~/.npmrc is never read.
 */
export function npmSpawnEnv(platform: InstallPlatform, execPath: string, tempDir: string): NodeJS.ProcessEnv {
  const p = platform === "win32" ? path.win32 : path.posix;
  const nodeDir = p.dirname(execPath);
  const cache = npmConfigPaths(tempDir, platform).cache;
  if (platform === "win32") {
    const base = systemToolEnv("win32", tempDir);
    const root = base.SystemRoot || "C:\\Windows";
    return {
      SystemRoot: base.SystemRoot,
      windir: base.windir,
      PATHEXT: base.PATHEXT,
      ComSpec: base.ComSpec,
      SystemDrive: base.SystemDrive,
      PATH: [nodeDir, path.win32.join(root, "System32"), root].join(";"),
      HOME: tempDir,
      USERPROFILE: tempDir,
      APPDATA: tempDir,
      LOCALAPPDATA: tempDir,
      TEMP: tempDir,
      TMP: tempDir,
      npm_config_cache: cache,
    };
  }
  return {
    PATH: [nodeDir, "/usr/sbin", "/usr/bin", "/sbin", "/bin"].join(":"),
    HOME: tempDir,
    USERPROFILE: tempDir,
    APPDATA: tempDir,
    LOCALAPPDATA: tempDir,
    TEMP: tempDir,
    TMP: tempDir,
    TMPDIR: tempDir,
    npm_config_cache: cache,
  };
}

/** `resolved` tarball URLs that are not the public npm registry. */
export function registryLockProblems(lockText: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockText);
  } catch {
    return ["package-lock.json is not JSON"];
  }
  const bad: string[] = [];
  const walk = (value: unknown): void => {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
      return;
    }
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (key === "resolved" && typeof child === "string") {
        if (!child.startsWith(NPM_REGISTRY)) bad.push(child);
      } else {
        walk(child);
      }
    }
  };
  walk(parsed);
  if (bad.length === 0 && !lockText.includes(`"resolved"`)) return ["package-lock.json has no resolved tarball URL"];
  return bad;
}

function registryBodyVersion(argv: readonly string[]): string | null {
  const spec = argv.find((arg) => arg.startsWith("@verax-ai/body@"));
  if (!spec) return null;
  const version = spec.slice("@verax-ai/body@".length).trim();
  return version === "" ? null : version;
}

function verifyRegistryInstall(codeDir: string, bodyVersion: string): string | null {
  const pkgPath = path.join(codeDir, "node_modules", "@verax-ai", "body", "package.json");
  const lockPath = path.join(codeDir, "package-lock.json");
  let version = "";
  let lockText = "";
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: unknown };
    version = typeof pkg.version === "string" ? pkg.version : "";
    lockText = readFileSync(lockPath, "utf8");
  } catch {
    return `installed body at ${pkgPath} cannot be read`;
  }
  if (version !== bodyVersion) return `installed @verax-ai/body version ${version || "missing"} is not ${bodyVersion}`;
  const bad = registryLockProblems(lockText);
  if (bad.length > 0) return `package-lock.json resolved URL is not ${NPM_REGISTRY}: ${bad[0]}`;
  return null;
}

function isNpmArgv(argv: readonly string[]): boolean {
  if (argv.some((arg) => arg.replace(/\\/g, "/").endsWith("/npm-cli.js"))) return true;
  // POSIX tests stand in a root-owned binary for npm-cli.js. The planned flags still name npm.
  return argv.includes("--userconfig") && (argv.includes("install") || argv.includes("audit"));
}

function privateTempPlan(platform: InstallPlatform, dir: string): PlanOp {
  if (platform === "win32") {
    return {
      op: "private-temp",
      path: dir,
      acl: PRIVATE_TEMP_ACL,
      inheritance: "removed",
      owner: ADMINISTRATORS_SID,
    };
  }
  return { op: "private-temp", path: dir, mode: 0o700 };
}

/** Every Windows tool argv during install uses the private temp, not the caller's TEMP. */
function tagWinTemp(ops: PlanOp[], tempDir: string): void {
  for (const op of ops) {
    if (op.op !== "argv") continue;
    const name = systemToolName(op.argv[0] ?? "");
    const temp = { TEMP: tempDir, TMP: tempDir };
    if (SYSTEM_TOOL_NAMES.has(name)) op.env = { ...systemToolEnv("win32", tempDir), ...op.env, ...temp };
    else op.env = { ...op.env, ...temp };
  }
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
  opts: {
    keepState: boolean;
    removeWinAccount?: boolean;
    removeDarwinUser?: boolean;
    removeDarwinGroup?: boolean;
    /** Linux `verax` login. Set only when the marker says `createdUser`. */
    removeLinuxUser?: boolean;
    /** Linux `verax` group. Set only when the marker says `createdGroup`. */
    removeLinuxGroup?: boolean;
    posixRoot?: string;
  },
): InstallPlan {
  const located = pathsFor(platform, env, opts.posixRoot);
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
  } else if (platform === "linux") {
    ops.push(
      { op: "argv", argv: toolArgv("systemctl", ["disable", "--now", "verax"], "linux"), optional: true },
      { op: "remove", path: "/etc/systemd/system/verax.service" },
      { op: "argv", argv: toolArgv("systemctl", ["daemon-reload"], "linux"), optional: true },
    );
  } else {
    ops.push(
      { op: "argv", argv: toolArgv("launchctl", ["bootout", `system/${DARWIN_LABEL}`], "darwin"), optional: true },
      { op: "remove", path: DARWIN_PLIST },
    );
  }
  ops.push({ op: "remove", path: paths.codeDir });
  if (platform === "darwin") ops.push({ op: "remove", path: DARWIN_MARKER }, { op: "remove", path: DARWIN_ROOT });
  if (!opts.keepState) ops.push({ op: "remove", path: paths.stateDir });
  if (platform === "win32" && opts.removeWinAccount) {
    ops.push({ op: "argv", argv: toolArgv("net", ["user", VERAX_SVC, "/delete"], "win32"), optional: true });
  }
  if (platform === "linux" && opts.removeLinuxUser) {
    ops.push({ op: "argv", argv: toolArgv("userdel", ["verax"], "linux"), optional: true });
  }
  if (platform === "linux" && opts.removeLinuxGroup) {
    ops.push({ op: "argv", argv: toolArgv("groupdel", ["verax"], "linux"), optional: true });
  }
  if (platform === "darwin" && opts.removeDarwinUser) {
    ops.push(dscl(["-delete", `/Users/${DARWIN_USER}`]));
  }
  if (platform === "darwin" && opts.removeDarwinGroup) {
    ops.push(dscl(["-delete", `/Groups/${DARWIN_USER}`]));
  }
  return { ok: true, ops, ...paths };
}

function aceRightsKind(rights: string): "F" | "RX" | "other" {
  const parsed = sddlRightsMask(rights);
  if ("unknown" in parsed) return "other";
  const mask = parsed.mask;
  const full = (mask & 0x1f01ff) === 0x1f01ff || (mask & 0x10000000) !== 0;
  if (full) return "F";
  if ((mask & OBJECT_WRITE_MASK) !== 0) return "other";
  const readExec = /FR|FX|GR|GX|RX/.test(rights) || (mask & 0x1200a9) === 0x1200a9;
  if (readExec && mask !== 0) return "RX";
  if (rights === "RX") return "RX";
  return "other";
}

export function foreignAclPrincipals(text: string, svcSid?: string): string[] {
  const aces = parseSddlAces(text);
  if (aces === null) return ["unparsed"];
  const sid = svcSid?.trim().replace(/^\*/, "").toUpperCase() ?? "";
  const found: string[] = [];
  for (const ace of aces) {
    if (ace.inheritOnly || ace.type !== "A") continue;
    if (TRUSTED_WRITER_SIDS.has(ace.sid)) continue;
    if (sid !== "" && ace.sid === sid) continue;
    found.push(ace.sid);
  }
  return found;
}

export type ParsedAce = { principal: string; rights: "F" | "RX" | "other"; inheritOnly: boolean };

/** One SDDL allow/deny ACE. `(IO)` does not apply to the object. */
export function parseIcaclsAce(line: string): ParsedAce | null {
  const aces = parseSddlAces(line);
  const ace = aces?.[0];
  if (!ace) return null;
  return { principal: `*${ace.sid}`, rights: aceRightsKind(ace.rights), inheritOnly: ace.inheritOnly };
}

export function parseIcaclsAces(text: string): ParsedAce[] {
  const aces = parseSddlAces(text);
  if (aces === null) return [];
  return aces.filter((ace) => !ace.inheritOnly).map((ace) => ({
    principal: `*${ace.sid}`,
    rights: aceRightsKind(ace.rights),
    inheritOnly: false,
  }));
}

function aclRole(principal: string, svcSid?: string): "svc" | "admin" | "system" | "other" {
  const key = canonicalSid(principal) ?? principal.trim().replace(/^\*/, "").toUpperCase();
  const sid = svcSid?.trim().replace(/^\*/, "").toUpperCase() ?? "";
  if (sid !== "" && key === sid) return "svc";
  if (key === SID_ADMINISTRATORS) return "admin";
  if (key === SID_SYSTEM) return "system";
  if (key === SID_TRUSTED_INSTALLER) return "other";
  return "other";
}

/**
 * Code dir: service RX, Administrators F, SYSTEM F, nothing else.
 * State dir: service F, Administrators F, SYSTEM F, nothing else.
 */
export function verifyServiceAcl(
  text: string,
  kind: "code" | "state",
  opts?: { dir?: string; svcSid?: string; file?: string },
): { ok: true; aces: ParsedAce[] } | { ok: false; aces: ParsedAce[]; detail: string } {
  const aces = parseIcaclsAces(text);
  const expectedSvc = kind === "code" ? "RX" : "F";
  const label = opts?.file ?? (kind === "code" ? "code" : "state");
  const parsed = aces.map((ace) => `${ace.principal} ${ace.rights}`).join("\n");
  const fail = (why: string): { ok: false; aces: ParsedAce[]; detail: string } => ({
    ok: false,
    aces,
    detail: `${label} ACL mismatch: ${why}\n${parsed}`,
  });
  if (aces.length === 0) return fail(opts?.file ? `empty ACL on ${opts.file}` : "empty ACL");
  const roles = aces.map((ace) => ({ ace, role: aclRole(ace.principal, opts?.svcSid) }));
  if (roles.some((row) => row.role === "other")) return fail("unexpected principal");
  const svc = roles.filter((row) => row.role === "svc");
  const admin = roles.filter((row) => row.role === "admin");
  const system = roles.filter((row) => row.role === "system");
  if (svc.length !== 1 || admin.length !== 1 || system.length !== 1) return fail("expected svc, Administrators, and SYSTEM");
  if (svc[0]!.ace.rights !== expectedSvc) return fail(`svc rights are ${svc[0]!.ace.rights}, expected ${expectedSvc}`);
  if (admin[0]!.ace.rights !== "F" || system[0]!.ace.rights !== "F") return fail("Administrators and SYSTEM must be F");
  return { ok: true, aces };
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
  const sid = canonicalSid(owner);
  if (sid === SID_ADMINISTRATORS || sid === SID_SYSTEM) return true;
  const n = owner.trim().toLowerCase();
  return n === "builtin\\administrators" || n === "nt authority\\system" || n === "administrators" || n === "system";
}

/** True when the root SDDL is missing or grants a write to a SID outside Administrators and SYSTEM. */
function rootDaclRejected(text: string): boolean {
  return windowsUserCanWrite(text);
}

export function installedBoundaryChecks(input: {
  codeDir: string;
  stateDir: string;
  manifest: string | null;
  hashOf: (rel: string) => string | null;
  aclText?: string;
  /** Windows icacls of the code directory. Same verifier as the state ACL, with svc RX. */
  codeAclText?: string;
  /** icacls of files inside the state or code tree. Inherited ACEs count. An empty DACL fails, naming the file. */
  fileAcls?: { path: string; text: string; kind: "code" | "state" }[];
  /** Service SID, so a read-back ACE named `*S-1-...` matches verax-svc. */
  svcSid?: string;
  mode?: number;
  owner?: string;
  /** Group name of the state directory. macOS expects `_verax`. */
  ownerGroup?: string;
  codeOwner?: string;
  codeMode?: number;
  /** Windows owner names for the state and code directories. */
  winOwners?: { state?: string; code?: string };
  /** icacls of `%ProgramData%\\Verax`. A Users or CREATOR OWNER write ACE fails. */
  rootAclText?: string;
  rootDir?: string;
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
    const verdict = verifyServiceAcl(input.aclText, "state", { dir: input.stateDir, svcSid: input.svcSid });
    if (verdict.ok) {
      checks.push({ id: "install-acl", level: "ok", detail: "state ACL names only verax-svc, Administrators, and SYSTEM" });
    } else {
      checks.push({ id: "install-acl", level: "fail", detail: verdict.detail });
      for (const ace of verdict.aces) {
        if (aclRole(ace.principal, input.svcSid) === "other") {
          checks.push({ id: "install-acl", level: "fail", detail: `state ACL names ${ace.principal}` });
        }
      }
    }
  }
  if (input.codeAclText !== undefined) {
    const verdict = verifyServiceAcl(input.codeAclText, "code", { dir: input.codeDir, svcSid: input.svcSid });
    checks.push(
      verdict.ok
        ? { id: "install-code-acl", level: "ok", detail: "code ACL is verax-svc RX, Administrators F, and SYSTEM F" }
        : { id: "install-code-acl", level: "fail", detail: verdict.detail },
    );
  }
  for (const file of input.fileAcls ?? []) {
    const verdict = verifyServiceAcl(file.text, file.kind, { dir: file.path, svcSid: input.svcSid, file: file.path });
    const id = file.kind === "code" ? "install-code-acl" : "install-acl";
    checks.push(
      verdict.ok
        ? { id, level: "ok", detail: `${file.path} ACL names only verax-svc, Administrators, and SYSTEM` }
        : { id, level: "fail", detail: verdict.detail },
    );
  }
  if (input.mode !== undefined) {
    const bits = input.mode & 0o777;
    const ownerOk = input.owner === undefined || input.owner === "verax" || input.owner === "_verax";
    const groupOk = input.ownerGroup === undefined || input.ownerGroup === "verax" || input.ownerGroup === "_verax";
    if (bits !== 0o700) {
      checks.push({ id: "install-mode", level: "fail", detail: `state mode ${bits.toString(8)} is not 0700` });
    } else if (!ownerOk) {
      checks.push({ id: "install-mode", level: "fail", detail: `state owner ${input.owner} is not verax` });
    } else if (!groupOk) {
      checks.push({ id: "install-mode", level: "fail", detail: `state group ${input.ownerGroup} is not _verax` });
    } else {
      const who = input.owner === undefined ? "" : ` owner ${input.owner}`;
      checks.push({ id: "install-mode", level: "ok", detail: `state mode 0700${who}` });
    }
  } else if (input.owner !== undefined && input.owner !== "verax" && input.owner !== "_verax") {
    checks.push({ id: "install-mode", level: "fail", detail: `state owner ${input.owner} is not verax` });
  }
  if (input.codeMode !== undefined || input.codeOwner !== undefined) {
    const bits = input.codeMode === undefined ? undefined : input.codeMode & 0o777;
    if (bits !== undefined && (bits & 0o022) !== 0) {
      checks.push({ id: "install-code-mode", level: "fail", detail: `code mode ${bits.toString(8)} is group or other writable` });
    } else if (input.codeOwner !== undefined && input.codeOwner !== "root") {
      checks.push({ id: "install-code-mode", level: "fail", detail: `code owner ${input.codeOwner} is not root` });
    } else {
      checks.push({
        id: "install-code-mode",
        level: "ok",
        detail: input.codeOwner === undefined ? "code directory is not group or other writable" : `code owner ${input.codeOwner}`,
      });
    }
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
  if (input.rootAclText !== undefined) {
    const bad = rootDaclRejected(input.rootAclText);
    checks.push(
      bad
        ? { id: "install-root-acl", level: "fail", detail: refuseAcl(input.rootAclText, `root ACL grants write to a non-administrator on ${input.rootDir ?? "the Verax root"}`) }
        : { id: "install-root-acl", level: "ok", detail: "root ACL names only Administrators and SYSTEM" },
    );
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

/** System tools take the planned env whole. Other commands keep the process env, with the caller's TEMP removed. */
function spawnEnvFor(name: string, planned?: NodeJS.ProcessEnv): NodeJS.ProcessEnv | undefined {
  if (!planned) return undefined;
  if (SYSTEM_TOOL_NAMES.has(name)) return planned;
  const merged: NodeJS.ProcessEnv = { ...process.env };
  delete merged.TEMP;
  delete merged.TMP;
  delete merged.TMPDIR;
  return { ...merged, ...planned };
}

function defaultExec(argv: string[], stdin?: string, env?: NodeJS.ProcessEnv, cwd?: string): ExecResult {
  const head = argv[0] ?? "";
  const name = systemToolName(head);
  const input = stdin === undefined ? {} : { input: stdin };
  const place = cwd ? { cwd } : {};
  const spawnEnv = isNpmArgv(argv) ? (env ?? {}) : spawnEnvFor(name, env);
  if (!SYSTEM_TOOL_NAMES.has(name)) {
    const ran = spawnSync(head, argv.slice(1), {
      encoding: "utf8",
      windowsHide: true,
      shell: false,
      ...(spawnEnv ? { env: spawnEnv } : {}),
      ...place,
      ...input,
    });
    return { status: ran.status, stdout: ran.stdout ?? "", stderr: ran.stderr ?? "" };
  }
  let file: string;
  try {
    file = requireSystemTool(name);
  } catch (err) {
    const message = err instanceof Error ? err.message : "system tool missing";
    return { status: EX_CONFIG, stderr: `${message}\n` };
  }
  // ausearch reads stdin when it is not a tty and is not given --input-logs, and then it hangs.
  // Close stdin. Callers still pass --input-logs and never pass an input string.
  const stdinClosed: { stdio?: StdioOptions } = name === "ausearch" && stdin === undefined ? { stdio: ["ignore", "pipe", "pipe"] } : {};
  const ran = spawnSync(file, argv.slice(1), {
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    env: spawnEnv ?? systemToolEnv(),
    ...place,
    ...input,
    ...stdinClosed,
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
  const plat: InstallPlatform = platform === "win32" ? "win32" : platform === "darwin" ? "darwin" : "linux";
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

/** Ancestors created along the way are 0755. Only `target` receives `mode`. */
export function mkdirLeaf(target: string, mode: number): void {
  const parent = path.dirname(target);
  if (parent !== target && !existsSync(parent)) mkdirLeaf(parent, 0o755);
  mkdirSync(target, { mode });
  if (process.platform !== "win32") {
    try {
      chmodSync(target, mode);
    } catch {
      // The platform does not honour the mode bit.
    }
  }
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

async function waitHealth(port: number, timeoutMs: number, io: InstallIo): Promise<boolean> {
  const start = Date.now();
  let nextMark = 10_000;
  while (Date.now() - start < timeoutMs) {
    if (await healthOnce(port)) return true;
    const elapsed = Date.now() - start;
    while (elapsed >= nextMark && nextMark < timeoutMs) {
      io.stderr.write(`waiting for the body (${nextMark / 1000} s)…\n`);
      nextMark += 10_000;
    }
    const left = timeoutMs - (Date.now() - start);
    if (left <= 0) break;
    const untilMark = nextMark - (Date.now() - start);
    await new Promise((r) => setTimeout(r, Math.min(200, left, Math.max(untilMark, 1))));
  }
  return false;
}

function argvSecrets(argv: readonly string[]): string[] {
  const secrets: string[] = [];
  const rp = argv.indexOf("/RP");
  if (rp >= 0 && argv[rp + 1] && !argv[rp + 1]!.startsWith("/")) secrets.push(argv[rp + 1]!);
  if (systemToolName(argv[0] ?? "") === "net") {
    const at = argv.indexOf(VERAX_SVC);
    const next = argv[at + 1];
    if (at >= 0 && next && !next.startsWith("/")) secrets.push(next);
  }
  return secrets;
}

function stderrHasErrorMark(stderr: string): boolean {
  return stderr.split(/\r?\n/).some((line) => line.startsWith(PS_ERROR_MARK));
}

function powershellScriptStep(argv: readonly string[], stdin?: string): boolean {
  if (systemToolName(argv[0] ?? "") !== "powershell") return false;
  if (stdin !== undefined) return true;
  return argv.some((arg) => arg.includes("$ErrorActionPreference = 'Stop'"));
}

function redactSecrets(detail: string, argv: readonly string[], stdin?: string): string {
  let out = detail;
  for (const secret of argvSecrets(argv)) out = out.split(secret).join("[redacted]");
  const line = stdin?.replace(/\r?\n$/, "") ?? "";
  if (line !== "") out = out.split(line).join("[redacted]");
  return out;
}

function parentsOf(dir: string, platform: InstallPlatform): string[] {
  const norm = platform === "win32" ? path.win32.normalize(dir) : path.posix.normalize(dir);
  const root = platform === "win32" ? path.win32.parse(norm).root : "/";
  const dirs: string[] = [];
  let current = norm;
  for (;;) {
    dirs.push(current);
    if (current === root) break;
    const parent = platform === "win32" ? path.win32.dirname(current) : path.posix.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return dirs;
}

function ownerModeLine(platform: InstallPlatform, dir: string, exec: (argv: string[]) => ExecResult): string {
  if (platform === "win32") {
    const ran = exec(toolArgv("powershell", [
      "-NoProfile",
      "-Command",
      `(Get-Acl -LiteralPath '${dir.replaceAll("'", "''")}').Owner`,
    ], "win32"));
    const owner = (ran.stdout ?? "").trim().split(/\r?\n/).filter((line) => line.trim() !== "").pop() ?? (ran.stderr ?? "").trim();
    return `${owner} ntfs ${dir}`;
  }
  const fmt = platform === "darwin" ? ["-f", "%Su|%p|%N", dir] : ["-c", "%U|%a|%n", dir];
  const ran = exec(toolArgv("stat", fmt, platform));
  const text = (ran.stdout ?? "").trim();
  const first = text.indexOf("|");
  const second = text.indexOf("|", first + 1);
  if (first < 0 || second < 0) return `${(ran.stderr || text || "stat failed").trim()} ${dir}`;
  const owner = text.slice(0, first);
  const raw = text.slice(first + 1, second);
  const name = text.slice(second + 1);
  const parsed = Number.parseInt(raw, 8);
  const mode = platform === "darwin" && Number.isFinite(parsed)
    ? (parsed & 0o777).toString(8).padStart(4, "0")
    : raw.padStart(4, "0");
  return `${owner} ${mode} ${name}`;
}

function tailFile(file: string, n: number): string | null {
  try {
    return cappedTail(readFileSync(file, "utf8"), n);
  } catch {
    return null;
  }
}

const NPM_FAIL_TAIL = 80;

/** Last `n` lines. A trailing newline is kept and does not count as an extra line. */
function cappedTail(text: string, n: number): string {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const tail = lines.slice(-n).join("\n");
  return tail === "" ? "" : `${tail}\n`;
}

function newestNpmDebugLog(tempDir: string, platform: InstallPlatform): string | null {
  const p = platform === "win32" ? path.win32 : path.posix;
  const logsDir = p.join(npmConfigPaths(tempDir, platform).cache, "_logs");
  let names: string[];
  try {
    names = readdirSync(logsDir);
  } catch {
    return null;
  }
  let best: { file: string; mtime: number } | null = null;
  for (const name of names) {
    if (!name.endsWith("-debug-0.log")) continue;
    const file = p.join(logsDir, name);
    let mtime = 0;
    try {
      mtime = statSync(file).mtimeMs;
    } catch {
      continue;
    }
    if (!best || mtime >= best.mtime) best = { file, mtime };
  }
  return best?.file ?? null;
}

/**
 * npm stdout+stderr, the newest cache debug log, then the code dir,
 * node_modules when it exists, and the private temp. Windows prints icacls.
 * POSIX prints `ls -ld` and the stat owner/mode line. Called before that temp is removed.
 */
function reportNpmFailure(
  platform: NodeJS.Platform,
  tempDir: string | undefined,
  argv: readonly string[],
  ran: ExecResult,
  exec: ToolExec,
  io: InstallIo,
): void {
  const plat: InstallPlatform = platform === "win32" ? "win32" : platform === "darwin" ? "darwin" : "linux";
  const combined = redactSecrets(`${ran.stdout ?? ""}${ran.stderr ?? ""}`, argv);
  const tail = cappedTail(combined, NPM_FAIL_TAIL);
  if (tail !== "") io.stderr.write(tail);
  if (tempDir) {
    const log = newestNpmDebugLog(tempDir, plat);
    const logged = log ? tailFile(log, NPM_FAIL_TAIL) : null;
    if (logged) io.stderr.write(logged.endsWith("\n") ? logged : `${logged}\n`);
  }
  const prefixAt = argv.indexOf("--prefix");
  const codeDir = prefixAt >= 0 ? (argv[prefixAt + 1] ?? "") : "";
  const pathFor = plat === "win32" ? path.win32 : path.posix;
  const targets: string[] = [];
  if (codeDir !== "") {
    targets.push(codeDir);
    const modules = pathFor.join(codeDir, "node_modules");
    if (existsSync(modules)) targets.push(modules);
  }
  if (tempDir) targets.push(tempDir);
  for (const dir of targets) {
    if (plat === "win32") {
      const acl = exec(toolArgv("icacls", [dir], "win32"));
      const text = `${acl.stdout ?? ""}${acl.stderr ?? ""}`;
      io.stderr.write(text.endsWith("\n") || text === "" ? text : `${text}\n`);
      continue;
    }
    const lsBin = plat === "darwin" ? "/bin/ls" : systemToolPath("ls", plat);
    const ls = exec([lsBin, "-ld", dir]);
    const lsText = `${ls.stdout ?? ""}${ls.stderr ?? ""}`;
    io.stderr.write(lsText.endsWith("\n") || lsText === "" ? lsText : `${lsText}\n`);
    io.stderr.write(`${ownerModeLine(plat, dir, exec)}\n`);
  }
}

function portLines(text: string, port: number): string {
  const re = new RegExp(`:${port}(?!\\d)`);
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").filter((line) => re.test(line));
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
}

/** `ss` or `lsof` at a fixed absolute path. Absent tools are named and skipped. */
function writeListenerTool(
  io: InstallIo,
  exec: (argv: string[]) => ExecResult,
  candidates: readonly string[],
  args: readonly string[],
  port: number,
): void {
  const bin = candidates.find((candidate) => existsSync(candidate));
  if (!bin) {
    io.stderr.write(`not present: ${candidates[0]}\n`);
    return;
  }
  const ran = exec([bin, ...args]);
  io.stderr.write(`${[bin, ...args].join(" ")}\n`);
  const matched = portLines(`${ran.stdout ?? ""}\n${ran.stderr ?? ""}`, port);
  const raw = `${ran.stdout ?? ""}${ran.stderr ?? ""}`;
  const text = matched !== "" ? matched : raw;
  io.stderr.write(text.endsWith("\n") || text === "" ? text : `${text}\n`);
}

/** `getenforce` through the injected exec. A missing binary or a non-zero status is no SELinux. */
function selinuxMode(exec: (argv: string[]) => ExecResult): string | null {
  const ran = exec(toolArgv("getenforce", [], "linux"));
  if ((ran.status ?? 1) !== 0) return null;
  const mode = (ran.stdout ?? "").trim();
  return mode === "" ? null : mode;
}

function serviceMainPid(exec: (argv: string[]) => ExecResult): string | null {
  const ran = exec(toolArgv("systemctl", ["show", "verax", "-p", "MainPID", "--value"], "linux"));
  const pid = (ran.stdout ?? "").trim();
  if ((ran.status ?? 1) !== 0 || !/^[1-9]\d*$/.test(pid)) return null;
  return pid;
}

/** Live label from `ps`, then `/proc/<pid>/attr/current` when ps has nothing. */
function serviceSelinuxLabel(exec: (argv: string[]) => ExecResult): string | null {
  const pid = serviceMainPid(exec);
  if (pid === null) return null;
  const ran = exec(toolArgv("ps", ["-o", "label=", "-p", pid], "linux"));
  const label = (ran.stdout ?? "").trim();
  if ((ran.status ?? 1) === 0 && label.includes(":")) return label;
  try {
    const text = readFileSync(`/proc/${pid}/attr/current`, "utf8").replace(/\0/g, "").trim();
    return text.includes(":") ? text : null;
  } catch {
    return null;
  }
}

function selinuxType(label: string): string {
  return label.split(":")[2] ?? "";
}

/** systemd can only domain-transition from these entrypoint types. `lib_t` is not one of them. */
const SELINUX_NODE_TYPES = new Set(["bin_t", "usr_t"]);

function selinuxNodeFix(node: string): string {
  return `Either install Node from your distribution (dnf install nodejs), or label this one: sudo semanage fcontext -a -t bin_t '${node}' && sudo restorecon -v '${node}'`;
}

function selinuxNodeSentence(node: string, type: string): string {
  return `SELinux is enforcing and ${node} is labelled ${type}; systemd services can only start Node labelled bin_t or usr_t. ${selinuxNodeFix(node)}`;
}

/** `stat -c %C` through the injected exec. Empty when the tool fails or prints no type. */
function selinuxFileType(exec: (argv: string[]) => ExecResult, file: string): string {
  const ran = exec(toolArgv("stat", ["-c", "%C", file], "linux"));
  if ((ran.status ?? 1) !== 0) return "";
  const token = (ran.stdout ?? "").trim().split(/\s+/)[0] ?? "";
  return selinuxType(token);
}

/**
 * Enforcing only, and only before install creates anything.
 * Permissive, Disabled, and a missing getenforce are not a check.
 * Returns the refusal line, or null when the Node label may start a service.
 */
export function linuxSelinuxNodeRefusal(
  exec: (argv: string[]) => ExecResult,
  nodePath: string,
): string | null {
  if (selinuxMode(exec) !== "Enforcing") return null;
  const node = resolveTrustPath(nodePath, "linux");
  const type = selinuxFileType(exec, node);
  const labelled = type === "" ? "unknown" : type;
  if (SELINUX_NODE_TYPES.has(labelled)) return null;
  return `refusing: ${selinuxNodeSentence(node, labelled)}\n`;
}

function labelFromAudit(text: string): string | null {
  const match = /scontext=([^\s]+)/.exec(text);
  const label = match?.[1] ?? "";
  return label.includes(":") ? label : null;
}

function hasExecmemDenial(text: string): boolean {
  return /denied\s*\{[^}\n]*execmem/i.test(text);
}

const EXECMEM_DENIAL_SENTENCE = "SELinux denied execmem to node, so the process could not map executable memory.";

function writeSelinuxSuccess(exec: (argv: string[]) => ExecResult, io: InstallIo): void {
  if (selinuxMode(exec) !== "Enforcing") return;
  const label = serviceSelinuxLabel(exec);
  io.stdout.write(label ? `SELinux context ${label}\n` : "SELinux is Enforcing\n");
}

/**
 * Enforcing only. The process often exits before we can read its pid, so the
 * audit `scontext` is the fallback. ausearch is one argv and no stdin.
 */
function writeSelinuxFailure(exec: (argv: string[]) => ExecResult, io: InstallIo, journalText: string): void {
  if (selinuxMode(exec) !== "Enforcing") return;
  const audit = exec(toolArgv("ausearch", ["--input-logs", "-m", "avc"], "linux"));
  const auditText = `${audit.stdout ?? ""}${audit.stderr ?? ""}`;
  const label = serviceSelinuxLabel(exec) ?? labelFromAudit(journalText) ?? labelFromAudit(auditText);
  io.stderr.write(label ? `SELinux context ${label}\n` : "SELinux is Enforcing\n");
  if (hasExecmemDenial(journalText) || hasExecmemDenial(auditText)) {
    io.stderr.write(`${EXECMEM_DENIAL_SENTENCE}\n`);
  }
}

/** Linux doctor line: the SELinux mode, and when enforcing the service domain. `init_t` is a warning. */
export function linuxSelinuxCheck(
  exec: (argv: string[]) => ExecResult = defaultExec,
): { id: string; level: "ok" | "warn"; detail: string } {
  const mode = selinuxMode(exec);
  if (mode === null) return { id: "selinux", level: "ok", detail: "SELinux is not present" };
  if (mode !== "Enforcing") return { id: "selinux", level: "ok", detail: `SELinux is ${mode}` };
  const label = serviceSelinuxLabel(exec);
  if (label === null) return { id: "selinux", level: "ok", detail: "SELinux is Enforcing; service domain is unknown" };
  const domain = selinuxType(label);
  return {
    id: "selinux",
    level: domain === "init_t" ? "warn" : "ok",
    detail: `SELinux is Enforcing; service domain is ${domain === "" ? label : domain}`,
  };
}

/**
 * Linux doctor line for the Node binary this process runs.
 * Enforcing prints the type and warns when it is not `bin_t` or `usr_t`.
 * Any other mode is not a check.
 */
export function linuxNodeLabelCheck(
  exec: (argv: string[]) => ExecResult = defaultExec,
  nodePath: string = process.execPath,
): { id: string; level: "ok" | "warn"; detail: string } | null {
  if (selinuxMode(exec) !== "Enforcing") return null;
  const node = resolveTrustPath(nodePath, "linux");
  const type = selinuxFileType(exec, node);
  const labelled = type === "" ? "unknown" : type;
  if (SELINUX_NODE_TYPES.has(labelled)) {
    return { id: "selinux-node", level: "ok", detail: `SELinux is Enforcing; Node ${node} is labelled ${labelled}` };
  }
  return {
    id: "selinux-node",
    level: "warn",
    detail: `SELinux is Enforcing; Node ${node} is labelled ${labelled}; systemd services can only start Node labelled bin_t or usr_t. ${selinuxNodeFix(node)}`,
  };
}

function reportHealthTimeout(
  platform: NodeJS.Platform,
  stateDir: string,
  port: number,
  exec: (argv: string[]) => ExecResult,
  io: InstallIo,
): void {
  const plat: InstallPlatform = platform === "win32" ? "win32" : platform === "darwin" ? "darwin" : "linux";
  const status =
    plat === "darwin"
      ? toolArgv("launchctl", ["print", `system/${DARWIN_LABEL}`], "darwin")
      : plat === "linux"
        ? toolArgv("systemctl", ["status", "verax", "--no-pager"], "linux")
        : toolArgv("schtasks", ["/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST"], "win32");
  const ran = exec(status);
  io.stderr.write(`${status.join(" ")}\n`);
  io.stderr.write(`${ran.stdout ?? ""}${ran.stderr ?? ""}`);
  if (!`${ran.stdout ?? ""}${ran.stderr ?? ""}`.endsWith("\n")) io.stderr.write("\n");
  if (plat === "darwin") {
    const errFile = path.posix.join(stateDir, "body.err");
    const tail = tailFile(errFile, 40);
    io.stderr.write(tail === null ? `stderr log missing: ${errFile}\n` : `${tail.endsWith("\n") ? tail : `${tail}\n`}`);
  } else if (plat === "linux") {
    const journal = toolArgv("journalctl", ["-u", "verax", "-n", "40", "--no-pager"], "linux");
    const logged = exec(journal);
    const journalText = `${logged.stdout ?? ""}${logged.stderr ?? ""}`;
    io.stderr.write(`${journal.join(" ")}\n`);
    io.stderr.write(journalText);
    if (!journalText.endsWith("\n")) io.stderr.write("\n");
    writeSelinuxFailure(exec, io, journalText);
  }
  const logPath = (plat === "win32" ? path.win32 : path.posix).join(stateDir, "body.log");
  const bodyTail = tailFile(logPath, 60);
  io.stderr.write(bodyTail === null ? `body.log missing: ${logPath}\n` : bodyTail.endsWith("\n") || bodyTail === "" ? bodyTail : `${bodyTail}\n`);
  if (plat === "win32") {
    const netstat = path.win32.join(windowsSystemRoot(), "System32", "NETSTAT.EXE");
    const listed = exec([netstat, "-ano", "-p", "tcp"]);
    io.stderr.write(`${netstat} -ano -p tcp\n`);
    const matched = portLines(`${listed.stdout ?? ""}\n${listed.stderr ?? ""}`, port);
    io.stderr.write(matched === "" ? "(no netstat line for the port)\n" : matched);
    const tasklist = path.win32.join(windowsSystemRoot(), "System32", "TASKLIST.EXE");
    const tasks = exec([tasklist, "/v", "/fi", "USERNAME eq verax-svc"]);
    io.stderr.write(`${tasklist} /v /fi "USERNAME eq verax-svc"\n`);
    const taskText = `${tasks.stdout ?? ""}${tasks.stderr ?? ""}`;
    io.stderr.write(taskText.endsWith("\n") || taskText === "" ? taskText : `${taskText}\n`);
  } else if (plat === "linux") {
    writeListenerTool(io, exec, ["/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss"], ["-ltnp"], port);
  } else {
    writeListenerTool(io, exec, ["/usr/sbin/lsof", "/usr/bin/lsof"], [`-iTCP:${port}`], port);
  }
  for (const dir of parentsOf(stateDir, plat)) {
    io.stderr.write(`${ownerModeLine(plat, dir, exec)}\n`);
  }
}

function mkdirNewChain(dir: string, platform: InstallPlatform): string[] {
  const p = platform === "win32" ? path.win32 : path.posix;
  const root = platform === "win32" ? path.win32.parse(dir).root : "/";
  const missing: string[] = [];
  let cur = dir;
  while (cur !== root && !existsSync(cur)) {
    missing.push(cur);
    const parent = p.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  const created: string[] = [];
  for (const next of missing.reverse()) {
    mkdirSync(next, { mode: 0o755 });
    created.push(next);
  }
  return created;
}

/**
 * Create the install scratch directory, refuse a planted path or reparse point,
 * and lock the Windows DACL to Administrators + SYSTEM before any file is written.
 * Returns an error sentence, or the parent directories this call created.
 */
function applyPrivateTemp(
  step: Extract<PlanOp, { op: "private-temp" }>,
  exec: ToolExec,
  platform: NodeJS.Platform,
): { error: string } | { parents: string[] } {
  const plat: InstallPlatform = platform === "win32" ? "win32" : platform === "darwin" ? "darwin" : "linux";
  const parent = plat === "win32" ? path.win32.dirname(step.path) : path.posix.dirname(step.path);
  if (existsSync(parent) && pathIsReparse(parent, exec, platform)) {
    return { error: `refusing: ${parent} is a reparse point\n` };
  }
  if (existsSync(step.path) || pathIsReparse(step.path, exec, platform)) {
    const why = pathIsReparse(step.path, exec, platform) ? "is a reparse point" : "already exists";
    return { error: `refusing: ${step.path} ${why}\n` };
  }
  const parents = existsSync(parent) ? [] : mkdirNewChain(parent, plat);
  mkdirSync(step.path, { mode: step.mode ?? 0o700 });
  if (pathIsReparse(step.path, exec, platform)) {
    rmSync(step.path, { recursive: true, force: true });
    return { error: `refusing: ${step.path} is a reparse point\n` };
  }
  if (plat === "win32") {
    const owner = exec(toolArgv("icacls", [step.path, "/setowner", step.owner ?? ADMINISTRATORS_SID], "win32"), undefined, systemToolEnv("win32", step.path));
    const grant = exec(toolArgv("icacls", [
      step.path,
      "/inheritance:r",
      "/grant:r",
      `${ADMINISTRATORS_SID}:(OI)(CI)F`,
      "/grant:r",
      `${SYSTEM_SID}:(OI)(CI)F`,
    ], "win32"), undefined, systemToolEnv("win32", step.path));
    const reset = exec(toolArgv("icacls", windowsResetInheritArgs(step.path), "win32"), undefined, systemToolEnv("win32", step.path));
    const resetOk = (reset.status ?? 1) === 0 || directoryIsEmpty(step.path);
    if ((owner.status ?? 1) !== 0 || (grant.status ?? 1) !== 0 || !resetOk) {
      rmSync(step.path, { recursive: true, force: true });
      const detail = (owner.stderr || owner.stdout || grant.stderr || grant.stdout || reset.stderr || reset.stdout || "icacls failed").trim();
      return { error: `icacls failed: ${detail}\n` };
    }
    return { parents };
  }
  try {
    chmodSync(step.path, 0o700);
  } catch {
    // Windows does not honour the mode bit. POSIX install is already root.
  }
  const spec = plat === "darwin" ? "darwin" : "linux";
  const ownerName = plat === "darwin" ? "root:wheel" : "root:root";
  const chowned = exec(toolArgv("chown", [ownerName, step.path], spec));
  const chmodded = exec(toolArgv("chmod", ["0700", step.path], spec));
  if ((chowned.status ?? 1) !== 0 || (chmodded.status ?? 1) !== 0) {
    rmSync(step.path, { recursive: true, force: true });
    const detail = (chowned.stderr || chmodded.stderr || "chown failed").trim();
    return { error: `${detail || "private temp ownership failed"}\n` };
  }
  return { parents };
}

function removeEmptyDirs(dirs: readonly string[]): void {
  for (const dir of [...dirs].reverse()) {
    try {
      if (readdirSync(dir).length === 0) rmSync(dir, { recursive: false, force: true });
    } catch {
      // Already gone, or not empty because a later step wrote there.
    }
  }
}

const COPY_ATTEMPTS = 10;
const COPY_WAIT_MS = 500;
const COPY_RETRY_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);

function waitMs(ms: number): void {
  if (ms <= 0) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Check-time sha256. Sharing violations (antivirus) retry like the later copy. */
export function hashFileWithRetry(
  file: string,
  read: (file: string) => Buffer | string,
  io: { stderr: { write: (chunk: string) => void } },
  pauseMs = COPY_WAIT_MS,
): { ok: true; sha256: string } | { ok: false; error: string } {
  let retries = 0;
  let code = "";
  let message = "hash failed";
  for (let attempt = 1; attempt <= COPY_ATTEMPTS; attempt += 1) {
    try {
      const sha256 = createHash("sha256").update(read(file)).digest("hex");
      if (retries > 0) io.stderr.write(`retried ${file}\n`);
      return { ok: true, sha256 };
    } catch (err) {
      code = (err as NodeJS.ErrnoException).code ?? "";
      message = (err as Error).message || code || "hash failed";
      if (!COPY_RETRY_CODES.has(code) || attempt === COPY_ATTEMPTS) {
        return { ok: false, error: `could not hash ${file}: ${code} ${message}\n` };
      }
      retries += 1;
      waitMs(pauseMs);
    }
  }
  return { ok: false, error: `could not hash ${file}: ${code} ${message}\n` };
}

function hashTarballDigests(
  files: readonly string[],
  io: InstallIo,
): { digests: { file: string; sha256: string }[] } | { error: string } {
  const digests: { file: string; sha256: string }[] = [];
  for (const file of files) {
    const hashed = hashFileWithRetry(file, readFileSync, io);
    if (!hashed.ok) return { error: hashed.error };
    digests.push({ file, sha256: hashed.sha256 });
  }
  return { digests };
}

/** Copy each trusted tarball into the private temp. Retry sharing violations. The copy's sha256 must match the trust-check hash. */
export function stageTarballCopies(
  files: readonly { source: string; sha256: string; dest: string }[],
  copyFile: (source: string, dest: string) => void,
  io: { stderr: { write: (chunk: string) => void } },
  pauseMs = COPY_WAIT_MS,
): { ok: true } | { ok: false; error: string } {
  for (const file of files) {
    let retries = 0;
    let copied = false;
    let last = "copy failed";
    for (let attempt = 1; attempt <= COPY_ATTEMPTS; attempt += 1) {
      try {
        copyFile(file.source, file.dest);
        copied = true;
        break;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code ?? "";
        last = (err as Error).message || code || "copy failed";
        if (!COPY_RETRY_CODES.has(code) || attempt === COPY_ATTEMPTS) {
          return { ok: false, error: `copy failed: ${file.source}: ${last}\n` };
        }
        retries += 1;
        waitMs(pauseMs);
      }
    }
    if (!copied) return { ok: false, error: `copy failed: ${file.source}: ${last}\n` };
    if (retries > 0) io.stderr.write(`retried ${file.source}\n`);
    let got = "";
    try {
      got = createHash("sha256").update(readFileSync(file.dest)).digest("hex");
    } catch {
      return { ok: false, error: `copy failed: ${file.dest} cannot be read\n` };
    }
    if (got.toLowerCase() !== file.sha256.toLowerCase()) {
      return { ok: false, error: `${file.source} changed after the trust check\n` };
    }
  }
  return { ok: true };
}

function applyLockRoot(
  step: Extract<PlanOp, { op: "lock-root" }>,
  exec: ToolExec,
): { error: string } | { ok: true } {
  const root = step.path;
  if (step.create) {
    const parent = path.win32.dirname(root);
    if (parent !== root && !existsSync(parent)) mkdirSync(parent, { recursive: true });
    try {
      mkdirSync(root);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") {
        return { error: `refusing: ${root} was not created by verax install\n` };
      }
      const message = err instanceof Error ? err.message : "mkdir failed";
      return { error: `refusing: ${root} ${message}\n` };
    }
  }
  const env = systemToolEnv("win32");
  const owner = exec(toolArgv("icacls", [root, "/setowner", ADMINISTRATORS_SID], "win32"), undefined, env);
  const grant = exec(toolArgv("icacls", [
    root,
    "/inheritance:r",
    "/grant:r",
    `${ADMINISTRATORS_SID}:(OI)(CI)F`,
    "/grant:r",
    `${SYSTEM_SID}:(OI)(CI)F`,
  ], "win32"), undefined, env);
  if ((owner.status ?? 1) !== 0 || (grant.status ?? 1) !== 0) {
    if (step.create) rmSync(root, { recursive: true, force: true });
    const detail = (owner.stderr || owner.stdout || grant.stderr || grant.stdout || "icacls failed").trim();
    return { error: `icacls failed: ${detail}\n` };
  }
  if (step.create) {
    let names: string[] = [];
    try {
      names = readdirSync(root);
    } catch {
      names = ["unreadable"];
    }
    if (names.length > 0) {
      const child = path.win32.join(root, names[0] ?? "");
      rmSync(root, { recursive: true, force: true });
      return { error: `refusing: ${child} appeared in ${root}\n` };
    }
  }
  const read = exec(windowsSddlArgv(root), undefined, env);
  const text = `${read.stdout ?? ""}\n${read.stderr ?? ""}`;
  if ((read.status ?? 1) !== 0 || rootDaclRejected(text)) {
    if (step.create) rmSync(root, { recursive: true, force: true });
    return { error: `refusing: ${root} was not created by verax install\n` };
  }
  return { ok: true };
}

function directoryIsEmpty(dir: string): boolean {
  try {
    return readdirSync(dir).length === 0;
  } catch {
    return false;
  }
}

/** `icacls <dir>\* /reset /T /C`. Null when this argv is not that reset. */
function inheritResetDir(argv: readonly string[]): string | null {
  if (!argv.includes("/reset")) return null;
  const star = argv.find((arg) => arg.endsWith("\\*") || arg.endsWith("/*"));
  return star ? star.slice(0, -2) : null;
}

/** Files whose DACL must match the directory grant. Missing files are skipped by the caller. */
export function serviceAclFiles(root: string, kind: "code" | "state"): string[] {
  if (kind === "code") {
    return [path.win32.join(root, "node_modules", "@verax-ai", "body", "package.json")];
  }
  const files = [
    path.win32.join(root, "local-issuer", "key.pem"),
    path.win32.join(root, "verax.env"),
  ];
  const keysDir = path.win32.join(root, "keys");
  try {
    for (const name of readdirSync(keysDir)) {
      const full = path.win32.join(keysDir, name);
      try {
        if (statSync(full).isFile()) files.push(full);
      } catch {
        // A name that vanished between listing and stat is not an ACL to check.
      }
    }
  } catch {
    // No keys directory yet.
  }
  return files;
}

function serviceGrantKind(argv: readonly string[]): "code" | "state" | null {
  for (const arg of argv) {
    const match = /^\*S-1-[0-9-]+:\(OI\)\(CI\)(RX|F)$/.exec(arg);
    if (!match) continue;
    return match[1] === "RX" ? "code" : "state";
  }
  return null;
}

type CreatedThisRun = {
  linuxUser: boolean;
  linuxGroup: boolean;
  linuxService: boolean;
  darwinUser: boolean;
  darwinGroup: boolean;
  darwinService: boolean;
  winAccount: boolean;
  winTask: boolean;
  codeDir: boolean;
  stateDir: boolean;
  serviceFile: string;
};

function rememberCreatedAccount(created: CreatedThisRun, argv: readonly string[]): void {
  const tool = systemToolName(argv[0] ?? "");
  if (tool === "useradd" && argv[argv.length - 1] === "verax") {
    created.linuxUser = true;
    if (!argv.includes("-N") && !argv.includes("--no-user-group")) created.linuxGroup = true;
  }
  if (tool === "dscl" && argv.includes("-create")) {
    if (argv.includes(`/Users/${DARWIN_USER}`)) created.darwinUser = true;
    if (argv.includes(`/Groups/${DARWIN_USER}`)) created.darwinGroup = true;
  }
  if (tool === "powershell" && argv.some((arg) => arg.includes("New-LocalUser"))) created.winAccount = true;
  if (tool === "powershell" && argv.some((arg) => arg.includes("Register-ScheduledTask"))) created.winTask = true;
  if (tool === "launchctl" && argv.includes("bootstrap")) created.darwinService = true;
  if (tool === "systemctl" && argv.includes("enable") && argv.includes("--now")) created.linuxService = true;
}

function removeRollbackPath(target: string, io: InstallIo): void {
  try {
    rmSync(target, { recursive: true, force: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "remove failed";
    io.stderr.write(`rm exit 1: ${message}\n`);
  }
}

/**
 * Drop what this run created after a failed install.
 * The Linux marker lives in the code dir, so rolling that dir back forgets
 * `createdUser` unless the login useradd just made is removed too.
 * macOS `_verax` and Windows `verax-svc` follow the same rule: only an account
 * this run created is removed.
 */
function rollbackCreatedThisRun(
  created: CreatedThisRun,
  plan: { codeDir: string; stateDir: string },
  call: ToolExec,
  io: InstallIo,
): void {
  const ignore = (argv: string[]): void => {
    call(argv);
  };
  const best = (argv: string[]): void => {
    const ran = call(argv);
    if ((ran.status ?? 1) === 0 || toolAlreadyAbsent(ran)) return;
    reportToolFailure(io, argv, ran);
  };
  if (created.linuxService || created.linuxUser) ignore(toolArgv("systemctl", ["disable", "--now", "verax"], "linux"));
  if (created.darwinService) ignore(toolArgv("launchctl", ["bootout", `system/${DARWIN_LABEL}`], "darwin"));
  if (created.winTask) {
    ignore(toolArgv("schtasks", ["/End", "/TN", TASK_NAME], "win32"));
    ignore(toolArgv("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"], "win32"));
  }
  if (created.linuxUser) best(toolArgv("userdel", ["verax"], "linux"));
  if (created.linuxGroup) best(toolArgv("groupdel", ["verax"], "linux"));
  if (created.darwinUser) best(toolArgv("dscl", [".", "-delete", `/Users/${DARWIN_USER}`], "darwin"));
  if (created.darwinGroup) best(toolArgv("dscl", [".", "-delete", `/Groups/${DARWIN_USER}`], "darwin"));
  if (created.winAccount) best(toolArgv("net", ["user", VERAX_SVC, "/delete"], "win32"));
  if (created.serviceFile !== "") removeRollbackPath(created.serviceFile, io);
  if (created.stateDir) removeRollbackPath(plan.stateDir, io);
  if (created.codeDir) removeRollbackPath(plan.codeDir, io);
}

async function execute(
  plan: Extract<InstallPlan, { ok: true }>,
  exec: ToolExec,
  io: InstallIo,
  platform: NodeJS.Platform,
  copyFile: (source: string, dest: string) => void = copyFileSync,
  installEnv?: NodeJS.ProcessEnv,
  healthTimeoutMs?: number,
): Promise<number> {
  const tempStep = plan.ops.find((op): op is Extract<PlanOp, { op: "private-temp" }> => op.op === "private-temp");
  const tempDir = tempStep?.path;
  const call: ToolExec = (argv, stdin, env, cwd) => {
    if (env) return exec(argv, stdin, env, cwd);
    if (!tempDir) return exec(argv, stdin, undefined, cwd);
    return exec(argv, stdin, systemToolEnv(platform, tempDir), cwd);
  };
  let svcSid = "";
  const serviceArgv = (argv: string[]): string[] | { error: string } => {
    if (!argv.some((arg) => arg.startsWith(`${VERAX_SVC}:`))) return argv;
    if (svcSid === "") {
      const ran = call(toolArgv("powershell", [
        "-NoProfile",
        "-Command",
        "(Get-LocalUser -Name 'verax-svc').SID.Value",
      ], "win32"));
      svcSid = (ran.stdout ?? "").match(/S-1-[0-9-]+/)?.[0] ?? "";
      if (svcSid === "") return { error: "verax-svc has no SID\n" };
    }
    return argv.map((arg) => (arg.startsWith(`${VERAX_SVC}:`) ? `*${svcSid}${arg.slice(VERAX_SVC.length)}` : arg));
  };
  const createdTemps: string[] = [];
  const createdParents: string[] = [];
  const created: CreatedThisRun = {
    linuxUser: false,
    linuxGroup: false,
    linuxService: false,
    darwinUser: false,
    darwinGroup: false,
    darwinService: false,
    winAccount: false,
    winTask: false,
    codeDir: false,
    stateDir: false,
    serviceFile: "",
  };
  let status = 0;
  const finish = (code: number): number => {
    status = code;
    return code;
  };
  try {
  for (const step of plan.ops) {
    if (step.op === "private-temp") {
      const applied = applyPrivateTemp(step, call, platform);
      if ("error" in applied) {
        io.stderr.write(applied.error.endsWith("\n") ? applied.error : `${applied.error}\n`);
        return finish(EX_CONFIG);
      }
      createdParents.push(...applied.parents);
      createdTemps.push(step.path);
      continue;
    }
    if (step.op === "stage-tarballs") {
      const staged = stageTarballCopies(step.files, copyFile, io);
      if (!staged.ok) {
        io.stderr.write(staged.error.endsWith("\n") ? staged.error : `${staged.error}\n`);
        return finish(EX_CONFIG);
      }
      continue;
    }
    if (step.op === "mkdir") {
      const existed = existsSync(step.path);
      mkdirLeaf(step.path, step.mode ?? 0o755);
      if (!existed && step.path === plan.codeDir) created.codeDir = true;
      if (!existed && step.path === plan.stateDir) created.stateDir = true;
      continue;
    }
    if (step.op === "manifest") {
      writeManifest(step.dir);
      continue;
    }
    if (step.op === "lock-root") {
      const applied = applyLockRoot(step, call);
      if ("error" in applied) {
        io.stderr.write(applied.error.endsWith("\n") ? applied.error : `${applied.error}\n`);
        return finish(EX_CONFIG);
      }
      continue;
    }
    if (step.op === "argv") {
      const resolved = serviceArgv(step.argv);
      if ("error" in resolved) {
        io.stderr.write(resolved.error.endsWith("\n") ? resolved.error : `${resolved.error}\n`);
        return finish(EX_CONFIG);
      }
      const ran = call(resolved, step.stdin, step.env, step.cwd);
      if (powershellScriptStep(resolved, step.stdin)) {
        const failed = (ran.status ?? 1) !== 0 || stderrHasErrorMark(ran.stderr ?? "");
        if (failed && !step.optional) {
          if (step.rollbackDir) rmSync(step.rollbackDir, { recursive: true, force: true });
          const detail = redactSecrets(ran.stderr ?? "", step.argv, step.stdin).trim();
          const code = ran.status ?? 1;
          const tool = systemToolName(resolved[0] ?? "") || "powershell";
          io.stderr.write(`${tool} exit ${code}${detail ? `: ${detail}` : ""}\n`);
          if (ran.status === EX_CONFIG) return finish(EX_CONFIG);
          return finish(1);
        }
        if (!failed) rememberCreatedAccount(created, resolved);
        continue;
      }
      if (isNpmArgv(resolved) && (ran.status ?? 1) !== 0 && !step.optional) {
        reportNpmFailure(platform, tempDir, resolved, ran, call, io);
        if (ran.status !== EX_CONFIG && step.rollbackDir) rmSync(step.rollbackDir, { recursive: true, force: true });
        const code = ran.status ?? 1;
        const detail = redactSecrets((ran.stderr || ran.stdout || "").trim(), step.argv, step.stdin);
        io.stderr.write(`npm exit ${code}${detail ? `: ${detail.split("\n")[0]}` : ""}\n`);
        if (ran.status === EX_CONFIG) return finish(EX_CONFIG);
        return finish(1);
      }
      if (ran.status === EX_CONFIG && !step.optional) {
        io.stderr.write(`${redactSecrets((ran.stderr || ran.stdout || "").trim(), step.argv, step.stdin)}\n`);
        return finish(EX_CONFIG);
      }
      if ((ran.status ?? 1) !== 0 && !step.optional) {
        const resetDir = inheritResetDir(resolved);
        if (resetDir !== null && directoryIsEmpty(resetDir)) continue;
        if (step.rollbackDir) rmSync(step.rollbackDir, { recursive: true, force: true });
        const detail = redactSecrets((ran.stderr || ran.stdout || "").trim(), step.argv, step.stdin);
        const code = ran.status ?? 1;
        const tool = step.argv.includes("signatures")
          ? "npm"
          : step.argv.includes("--omit=dev")
            ? "npm"
            : (systemToolName(step.argv[0] ?? "") || (step.argv[0] ?? "command"));
        io.stderr.write(`${tool} exit ${code}${detail ? `: ${detail.split("\n")[0]}` : ""}\n`);
        return finish(1);
      }
      const grantKind = platform === "win32" ? serviceGrantKind(resolved) : null;
      if (grantKind) {
        const target = resolved[1] ?? "";
        const files = serviceAclFiles(target, grantKind).filter((file) => existsSync(file));
        const readBack = readSddlBatch(call, [target, ...files]);
        const read = sddlOrMiss(readBack, target);
        const text = read.text;
        const verdict = verifyServiceAcl(text, grantKind, { dir: target, svcSid });
        if (read.status !== 0 || !verdict.ok) {
          const detail = verdict.ok ? (text.trim() || "icacls failed") : verdict.detail;
          io.stderr.write(detail.endsWith("\n") ? detail : `${detail}\n`);
          return finish(EX_CONFIG);
        }
        for (const file of files) {
          const fileRead = sddlOrMiss(readBack, file);
          const fileVerdict = verifyServiceAcl(fileRead.text, grantKind, { dir: file, svcSid, file });
          if (fileRead.status !== 0 || !fileVerdict.ok) {
            const detail = fileVerdict.ok ? `empty ACL on ${file}` : fileVerdict.detail;
            io.stderr.write(detail.endsWith("\n") ? detail : `${detail}\n`);
            return finish(EX_CONFIG);
          }
        }
      }
      if (platform === "win32" && resolved.includes("/setowner") && resolved.includes("/T") && (resolved[1] ?? "") === plan.stateDir) {
        const files = serviceAclFiles(plan.stateDir, "state").filter((file) => existsSync(file));
        const readBack = readSddlBatch(call, files);
        for (const file of files) {
          const fileRead = sddlOrMiss(readBack, file);
          const fileVerdict = verifyServiceAcl(fileRead.text, "state", { dir: file, svcSid, file });
          if (fileRead.status !== 0 || !fileVerdict.ok) {
            const detail = fileVerdict.ok ? `empty ACL on ${file}` : fileVerdict.detail;
            io.stderr.write(detail.endsWith("\n") ? detail : `${detail}\n`);
            return finish(EX_CONFIG);
          }
        }
      }
      const expected = registryBodyVersion(resolved);
      if (expected && resolved.includes("install") && resolved.includes("--prefix")) {
        const codeDir = resolved[resolved.indexOf("--prefix") + 1] ?? "";
        const problem = verifyRegistryInstall(codeDir, expected);
        if (problem) {
          if (step.rollbackDir) rmSync(step.rollbackDir, { recursive: true, force: true });
          io.stderr.write(`${problem}\n`);
          return finish(1);
        }
      }
      rememberCreatedAccount(created, resolved);
      continue;
    }
    if (step.op === "write") {
      const service = step.path.endsWith("/verax.service") || step.path.endsWith("/com.verax-ai.body.plist");
      const priorService = service && existsSync(step.path);
      mkdirSync(path.dirname(step.path), { recursive: true });
      writeFileSync(step.path, step.contents, { encoding: "utf8", mode: step.mode ?? 0o644, flag: step.exclusive ? "wx" : "w" });
      if (service && !priorService) created.serviceFile = step.path;
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
        { tokenPath: step.tokenPath, quiet: true, noOwnerGrant: step.noOwnerGrant, env: installEnv },
      );
      if (code !== 0) return finish(code);
      continue;
    }
    if (step.op === "remove") {
      rmSync(step.path, { recursive: true, force: true });
      continue;
    }
    if (step.op === "wait-healthz") {
      if (!(await waitHealth(step.port, healthTimeoutMs ?? step.timeoutMs, io))) {
        io.stderr.write(`install-health-timeout:${step.port}\n`);
        reportHealthTimeout(platform, plan.stateDir, step.port, call, io);
        return finish(1);
      }
      if (platform === "linux") writeSelinuxSuccess(call, io);
      continue;
    }
    io.stdout.write(step.text.endsWith("\n") ? step.text : `${step.text}\n`);
  }
  return finish(0);
  } catch (err) {
    if (status === 0) status = 1;
    throw err;
  } finally {
    if (status !== 0) rollbackCreatedThisRun(created, plan, call, io);
    for (const dir of createdTemps) rmSync(dir, { recursive: true, force: true });
    if (status !== 0) removeEmptyDirs(createdParents);
  }
}

function invokingEnv(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  exec: (argv: string[]) => ExecResult,
): { env: NodeJS.ProcessEnv; invokingHome?: string } | { error: string } {
  const given = env.VERAX_INVOKING_HOME?.trim() ?? "";
  if (platform === "linux") {
    const user = env.SUDO_USER?.trim() ?? "";
    if (user === "") return { env };
    const looked = exec(toolArgv("getent", ["passwd", user], "linux"));
    const home = (looked.stdout ?? "").split(":")[5]?.trim() ?? "";
    if (looked.status === 0 && home !== "") {
      if (given !== "" && given !== home) {
        return { error: `refusing: VERAX_INVOKING_HOME ${given} is not the home ${home}` };
      }
      return { env: { ...env, VERAX_INVOKING_HOME: home }, invokingHome: home };
    }
    return { error: `verax install could not read the home of ${user} from getent` };
  }
  if (platform === "darwin") {
    const user = env.SUDO_USER?.trim() ?? "";
    if (user === "") return { env };
    const looked = exec(toolArgv("dscl", [".", "-read", `/Users/${user}`, "NFSHomeDirectory"], "darwin"));
    const home = (looked.stdout ?? "").match(/NFSHomeDirectory:\s*(\S+)/)?.[1] ?? "";
    if (looked.status === 0 && home !== "") {
      if (given !== "" && given !== home) {
        return { error: `refusing: VERAX_INVOKING_HOME ${given} is not the home ${home}` };
      }
      return { env: { ...env, VERAX_INVOKING_HOME: home }, invokingHome: home };
    }
    return { error: `verax install could not read the home of ${user} from dscl` };
  }
  return { env };
}

function installMarkerText(
  opts: PlanOpts,
  paths: Paths,
  extra?: { createdAccount?: boolean; createdUser?: boolean; createdGroup?: boolean },
): string {
  const body: Record<string, unknown> = {
    version: opts.bodyVersion,
    codeDir: paths.codeDir,
    stateDir: paths.stateDir,
    installedAt: new Date().toISOString(),
    source: opts.fromTarballs ? "tarballs" : "registry",
  };
  if (extra?.createdAccount) body.createdAccount = true;
  if (extra?.createdUser) body.createdUser = true;
  if (extra?.createdGroup) body.createdGroup = true;
  return `${JSON.stringify(body, null, 2)}\n`;
}

function posixPresence(dir: string): { exists: boolean; symlink: boolean } {
  try {
    return { exists: true, symlink: lstatSync(dir).isSymbolicLink() };
  } catch {
    return { exists: false, symlink: false };
  }
}

function usedDarwinIds(text: string): Set<number> {
  const used = new Set<number>();
  for (const line of text.split(/\r?\n/)) {
    const match = /(\d+)\s*$/.exec(line.trim());
    if (match) used.add(Number(match[1]));
  }
  return used;
}

function firstFreeDarwinId(used: Set<number>): number | null {
  for (let n = 200; n <= 400; n += 1) if (!used.has(n)) return n;
  return null;
}

function pickDarwinAccount(
  exec: (argv: string[]) => ExecResult,
  flags: { createdUser: boolean; createdGroup: boolean },
): NonNullable<PlanOpts["darwinAccount"]> | { error: string } {
  const user = exec(toolArgv("id", ["-u", DARWIN_USER], "darwin"));
  const userExists = user.status === 0;
  if (userExists && !flags.createdUser) {
    return { error: `refusing: ${DARWIN_USER} already exists and was not created by verax install` };
  }
  const group = exec(toolArgv("dscl", [".", "-read", `/Groups/${DARWIN_USER}`, "PrimaryGroupID"], "darwin"));
  const groupExists = group.status === 0;
  if (groupExists && !flags.createdGroup) {
    return { error: `refusing: group ${DARWIN_USER} already exists and was not created by verax install` };
  }
  let uid = 280;
  let gid = 280;
  if (!userExists) {
    const listed = exec(toolArgv("dscl", [".", "-list", "/Users", "UniqueID"], "darwin"));
    if ((listed.status ?? 1) !== 0) return { error: "dscl failed to list user ids" };
    const free = firstFreeDarwinId(usedDarwinIds(listed.stdout ?? ""));
    if (free === null) return { error: "no free UniqueID in 200-400" };
    uid = free;
  } else {
    const read = exec(toolArgv("dscl", [".", "-read", `/Users/${DARWIN_USER}`, "UniqueID"], "darwin"));
    const n = Number((read.stdout ?? "").match(/(\d+)/)?.[1]);
    if (Number.isInteger(n)) uid = n;
  }
  if (!groupExists) {
    const listed = exec(toolArgv("dscl", [".", "-list", "/Groups", "PrimaryGroupID"], "darwin"));
    if ((listed.status ?? 1) !== 0) return { error: "dscl failed to list group ids" };
    const free = firstFreeDarwinId(usedDarwinIds(listed.stdout ?? ""));
    if (free === null) return { error: "no free PrimaryGroupID in 200-400" };
    gid = free;
  } else {
    const n = Number((group.stdout ?? "").match(/(\d+)/)?.[1]);
    if (Number.isInteger(n)) gid = n;
  }
  return {
    uid,
    gid,
    createUser: !userExists,
    createGroup: !groupExists,
    recordUser: !userExists || flags.createdUser,
    recordGroup: !groupExists || flags.createdGroup,
  };
}

function markerFlags(file: string): { createdAccount: boolean; createdUser: boolean; createdGroup: boolean } {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as {
      createdAccount?: unknown;
      createdUser?: unknown;
      createdGroup?: unknown;
    };
    return {
      createdAccount: parsed.createdAccount === true,
      createdUser: parsed.createdUser === true,
      createdGroup: parsed.createdGroup === true,
    };
  } catch {
    return { createdAccount: false, createdUser: false, createdGroup: false };
  }
}

function ourMarker(file: string): boolean {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { version?: unknown; codeDir?: unknown };
    return typeof parsed.version === "string" && typeof parsed.codeDir === "string";
  } catch {
    return false;
  }
}

/** Existing token parent: real directory the agent cannot steal, or a refusal sentence. */
export function tokenParentRefusal(facts: {
  dir: string;
  symlink: boolean;
  directory: boolean;
  reparse: boolean;
  platform: NodeJS.Platform;
  uid: number;
  invokingUid?: number;
  ownerSid?: string;
  invokingSid?: string;
}): string | null {
  if (facts.symlink || facts.reparse) return `refusing: ${facts.dir} is a reparse point`;
  if (!facts.directory) return `refusing: ${facts.dir} is not a directory`;
  if (facts.platform === "win32") {
    const owner = facts.ownerSid?.trim().toUpperCase() ?? "";
    const invoking = facts.invokingSid?.trim().toUpperCase() ?? "";
    if (owner !== "" && (owner === invoking || TRUSTED_FOLDER_OWNER_SIDS.has(owner))) return null;
    return `refusing: ${facts.dir} is not owned by the invoking user`;
  }
  if (facts.uid === 0 || (facts.invokingUid !== undefined && facts.uid === facts.invokingUid)) return null;
  return `refusing: ${facts.dir} is not owned by the invoking user`;
}

/** chown + chmod so the invoking user can read a root-created token folder. */
export function rootOwnedTokenParentArgv(dir: string, invokingUid: number, platform: NodeJS.Platform): string[][] {
  const spec = platform === "darwin" ? "darwin" : "linux";
  return [
    toolArgv("chown", [`${invokingUid}:`, dir], spec),
    toolArgv("chmod", ["0700", dir], spec),
  ];
}

type WinOwnerCache = {
  sidResolved: boolean;
  sid?: string;
  owners: Map<string, string | undefined>;
};

let winOwnerCache: WinOwnerCache | null = null;
let winOwnerDepth = 0;

/** One invoking SID and one owner lookup per path for this install or init run. */
export function beginWinOwnerRun(): void {
  if (winOwnerDepth === 0) winOwnerCache = { sidResolved: false, owners: new Map() };
  winOwnerDepth += 1;
}

export function endWinOwnerRun(): void {
  winOwnerDepth = Math.max(0, winOwnerDepth - 1);
  if (winOwnerDepth === 0) winOwnerCache = null;
}

function directoryOwnerSid(dir: string, exec: (argv: string[]) => ExecResult): string | undefined {
  const cached = winOwnerCache?.owners;
  if (cached?.has(dir)) return cached.get(dir);
  const literal = dir.replaceAll("'", "''");
  const ran = exec(toolArgv("powershell", [
    "-NoProfile",
    "-Command",
    `(Get-Acl -LiteralPath '${literal}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`,
  ], "win32"));
  const sid = (ran.status ?? 1) !== 0 ? undefined : `${ran.stdout ?? ""}`.match(/S-1-[0-9-]+/i)?.[0];
  cached?.set(dir, sid);
  return sid;
}

function sudoUserUid(env: NodeJS.ProcessEnv, exec: (argv: string[]) => ExecResult, platform: NodeJS.Platform): number | undefined {
  const user = env.SUDO_USER?.trim() ?? "";
  if (user === "") return undefined;
  const spec = platform === "darwin" ? "darwin" : "linux";
  const ran = exec(toolArgv("id", ["-u", user], spec));
  if ((ran.status ?? 1) !== 0) return undefined;
  const uid = Number.parseInt((ran.stdout ?? "").trim(), 10);
  return Number.isInteger(uid) ? uid : undefined;
}

/**
 * Create a missing token parent with recursive mkdir.
 * An existing directory must be a real directory, not a symlink or reparse point,
 * owned by the invoking user, Administrators, SYSTEM, or root. A root-owned
 * POSIX directory is chowned to the invoking uid and chmod 0700.
 */
export function ensureTokenParent(
  dir: string,
  env: NodeJS.ProcessEnv = process.env,
  exec: ToolExec = defaultExec,
): void {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
      try {
        chmodSync(dir, 0o700);
      } catch {
        // The platform does not honour the mode bit.
      }
    }
    return;
  }
  const platform = process.platform;
  const reparse = pathIsReparse(dir, exec, platform);
  const owned = !reparse && !st.isSymbolicLink() && st.isDirectory();
  const invokingUid = owned && platform !== "win32" ? sudoUserUid(env, exec, platform) : undefined;
  const reason = tokenParentRefusal({
    dir,
    symlink: st.isSymbolicLink(),
    directory: st.isDirectory(),
    reparse,
    platform,
    uid: st.uid,
    invokingUid,
    ownerSid: owned && platform === "win32" ? directoryOwnerSid(dir, exec) : undefined,
    invokingSid: owned && platform === "win32" ? invokingSid(exec) : undefined,
  });
  if (reason) throw new SystemToolError(reason);
  if (platform !== "win32" && st.uid === 0 && invokingUid !== undefined && invokingUid !== 0) {
    for (const argv of rootOwnedTokenParentArgv(dir, invokingUid, platform)) {
      const ran = exec(argv);
      if ((ran.status ?? 1) !== 0) {
        throw new SystemToolError((ran.stderr || ran.stdout || "chown failed").trim());
      }
    }
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

/** Resolved path: root-owned and not group- or other-writable. The symlink itself is not the object. */
function posixEntryUntrusted(file: string): boolean {
  try {
    const st = lstatSync(file);
    if (st.isSymbolicLink()) return true;
    return st.uid !== 0 || (st.mode & 0o022) !== 0;
  } catch {
    return true;
  }
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
  let sid = winOwnerCache?.sidResolved ? winOwnerCache.sid : undefined;
  if (!winOwnerCache?.sidResolved) {
    const who = spawn(whoami, ["/user", "/fo", "csv", "/nh"], opts);
    if ((who.status ?? 1) !== 0) {
      throw new Error(`whoami failed: ${(who.stderr || who.stdout || "").trim()}`);
    }
    sid = /S-1-[0-9-]+/.exec(who.stdout ?? "")?.[0];
    if (winOwnerCache) {
      winOwnerCache.sidResolved = true;
      winOwnerCache.sid = sid;
    }
  }
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
  if (winOwnerCache?.sidResolved) return winOwnerCache.sid;
  const ran = exec(toolArgv("whoami", ["/user"], "win32"));
  const sid = `${ran.stdout ?? ""}`.match(/S-1-[0-9-]+/)?.[0];
  if (winOwnerCache) {
    winOwnerCache.sidResolved = true;
    winOwnerCache.sid = sid;
  }
  return sid;
}

function markerSource(file: string): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { source?: unknown };
    return typeof parsed.source === "string" ? parsed.source : undefined;
  } catch {
    return undefined;
  }
}

function listedTarballTargets(dirArg: string): { dir: string; files: string[] } | { dir: string; missing: true } | { dir: string; empty: true } {
  const dir = path.resolve(dirArg);
  let names: string[];
  try {
    names = readdirSync(dir).filter((name) => name.endsWith(".tgz"));
  } catch {
    return { dir, missing: true };
  }
  const files = orderTarballs(names.map((name) => path.join(dir, name)));
  if (files.length === 0) return { dir, empty: true };
  return { dir, files };
}

function collectTarballs(
  dirArg: string,
  platform: NodeJS.Platform,
  exec: (argv: string[]) => ExecResult,
  io: InstallIo,
  sddl: Map<string, SddlHit> | null = null,
): { dir: string; files: string[]; digests: { file: string; sha256: string }[]; icacls?: string; modes?: { uid: number; mode: number }[] } | { error: true; code: number } {
  const listed = listedTarballTargets(dirArg);
  if ("missing" in listed) {
    io.stderr.write(`--from-tarballs ${listed.dir} is not a directory\n`);
    return { error: true, code: EX_CONFIG };
  }
  if ("empty" in listed) {
    io.stderr.write(`--from-tarballs ${listed.dir} has no tarballs\n`);
    return { error: true, code: EX_CONFIG };
  }
  const { dir, files } = listed;
  const targets = [dir, ...files];
  if (platform === "win32") {
    const sid = invokingSid(exec);
    const chunks: string[] = [];
    for (const file of targets) {
      const acl = sddl?.get(file) ?? { status: 1, text: "" };
      const text = acl.text;
      chunks.push(text);
      const ancestor = file === dir;
      if (acl.status !== 0 || windowsUserCanWrite(text, { path: file, userSid: sid, ancestor })) {
        io.stderr.write(`${refuseAcl(text, tarballTrustMessage(file))}\n`);
        return { error: true, code: EX_CONFIG };
      }
    }
    const hashed = hashTarballDigests(files, io);
    if ("error" in hashed) {
      io.stderr.write(hashed.error.endsWith("\n") ? hashed.error : `${hashed.error}\n`);
      return { error: true, code: EX_CONFIG };
    }
    return { dir, files, digests: hashed.digests, icacls: chunks.join("\n") };
  }
  if (platform === "linux" || platform === "darwin") {
    const modes: { uid: number; mode: number }[] = [];
    for (const file of targets) {
      if (linuxFileUntrusted(file)) {
        io.stderr.write(`${tarballTrustMessage(file)}\n`);
        return { error: true, code: EX_CONFIG };
      }
      const st = statSync(file);
      modes.push({ uid: st.uid, mode: st.mode });
    }
    const hashed = hashTarballDigests(files, io);
    if ("error" in hashed) {
      io.stderr.write(hashed.error.endsWith("\n") ? hashed.error : `${hashed.error}\n`);
      return { error: true, code: EX_CONFIG };
    }
    return { dir, files, digests: hashed.digests, modes };
  }
  io.stderr.write("--from-tarballs is not supported on this operating system\n");
  return { error: true, code: EX_CONFIG };
}

export async function runInstall(argv: readonly string[], hooks: InstallHooks = {}): Promise<number> {
  beginWinOwnerRun();
  try {
  return await runInstallBody(argv, hooks);
  } finally {
    endWinOwnerRun();
  }
}

async function runInstallBody(argv: readonly string[], hooks: InstallHooks = {}): Promise<number> {
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
  const resolvedEnv = invokingEnv(platform, env, exec);
  if ("error" in resolvedEnv) {
    io.stderr.write(`${resolvedEnv.error}\n`);
    return EX_CONFIG;
  }
  const plannedEnv = resolvedEnv.env;
  const invokingHome = resolvedEnv.invokingHome;
  const discovered = hooks.layout ?? discoverLayout(process.execPath, platform);
  if ("error" in discovered) {
    io.stderr.write(`${discovered.error}\n`);
    return EX_CONFIG;
  }
  const layout = discovered;
  const posixRoot = platform === "win32" ? undefined : hooks.posixRoot;
  const fixed = fixedPosix(posixRoot);
  const stateDir = stateDirFor(platform, plannedEnv, posixRoot);
  const exists = hooks.stateExists ? hooks.stateExists(stateDir) : existsSync(stateDir);
  const trustPlat = platform === "win32" || platform === "linux" || platform === "darwin" ? platform as InstallPlatform : null;
  const trustFiles = trustPlat ? [...trustTargets(layout.execPath, trustPlat), ...trustTargets(layout.npmCli, trustPlat)] : [];
  let sddlPlan: Map<string, SddlHit> | null = null;
  if (platform === "win32") {
    const root = path.win32.dirname(stateDir);
    let rootExists = false;
    try {
      lstatSync(root);
      rootExists = true;
    } catch {
      rootExists = false;
    }
    const preview = parsed.fromTarballs ? listedTarballTargets(parsed.fromTarballs) : undefined;
    const tarballPaths = preview && "files" in preview ? [preview.dir, ...preview.files] : [];
    sddlPlan = readSddlBatch(exec, [
      ...trustFiles.map((file) => file.path),
      ...(rootExists ? [root] : []),
      ...tarballPaths,
    ]);
  }
  if (trustPlat) {
    if (platform === "win32") {
      const sid = invokingSid(exec);
      const cache = sddlPlan ?? new Map<string, SddlHit>();
      for (const file of trustFiles) {
        const acl = sddlOrMiss(cache, file.path);
        if (acl.status !== 0 || windowsUserCanWrite(acl.text, { path: file.path, userSid: sid, ancestor: file.ancestor })) {
          io.stderr.write(`${refuseAcl(acl.text, nodeTrustMessage(file.path))}\n`);
          return EX_CONFIG;
        }
      }
    } else {
      for (const file of trustFiles) {
        if (posixEntryUntrusted(file.path)) {
          io.stderr.write(`${nodeTrustMessageFor(file.path, trustPlat)}\n`);
          return EX_CONFIG;
        }
      }
    }
  }
  if (platform === "linux") {
    const refusal = linuxSelinuxNodeRefusal(exec, layout.execPath);
    if (refusal) {
      io.stderr.write(refusal);
      return EX_CONFIG;
    }
  }
  let veraxRootExists = false;
  let markerExists = false;
  let reparsePath: string | undefined;
  let linuxState: PlanOpts["linuxState"];
  let linuxCode: PlanOpts["linuxCode"];
  let winAccount: PlanOpts["winAccount"];
  let linuxAccount: PlanOpts["linuxAccount"];
  let winRootOwner: string | undefined;
  let winRootAcl: string | undefined;
  let darwinAccount: PlanOpts["darwinAccount"];
  let darwinState: PlanOpts["darwinState"];
  let darwinRoot: PlanOpts["darwinRoot"];
  if (platform === "win32") {
    const root = path.win32.dirname(stateDir);
    const marker = path.win32.join(root, "install.json");
    markerExists = ourMarker(marker);
    const probed = exec(toolArgv("net", ["user", VERAX_SVC], "win32"));
    winAccount = { exists: probed.status === 0, createdByUs: markerFlags(marker).createdAccount };
    try {
      lstatSync(root);
      veraxRootExists = true;
    } catch {
      veraxRootExists = false;
    }
    if (pathIsReparse(root, exec, platform)) reparsePath = root;
    else if (pathIsReparse(stateDir, exec, platform)) reparsePath = stateDir;
    if (veraxRootExists) {
      const text = sddlOrMiss(sddlPlan ?? new Map(), root).text;
      winRootAcl = text;
      winRootOwner = sddlOwner(text) ?? "";
    }
  } else if (platform === "linux") {
    const codeDir = codeDirFor(platform, plannedEnv, posixRoot);
    linuxState = linuxFact(stateDir, exec);
    linuxCode = linuxFact(codeDir, exec);
    const probed = exec(toolArgv("id", ["verax"], "linux"));
    const prior = markerFlags(path.posix.join(codeDir, "install.json"));
    linuxAccount = { exists: probed.status === 0, createdByUs: prior.createdUser, createdGroup: prior.createdGroup };
  } else if (platform === "darwin") {
    markerExists = ourMarker(fixed.darwinMarker);
    darwinState = posixPresence(stateDir);
    darwinRoot = posixPresence(fixed.darwinRoot);
    const picked = pickDarwinAccount(exec, markerFlags(fixed.darwinMarker));
    if ("error" in picked) {
      io.stderr.write(`${picked.error}\n`);
      return EX_CONFIG;
    }
    darwinAccount = picked;
  }
  let userSid = platform === "win32" ? invokingSid(exec) : undefined;
  let profileImagePath: string | undefined;
  if (platform === "win32" && userSid) {
    const sid = userSid.toUpperCase();
    if (GROUP_TOKEN_SIDS.has(sid)) {
      io.stderr.write(`refusing token principal ${sid}: a well-known group is not the invoking user\n`);
      return EX_CONFIG;
    }
    const looked = exec(toolArgv("powershell", [
      "-NoProfile",
      "-Command",
      `(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\${sid}').ProfileImagePath`,
    ], "win32"));
    const image = (looked.stdout ?? "").trim().split(/\r?\n/).filter((line) => line.trim() !== "").pop() ?? "";
    if (/^[A-Za-z]:\\/.test(image)) {
      const profile = plannedEnv.USERPROFILE?.trim() ?? "";
      if (profile !== "" && profile !== image) {
        io.stderr.write(`refusing: USERPROFILE ${profile} is not ProfileImagePath ${image}\n`);
        return EX_CONFIG;
      }
      profileImagePath = image;
    }
  }
  const packed = parsed.fromTarballs ? collectTarballs(parsed.fromTarballs, platform, exec, io, sddlPlan) : undefined;
  if (packed && "error" in packed) return packed.code;
  const plan = planInstall(platform as InstallPlatform, plannedEnv, {
    ...layout,
    port: parsed.port,
    days: parsed.days,
    force: parsed.force,
    posixRoot,
    stateExists: exists,
    veraxRootExists,
    markerExists,
    reparsePath,
    linuxState,
    linuxCode,
    winAccount,
    linuxAccount,
    winRootOwner,
    winRootAcl,
    userSid,
    profileImagePath,
    invokingHome,
    darwinAccount,
    darwinState,
    darwinRoot,
    ...(packed && !("error" in packed)
      ? { fromTarballs: packed.dir, tarballFiles: packed.files, tarballDigests: packed.digests, tarballIcacls: packed.icacls, tarballModes: packed.modes }
      : {}),
  });
  if (!plan.ok) {
    io.stderr.write(plan.message);
    return plan.code;
  }
  return execute(plan, exec, io, platform, hooks.copyFile ?? copyFileSync, plannedEnv, hooks.healthTimeoutMs);
}

/** A non-zero tool result that means the install artifact is already gone. */
function toolAlreadyAbsent(ran: ExecResult): boolean {
  if ((ran.status ?? 1) === 0) return false;
  const text = `${ran.stdout ?? ""}\n${ran.stderr ?? ""}`.toLowerCase();
  if (text.trim() === "") return true;
  return /cannot find the file specified|does not exist|could not be found|could not find|no such file|not found|not loaded|isn't loaded|is not loaded/.test(text);
}

function reportToolFailure(io: InstallIo, argv: readonly string[], ran: ExecResult): void {
  const tool = systemToolName(argv[0] ?? "") || (argv[0] ?? "command");
  const code = ran.status ?? 1;
  const err = `${ran.stderr ?? ""}`.replace(/\s+$/, "");
  io.stderr.write(err === "" ? `${tool} exit ${code}\n` : `${tool} exit ${code}: ${err}\n`);
}

/** Run one uninstall tool. Absent artifacts are not failures. Returns a non-zero code when the tool failed. */
function runUninstallTool(exec: ToolExec, io: InstallIo, argv: string[]): number | null {
  const ran = exec(argv);
  if ((ran.status ?? 1) === 0 || toolAlreadyAbsent(ran)) return null;
  reportToolFailure(io, argv, ran);
  return ran.status ?? 1;
}

function removeInstallPath(target: string, io: InstallIo): number | null {
  try {
    rmSync(target, { recursive: true, force: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "remove failed";
    io.stderr.write(`rm exit 1: ${message}\n`);
    return 1;
  }
  return null;
}

/**
 * Remove whatever is still installed. A clean machine prints `nothing to remove` and exits 0.
 * A real tool failure prints the tool, its exit code, and its stderr.
 */
function executeUninstall(
  platform: NodeJS.Platform,
  plan: Extract<InstallPlan, { ok: true }>,
  exec: ToolExec,
  io: InstallIo,
  opts: {
    keepState: boolean;
    removeWinAccount: boolean;
    removeDarwinUser: boolean;
    removeDarwinGroup: boolean;
    removeLinuxUser: boolean;
    removeLinuxGroup: boolean;
  },
): number {
  const lines: string[] = [];
  let any = false;
  const writeLines = (): void => {
    for (const line of lines) io.stdout.write(`${line}\n`);
  };

  const note = (present: boolean, label: string, remove: () => number | null): number | null => {
    if (!present) {
      lines.push(`already absent: ${label}`);
      return null;
    }
    any = true;
    const failed = remove();
    if (failed !== null) return failed;
    lines.push(`removed: ${label}`);
    return null;
  };

  if (platform === "win32") {
    const queryArgv = toolArgv("schtasks", ["/Query", "/TN", TASK_NAME], "win32");
    const query = exec(queryArgv);
    if ((query.status ?? 1) !== 0 && !toolAlreadyAbsent(query)) {
      reportToolFailure(io, queryArgv, query);
      return query.status ?? 1;
    }
    const failed = note(query.status === 0, `scheduled task ${TASK_NAME}`, () => {
      const end = runUninstallTool(exec, io, toolArgv("schtasks", ["/End", "/TN", TASK_NAME], "win32"));
      if (end !== null) return end;
      return runUninstallTool(exec, io, toolArgv("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"], "win32"));
    });
    if (failed !== null) {
      writeLines();
      return failed;
    }
  } else if (platform === "linux") {
    const unit = "/etc/systemd/system/verax.service";
    const failed = note(existsSync(unit), "systemd unit verax.service", () => {
      const stopped = runUninstallTool(exec, io, toolArgv("systemctl", ["disable", "--now", "verax"], "linux"));
      if (stopped !== null) return stopped;
      const removed = removeInstallPath(unit, io);
      if (removed !== null) return removed;
      return runUninstallTool(exec, io, toolArgv("systemctl", ["daemon-reload"], "linux"));
    });
    if (failed !== null) {
      writeLines();
      return failed;
    }
  } else if (platform === "darwin") {
    const failed = note(existsSync(DARWIN_PLIST), `launchd plist ${DARWIN_PLIST}`, () => {
      const boot = runUninstallTool(exec, io, toolArgv("launchctl", ["bootout", `system/${DARWIN_LABEL}`], "darwin"));
      if (boot !== null) return boot;
      return removeInstallPath(DARWIN_PLIST, io);
    });
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }

  const codeFailed = note(existsSync(plan.codeDir), plan.codeDir, () => removeInstallPath(plan.codeDir, io));
  if (codeFailed !== null) {
    writeLines();
    return codeFailed;
  }
  if (platform === "darwin") {
    const markerFailed = note(existsSync(DARWIN_MARKER), DARWIN_MARKER, () => removeInstallPath(DARWIN_MARKER, io));
    if (markerFailed !== null) {
      writeLines();
      return markerFailed;
    }
    const rootFailed = note(existsSync(DARWIN_ROOT), DARWIN_ROOT, () => removeInstallPath(DARWIN_ROOT, io));
    if (rootFailed !== null) {
      writeLines();
      return rootFailed;
    }
  }
  if (!opts.keepState) {
    const stateFailed = note(existsSync(plan.stateDir), plan.stateDir, () => removeInstallPath(plan.stateDir, io));
    if (stateFailed !== null) {
      writeLines();
      return stateFailed;
    }
  }
  if (platform === "win32" && opts.removeWinAccount) {
    const queryArgv = toolArgv("net", ["user", VERAX_SVC], "win32");
    const query = exec(queryArgv);
    if ((query.status ?? 1) !== 0 && !toolAlreadyAbsent(query)) {
      reportToolFailure(io, queryArgv, query);
      writeLines();
      return query.status ?? 1;
    }
    const failed = note(query.status === 0, `account ${VERAX_SVC}`, () =>
      runUninstallTool(exec, io, toolArgv("net", ["user", VERAX_SVC, "/delete"], "win32")),
    );
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }
  if (platform === "darwin" && opts.removeDarwinUser) {
    const queryArgv = toolArgv("id", ["-u", DARWIN_USER], "darwin");
    const query = exec(queryArgv);
    if ((query.status ?? 1) !== 0 && !toolAlreadyAbsent(query)) {
      reportToolFailure(io, queryArgv, query);
      writeLines();
      return query.status ?? 1;
    }
    const failed = note(query.status === 0, `user ${DARWIN_USER}`, () =>
      runUninstallTool(exec, io, toolArgv("dscl", [".", "-delete", `/Users/${DARWIN_USER}`], "darwin")),
    );
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }
  if (platform === "darwin" && opts.removeDarwinGroup) {
    const queryArgv = toolArgv("dscl", [".", "-read", `/Groups/${DARWIN_USER}`, "PrimaryGroupID"], "darwin");
    const query = exec(queryArgv);
    if ((query.status ?? 1) !== 0 && !toolAlreadyAbsent(query)) {
      reportToolFailure(io, queryArgv, query);
      writeLines();
      return query.status ?? 1;
    }
    const failed = note(query.status === 0, `group ${DARWIN_USER}`, () =>
      runUninstallTool(exec, io, toolArgv("dscl", [".", "-delete", `/Groups/${DARWIN_USER}`], "darwin")),
    );
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }
  if (platform === "linux" && opts.removeLinuxUser) {
    const queryArgv = toolArgv("id", ["verax"], "linux");
    const query = exec(queryArgv);
    if ((query.status ?? 1) !== 0 && !toolAlreadyAbsent(query)) {
      reportToolFailure(io, queryArgv, query);
      writeLines();
      return query.status ?? 1;
    }
    const failed = note(query.status === 0, "account verax", () =>
      runUninstallTool(exec, io, toolArgv("userdel", ["verax"], "linux")),
    );
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }
  if (platform === "linux" && opts.removeLinuxGroup) {
    const queryArgv = toolArgv("getent", ["group", "verax"], "linux");
    const query = exec(queryArgv);
    if ((query.status ?? 1) !== 0 && !toolAlreadyAbsent(query)) {
      reportToolFailure(io, queryArgv, query);
      writeLines();
      return query.status ?? 1;
    }
    const failed = note(query.status === 0, "group verax", () =>
      runUninstallTool(exec, io, toolArgv("groupdel", ["verax"], "linux")),
    );
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }

  if (!any) {
    io.stdout.write("nothing to remove\n");
    return 0;
  }
  writeLines();
  return 0;
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
  const resolvedEnv = invokingEnv(platform, env, exec);
  if ("error" in resolvedEnv) {
    io.stderr.write(`${resolvedEnv.error}\n`);
    return EX_CONFIG;
  }
  const plannedEnv = resolvedEnv.env;
  const posixRoot = platform === "win32" ? undefined : hooks.posixRoot;
  const fixed = fixedPosix(posixRoot);
  // Linux install.json lives in the code dir. Read it before that dir is removed.
  const markerFile = platform === "win32"
    ? path.win32.join(path.win32.dirname(stateDirFor(platform, plannedEnv)), "install.json")
    : platform === "darwin"
      ? fixed.darwinMarker
      : path.posix.join(fixed.linuxCode, "install.json");
  const flags = markerFlags(markerFile);
  const plan = planUninstall(platform as InstallPlatform, plannedEnv, {
    keepState: parsed.keepState,
    removeWinAccount: flags.createdAccount,
    removeDarwinUser: flags.createdUser,
    removeDarwinGroup: flags.createdGroup,
    removeLinuxUser: flags.createdUser,
    removeLinuxGroup: flags.createdGroup,
    posixRoot,
  });
  if (!plan.ok) {
    io.stderr.write(plan.message);
    return plan.code;
  }
  return executeUninstall(platform, plan, exec, io, {
    keepState: parsed.keepState,
    removeWinAccount: flags.createdAccount,
    removeDarwinUser: flags.createdUser,
    removeDarwinGroup: flags.createdGroup,
    removeLinuxUser: flags.createdUser,
    removeLinuxGroup: flags.createdGroup,
  });
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
    const rootDir = path.win32.dirname(stateDir);
    const rows = [
      ...serviceAclFiles(stateDir, "state").map((file) => ({ path: file, kind: "state" as const })),
      ...serviceAclFiles(codeDir, "code").map((file) => ({ path: file, kind: "code" as const })),
    ].filter((file) => existsSync(file.path));
    const readBack = readSddlBatch(exec, [stateDir, codeDir, rootDir, ...rows.map((file) => file.path)]);
    const textOf = (file: string): string => sddlOrMiss(readBack, file).text;
    const fileAcls = rows.map((file) => ({ path: file.path, kind: file.kind, text: textOf(file.path) }));
    const task = exec(toolArgv("schtasks", ["/Query", "/TN", TASK_NAME], "win32"));
    const ownerOf = (dir: string): string => sddlOwner(textOf(dir)) ?? "";
    const acl = { stdout: textOf(stateDir), stderr: "" };
    const codeAcl = { stdout: textOf(codeDir), stderr: "" };
    const rootAcl = { stdout: textOf(rootDir), stderr: "" };
    const marker = path.win32.join(rootDir, "install.json");
    return installedBoundaryChecks({
      codeDir,
      stateDir,
      manifest,
      hashOf: (rel) => hashUnder(codeDir, rel),
      aclText: `${acl.stdout ?? ""}\n${acl.stderr ?? ""}`,
      codeAclText: `${codeAcl.stdout ?? ""}\n${codeAcl.stderr ?? ""}`,
      fileAcls,
      winOwners: { state: ownerOf(stateDir), code: ownerOf(codeDir) },
      rootDir,
      rootAclText: `${rootAcl.stdout ?? ""}\n${rootAcl.stderr ?? ""}`,
      markerPresent: ourMarker(marker),
      installSource: markerSource(marker),
      autostart: task.status === 0,
    });
  }
  if (platform === "darwin") {
    const statName = (flag: string, dir: string): string => (exec(toolArgv("stat", ["-f", flag, dir], "darwin")).stdout ?? "").trim();
    const statMode = (dir: string): number | undefined => {
      const bits = Number.parseInt(statName("%Lp", dir), 8);
      return Number.isNaN(bits) ? undefined : bits;
    };
    const loaded = exec(toolArgv("launchctl", ["print", `system/${DARWIN_LABEL}`], "darwin"));
    return installedBoundaryChecks({
      codeDir,
      stateDir,
      manifest,
      hashOf: (rel) => hashUnder(codeDir, rel),
      mode: statMode(stateDir),
      owner: statName("%Su", stateDir) || undefined,
      ownerGroup: statName("%Sg", stateDir) || undefined,
      codeOwner: statName("%Su", codeDir) || undefined,
      codeMode: statMode(codeDir),
      installSource: markerSource(DARWIN_MARKER),
      autostart: loaded.status === 0 && existsSync(DARWIN_PLIST),
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
