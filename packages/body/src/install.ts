import { spawnSync, type SpawnSyncReturns, type StdioOptions } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { get } from "node:http";
import { createServer as createNetServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EX_CONFIG } from "./config.ts";
import { INSTALL_HEALTH_NONCE } from "./health-extras.ts";
import { runInitLocal } from "./init-local.ts";
import { psModuleImports, type PsModule } from "./ps-module-imports.ts";

export const EX_ELEVATION = 77;

export const ELEVATION_LINE = "verax install needs an elevated shell (Administrator / root)";

const POSIX_CLI = "/opt/verax-cli/lib/node_modules/@verax-ai/body/dist/cli.js";

/** The tarball Node under `/opt/verax-node`, plus the distribution `/usr/bin/node`. Neither is `env node`. */
export function posixRootOwnedCommand(platform: "linux" | "darwin", command: string): string {
  const os = platform === "darwin" ? "darwin" : "linux";
  const node = `/opt/verax-node/node-v${process.versions.node}-${os}-${process.arch}/bin/node`;
  return `sudo ${node} ${POSIX_CLI} ${command} or sudo /usr/bin/node ${POSIX_CLI} ${command}`;
}

/** Names the administrator-owned copy. A same-user elevated shell is not that copy. */
export function unreadableSentence(dir: string, command = "verax"): string {
  if (process.platform === "win32" && command === "approve") {
    return `cannot read ${dir}: approve from the panel with a passkey. An elevated CLI approve is a fallback from a separate administrator account, not this account elevated: & "$env:ProgramFiles\\verax-cli\\verax.cmd" approve`;
  }
  const copy =
    process.platform === "win32"
      ? `& "$env:ProgramFiles\\verax-cli\\verax.cmd" ${command}`
      : posixRootOwnedCommand(process.platform === "darwin" ? "darwin" : "linux", command);
  return `cannot read ${dir}: run ${copy}`;
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

const WIN32_TOOLS = ["whoami", "icacls", "schtasks", "net", "fsutil", "powershell", "netstat"] as const;
const LINUX_TOOLS = ["useradd", "userdel", "groupdel", "chown", "chmod", "id", "getent", "stat", "systemctl", "journalctl", "getenforce", "ps", "ausearch"] as const;
const DARWIN_TOOLS = ["dscl", "launchctl", "chown", "chmod", "id", "stat", "plutil", "lsof"] as const;
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
  lsof: "/usr/sbin/lsof",
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

function pathHasDotDot(value: string): boolean {
  return value.split(/[\\/]/).some((part) => part === "..");
}

/** `X:\Windows` after a `..`-free normalisation. Anything else is refused before a tool runs. */
function requireWindowsDir(value: string): string {
  const raw = value.trim();
  if (pathHasDotDot(raw)) throw new SystemToolError(`refusing: SystemRoot ${raw} contains ..`);
  const norm = path.win32.normalize(raw).replace(/[\\/]+$/, "");
  // Only C:\Windows. Any other drive letter could be a data drive where a user can create `\Windows\System32`,
  // and the trust check itself runs PowerShell from this directory, so it cannot vouch for it.
  if (pathHasDotDot(norm) || !/^C:\\Windows$/i.test(norm)) {
    throw new SystemToolError(
      `refusing: SystemRoot ${raw} is not C:\\Windows; this installer runs system tools only from C:\\Windows\\System32`,
    );
  }
  return "C:\\Windows";
}

/**
 * Windows directory for system tools. An env value is accepted only when it is
 * `X:\\Windows` and contains no `..`. A value that points elsewhere is refused
 * before any process is started. `exec`, when passed, then applies the same
 * administrator-only DACL check used for node.exe to System32 and each tool,
 * ancestors included.
 */
export function windowsSystemRoot(env: NodeJS.ProcessEnv = process.env, exec?: ToolExec): string {
  const hinted = [env.SystemRoot, env.windir].filter((value): value is string => typeof value === "string" && value.trim() !== "");
  const root = hinted.length === 0 ? "C:\\Windows" : requireWindowsDir(hinted[0]!);
  for (const value of hinted.slice(1)) {
    const next = requireWindowsDir(value);
    if (next.toLowerCase() !== root.toLowerCase()) {
      throw new SystemToolError(`refusing: SystemRoot ${hinted[0]} is not the Windows directory`);
    }
  }
  if (exec) assertAdminWritableTree(root, exec);
  return root;
}

/** One install root, normalised. `..` is refused. The machine comparison is separate. */
export function windowsInstallRoot(raw: string | undefined, fallback: string, label: string): string {
  const text = raw === undefined || raw.trim() === "" ? fallback : raw.trim();
  if (pathHasDotDot(text)) throw new SystemToolError(`refusing: ${label} ${text} contains ..`);
  const norm = path.win32.normalize(text).replace(/[\\/]+$/, "");
  // On Windows the root must carry a drive letter. A Windows plan built on another host (tests) only needs an
  // absolute path; the trust check applies to it either way.
  const absolute = process.platform === "win32" ? /^[A-Za-z]:\\/.test(norm) : path.win32.isAbsolute(norm);
  if (pathHasDotDot(norm) || !absolute) {
    throw new SystemToolError(`refusing: ${label} ${text} is not an absolute path`);
  }
  return norm;
}

/** ProgramData and Program Files as the machine records them, not as the shell sets them. */
export type WindowsMachineRoots = { programData: string; programFiles: string };

export const WINDOWS_CANONICAL_ROOTS: WindowsMachineRoots = {
  programData: "C:\\ProgramData",
  programFiles: "C:\\Program Files",
};

function windowsPathKey(value: string): string {
  return path.win32.normalize(value.trim()).replace(/[\\/]+$/, "").toLowerCase();
}

function stripWinExtended(value: string): string {
  if (value.startsWith("\\\\?\\UNC\\")) return `\\\\${value.slice("\\\\?\\UNC\\".length)}`;
  if (value.startsWith("\\\\?\\")) return value.slice("\\\\?\\".length);
  return value;
}

/** A junction or symlink. A missing path is not one. Intermediate links are not followed: the named path is lstat'd. */
function windowsReparsePoint(file: string): boolean {
  try {
    return lstatSync(file).isSymbolicLink();
  } catch {
    return false;
  }
}

function refuseWindowsRootShape(root: string, label: string): void {
  for (const entry of ancestry(root, "win32")) {
    if (windowsReparsePoint(entry)) throw new SystemToolError(`refusing: ${entry} is a reparse point`);
  }
  let real: string;
  try {
    real = stripWinExtended(realpathSync.native(root));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new SystemToolError(`refusing: ${label} ${root} could not be read`);
  }
  if (windowsPathKey(real) !== windowsPathKey(root)) {
    throw new SystemToolError(`refusing: ${label} ${root} is not the path on disk ${real}`);
  }
}

/**
 * Use the machine roots. A shell value that differs is named and refused.
 * An unset shell variable is not a redirect. The root and each ancestor must
 * be a real directory, and the path on disk must be the path as given.
 */
export function adoptWindowsInstallRoots(
  env: NodeJS.ProcessEnv,
  machine: WindowsMachineRoots = WINDOWS_CANONICAL_ROOTS,
): WindowsMachineRoots {
  const rows: { label: "ProgramData" | "ProgramFiles"; fromEnv: string | undefined; fromMachine: string; fallback: string }[] = [
    { label: "ProgramData", fromEnv: env.ProgramData, fromMachine: machine.programData, fallback: WINDOWS_CANONICAL_ROOTS.programData },
    { label: "ProgramFiles", fromEnv: env.ProgramFiles, fromMachine: machine.programFiles, fallback: WINDOWS_CANONICAL_ROOTS.programFiles },
  ];
  const resolved: { label: "ProgramData" | "ProgramFiles"; machinePath: string }[] = [];
  for (const row of rows) {
    const machinePath = windowsInstallRoot(row.fromMachine, row.fromMachine, row.label);
    if (row.fromEnv !== undefined && row.fromEnv.trim() !== "") {
      const envPath = windowsInstallRoot(row.fromEnv, row.fallback, row.label);
      if (windowsPathKey(envPath) !== windowsPathKey(machinePath)) {
        throw new SystemToolError(
          `refusing: ${row.label} in this shell is ${row.fromEnv.trim()}, the machine says ${machinePath}`,
        );
      }
    }
    resolved.push({ label: row.label, machinePath });
  }
  const out: WindowsMachineRoots = { programData: "", programFiles: "" };
  for (const row of resolved) {
    refuseWindowsRootShape(row.machinePath, row.label);
    if (row.label === "ProgramData") out.programData = row.machinePath;
    else out.programFiles = row.machinePath;
  }
  return out;
}

function expandMachineRoot(raw: string, drive: string, label: string): string {
  if (!raw.includes("%")) return raw;
  if (!/^[A-Za-z]:$/.test(drive)) {
    throw new SystemToolError(`refusing: ${label} ${raw} needs SystemDrive and the machine says ${drive || "(empty)"}`);
  }
  const expanded = raw.replace(/%SystemDrive%/gi, drive);
  if (/%[^%]+%/.test(expanded)) throw new SystemToolError(`refusing: ${label} ${raw} has an unexpanded variable`);
  return expanded;
}

const MACHINE_ROOTS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  psModuleImports(["Microsoft.PowerShell.Management"]),
  "$files = (Get-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion').GetValue('ProgramFilesDir', $null, 'DoNotExpandEnvironmentNames')",
  "$data = (Get-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList').GetValue('ProgramData', $null, 'DoNotExpandEnvironmentNames')",
  "$root = (Get-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').GetValue('SystemRoot', $null, 'DoNotExpandEnvironmentNames')",
  "if ($root -notmatch '^[A-Za-z]:\\\\') { throw 'SystemRoot does not name a drive' }",
  "$drive = $root.Substring(0, 2)",
  "Write-Output ('ProgramFilesDir=' + $files)",
  "Write-Output ('ProgramData=' + $data)",
  "Write-Output ('SystemDrive=' + $drive)",
].join("; ");

/** HKLM ProgramFilesDir and ProfileList ProgramData, read without expansion. The drive is the drive of SystemRoot. */
export function readWindowsMachineRoots(exec: ToolExec = defaultExec): WindowsMachineRoots {
  const ran = exec(toolArgv("powershell", ["-NoProfile", "-NonInteractive", "-Command", MACHINE_ROOTS_SCRIPT], "win32"));
  if ((ran.status ?? 1) !== 0) {
    throw new SystemToolError("refusing: the machine ProgramData and ProgramFiles could not be read");
  }
  const lines = `${ran.stdout ?? ""}`.split(/\r?\n/).map((line) => line.trim());
  const pick = (key: string): string => {
    const line = lines.find((item) => item.startsWith(`${key}=`));
    const value = line?.slice(key.length + 1).trim() ?? "";
    if (value === "") throw new SystemToolError(`refusing: the machine ${key} is empty`);
    return value;
  };
  const drive = pick("SystemDrive");
  if (!/^[A-Za-z]:$/.test(drive)) throw new SystemToolError(`refusing: the machine SystemDrive is ${drive}`);
  return {
    programFiles: expandMachineRoot(pick("ProgramFilesDir"), drive, "ProgramFiles"),
    programData: expandMachineRoot(pick("ProgramData"), drive, "ProgramData"),
  };
}

function winToolUnder(root: string, name: string): string {
  if (name === "powershell") return path.win32.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  return path.win32.join(root, "System32", `${name}.exe`);
}

/** System32 and every Windows install tool, each with its ancestors. */
function assertAdminWritableTree(root: string, exec: ToolExec): void {
  const targets = [
    path.win32.join(root, "System32"),
    ...WIN32_TOOLS.map((name) => winToolUnder(root, name)),
  ];
  for (const file of targets) {
    for (const entry of trustTargets(file, "win32")) {
      const ran = exec(windowsSddlArgv(entry.path));
      const text = `${ran.stdout ?? ""}`;
      if ((ran.status ?? 1) !== 0 || windowsUserCanWrite(text, { path: entry.path, ancestor: entry.ancestor })) {
        throw new SystemToolError(refuseAcl(text, `refusing: ${entry.path} can be changed by a non-administrator`).trimEnd());
      }
    }
  }
}

/**
 * Absolute path for a system tool. Windows uses System32 under SystemRoot.
 * Linux walks fixed directories and never consults PATH.
 * macOS uses the fixed table (dscl, launchctl, chown, chmod, id, stat, plutil, lsof).
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
 * On Windows, PSModulePath is only the System32 Windows PowerShell 5.1 module
 * directory. Without it, PowerShell 5.1 puts Documents\WindowsPowerShell\Modules
 * first, and -NoProfile does not change that list. PowerShell 5.1 still inserts
 * Program Files\WindowsPowerShell\Modules in front of the pinned value (measured
 * on 5.1.26100); the install trust-checks that directory as an object.
 */
export function systemToolEnv(platform: NodeJS.Platform = process.platform, tempDir?: string): NodeJS.ProcessEnv {
  if (platform === "win32") {
    const root = windowsSystemRoot();
    const drive = path.win32.parse(root).root.replace(/[\\/]+$/, "") || "C:";
    const env: NodeJS.ProcessEnv = {
      SystemRoot: root,
      windir: root,
      PATHEXT: WIN32_PATHEXT,
      ComSpec: path.win32.join(root, "System32", "cmd.exe"),
      SystemDrive: drive,
      PSModulePath: path.win32.join(root, "System32", "WindowsPowerShell", "v1.0", "Modules"),
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

export function toolArgv(tool: string, args: readonly string[], platform: NodeJS.Platform = process.platform): string[] {
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
/** Replace or re-point a child. Add-file (0x2) and add-subdirectory (0x4) on an ancestor do not. FA includes these bits; the full FA mask is not ORed in. The directory that holds an executable is not an ancestor: Windows loads a DLL from that directory first, so it uses the object mask. */
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
  // Registry aliases. On a file these masks include write bits (KA includes FILE_WRITE_DATA).
  KA: 0xf003f,
  KR: 0x20019,
  KW: 0x20006,
  KX: 0x20019,
};

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
    // The CLI goes into a root-owned prefix too: an elevated command refuses code the user can change.
    `sudo ${node} ${dest}/node-v${ver}-${os}-${arch}/bin/npm install -g --prefix /opt/verax-cli @verax-ai/body`,
    `sudo ${node} /opt/verax-cli/lib/node_modules/@verax-ai/body/dist/cli.js install`,
  ].join("\n");
}

export function nodeTrustMessage(nodePath: string): string {
  return `Node at ${nodePath} can be changed by your user account; install Node for all users (nodejs.org installer) and run verax install from that Node`;
}

/** A directory Node or PowerShell searches for code to load, judged apart from Node itself. */
function isModuleSearchDir(file: string): boolean {
  const trimmed = file.replace(/[\\/]+$/, "");
  return /(^|[\\/])node_modules$/i.test(trimmed) || /[\\/]WindowsPowerShell[\\/]Modules$/i.test(trimmed);
}

/**
 * The remedy for a module directory is that directory, not a different Node:
 * a user-writable /usr/local/lib/node_modules refuses every Node under /usr/local/lib.
 */
function moduleDirTrustMessage(dir: string, platform: InstallPlatform): string {
  const head = `Module directory ${dir} can be changed by your user account. An elevated install loads code from it, so the install refuses it`;
  if (platform === "win32") {
    return `${head}. Remove it, or leave it writable only by Administrators and SYSTEM, then run verax install again`;
  }
  const owner = platform === "darwin" ? "root:wheel" : "root:root";
  return `${head}. Remove it, or make it ${owner} and not group- or other-writable (sudo chown -R ${owner} ${dir}; sudo chmod -R go-w ${dir}), then run verax install again`;
}

function nodeTrustMessageFor(nodePath: string, platform: InstallPlatform): string {
  const head = `Node at ${nodePath} can be changed by your user account`;
  if (platform === "win32") return nodeTrustMessage(nodePath);
  const owner = platform === "darwin" ? "root:wheel" : "root:root";
  const dest = officialNodeRoot(platform);
  return `${head}. An elevated install must not run a Node your account can swap. Download the official tarball and SHASUMS256.txt, check the sha256, and extract as root into ${dest} (${owner}, go-w), then run verax install from that Node:\n${officialNodeRemedy(platform)}`;
}

/** Account name printed when elevated code is writable by the invoking user. */
export function codeTrustAccount(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  if (platform === "win32") {
    const name = env.USERNAME?.trim() ?? "";
    const domain = env.USERDOMAIN?.trim() ?? "";
    if (name !== "") return domain !== "" ? `${domain}\\${name}` : name;
    return "the invoking user";
  }
  const sudo = env.SUDO_USER?.trim() ?? "";
  return sudo !== "" ? sudo : "the invoking user";
}

export function elevatedCodeMessage(dir: string, account: string, platform: InstallPlatform, detail?: string): string {
  const head = `refusing: the verax code at ${dir} can be changed by ${account}${detail ? ` (${detail})` : ""}; run elevated commands from a copy only administrators can write`;
  if (platform === "win32") {
    return [
      head,
      'In an Administrator PowerShell: npm install -g --prefix "$env:ProgramFiles\\verax-cli" @verax-ai/body',
      'then: & "$env:ProgramFiles\\verax-cli\\verax.cmd" install',
    ].join("\n");
  }
  return `${head}\n${officialNodeRemedy(platform)}`;
}

function packageRootOf(start: string): string | null {
  let cur = start;
  for (let i = 0; i < 8; i += 1) {
    const pkg = path.join(cur, "package.json");
    if (existsSync(pkg)) {
      try {
        const parsed = JSON.parse(readFileSync(pkg, "utf8")) as { name?: unknown };
        if (typeof parsed.name === "string" && parsed.name.startsWith("@verax-ai/")) return cur;
      } catch {
        // A package.json that does not parse is not this package. Keep walking.
      }
    }
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

/** Package directory of the running CLI, each `@verax-ai/*` it loads, and their `node_modules`. */
export function veraxCodeDirectories(entryUrl: string = import.meta.url): string[] {
  const start = path.dirname(fileURLToPath(entryUrl));
  const body = packageRootOf(start);
  const dirs = new Set<string>();
  // A directory that is not on disk loads no code. Its parent is on the list and is judged.
  const add = (dir: string): void => {
    try {
      dirs.add(realpathSync(dir));
    } catch {
      // not on disk
    }
  };
  if (!body) return [];
  add(body);
  add(path.join(body, "node_modules"));
  // Node also searches every ancestor's node_modules, up to the drive root.
  const hostFlavor: InstallPlatform = process.platform === "win32" ? "win32" : "linux";
  for (const dir of moduleSearchDirs(body, hostFlavor)) add(dir);
  let deps: string[] = [];
  try {
    const parsed = JSON.parse(readFileSync(path.join(body, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
    };
    deps = Object.keys(parsed.dependencies ?? {}).filter((name) => name.startsWith("@verax-ai/"));
  } catch {
    deps = [];
  }
  for (const name of deps) {
    // Resolve the entry Node itself would load (an exports map may not expose
    // package.json), then walk up to that package's root.
    let dir: string | null = null;
    try {
      dir = packageRootOf(path.dirname(fileURLToPath(import.meta.resolve(name))));
    } catch {
      dir = null;
    }
    if (dir === null) return [];
    add(dir);
    add(path.join(dir, "node_modules"));
  }
  return [...dirs];
}

/**
 * `probe` returns true when that directory can be changed by the invoking user.
 * Without a probe the caller supplies `userWritable` from the same ACL or mode
 * check used for node.exe, ancestors included.
 */
export function elevatedCodeRefusal(
  platform: InstallPlatform,
  dirs: readonly string[],
  opts: { account: string; probe?: (dir: string) => boolean; userWritable?: (dir: string) => boolean | string },
): string | null {
  // No directory found is not a directory that passed.
  if (dirs.length === 0) return "refusing: the verax code directory could not be found, so its owner cannot be checked";
  for (const dir of dirs) {
    // A string names the entry that failed, so the operator can see which path to fix.
    const writable = opts.probe ? opts.probe(dir) : (opts.userWritable?.(dir) ?? false);
    if (writable !== false) return elevatedCodeMessage(dir, opts.account, platform, typeof writable === "string" ? writable : undefined);
  }
  return null;
}

/**
 * The child that writes `~/.verax/agent.token`. It runs as the invoking uid.
 * The token arrives on stdin. The directory and file paths arrive in the environment.
 */
const USER_TOKEN_WRITER = [
  'import { lstatSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";',
  "const dir = process.env.VERAX_TOKEN_DIR ?? \"\";",
  "const file = process.env.VERAX_TOKEN_PATH ?? \"\";",
  "const token = readFileSync(0, \"utf8\");",
  "if (dir === \"\" || file === \"\") process.exit(78);",
  "let st;",
  "try { st = lstatSync(dir); } catch (err) {",
  "  if (err && err.code !== \"ENOENT\") { console.error(err.message); process.exit(78); }",
  "  mkdirSync(dir, { mode: 0o700 });",
  "  st = lstatSync(dir);",
  "}",
  "if (st.isSymbolicLink()) { console.error(\"refusing: \" + dir + \" is a symbolic link\"); process.exit(78); }",
  "if (!st.isDirectory()) { console.error(\"refusing: \" + dir + \" is not a directory\"); process.exit(78); }",
  "if (typeof process.getuid === \"function\" && st.uid !== process.getuid()) { console.error(\"refusing: \" + dir + \" is not owned by the invoking user\"); process.exit(78); }",
  "try { lstatSync(file); unlinkSync(file); } catch (err) {",
  "  if (!err || err.code !== \"ENOENT\") { console.error(err && err.message ? err.message : \"token file\"); process.exit(78); }",
  "}",
  "writeFileSync(file, token, { encoding: \"utf8\", mode: 0o600, flag: \"wx\" });",
].join("\n");

export type UserTokenSpawn = {
  uid: number;
  gid: number;
  tokenDir: string;
  tokenPath: string;
  token: string;
};

/** Same checks as the uid child. Tests call this in place of spawn. */
export function writeAgentTokenFile(tokenDir: string, tokenPath: string, token: string): { ok: true } | { ok: false; error: string } {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(tokenDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ok: false, error: err instanceof Error ? err.message : "token directory unreadable" };
    }
    try {
      mkdirSync(tokenDir, { mode: 0o700 });
      st = lstatSync(tokenDir);
    } catch (mk) {
      return { ok: false, error: mk instanceof Error ? mk.message : "token directory was not created" };
    }
  }
  if (st.isSymbolicLink()) return { ok: false, error: `refusing: ${tokenDir} is a symbolic link` };
  if (!st.isDirectory()) return { ok: false, error: `refusing: ${tokenDir} is not a directory` };
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    return { ok: false, error: `refusing: ${tokenDir} is not owned by the invoking user` };
  }
  try {
    lstatSync(tokenPath);
    unlinkSync(tokenPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ok: false, error: err instanceof Error ? err.message : "token file was not replaced" };
    }
  }
  try {
    writeFileSync(tokenPath, token, { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "token file was not created" };
  }
  return { ok: true };
}

/** Copy the state-directory token into an administrator-owned file. Does not follow a link at the file. */
function placeInstalledToken(
  stateDir: string,
  tokenPath: string,
  platform: NodeJS.Platform,
): { ok: true } | { ok: false; error: string } {
  const stateToken = (platform === "win32" ? path.win32 : path.posix).join(stateDir, "local-issuer", "agent.token");
  let token = "";
  try {
    token = readFileSync(stateToken, "utf8");
  } catch {
    return { ok: false, error: "agent token was not created in the state directory" };
  }
  const dir = path.dirname(tokenPath);
  let parent: ReturnType<typeof lstatSync>;
  try {
    parent = lstatSync(dir);
  } catch {
    return { ok: false, error: `refusing: ${dir} is not a directory` };
  }
  if (parent.isSymbolicLink() || !parent.isDirectory()) return { ok: false, error: `refusing: ${dir} is a reparse point` };
  try {
    const cur = lstatSync(tokenPath);
    if (!cur.isSymbolicLink() && !cur.isFile()) return { ok: false, error: `refusing: ${tokenPath} is not a file` };
    unlinkSync(tokenPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ok: false, error: `refusing: ${tokenPath} was not replaced` };
    }
  }
  try {
    writeFileSync(tokenPath, token, { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "token file was not created" };
  }
  return { ok: true };
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
  /**
   * Machine ProgramData and Program Files. When omitted, the canonical paths
   * are the machine values. A shell value that differs is refused.
   */
  windowsMachineRoots?: WindowsMachineRoots;
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
  /**
   * uid and mode of each ancestor of the Linux and macOS install roots.
   * When set, the plan does not lstat those directories. `null` means unreadable.
   */
  ancestorStat?: (dir: string) => { uid: number; mode: number; symlink?: boolean } | null;
  /** Release-test install from `npm pack` tarballs. Skips the registry and signature audit. */
  fromTarballs?: string;
  tarballFiles?: string[];
  /** Injected icacls text for the tarball directory. A user write ACE refuses. */
  tarballIcacls?: string;
  /**
   * One SDDL per path. A newline-joined blob is not one descriptor.
   * `ancestor` is true only for the tarball directory.
   */
  tarballSddl?: { path: string; sddl: string; ancestor: boolean }[];
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
  /** uid and gid of SUDO_USER, already checked against `id` and SUDO_UID/SUDO_GID. */
  invokingIds?: { uid: number; gid: number };
};

export type PlanOp =
  | { op: "manifest"; dir: string }
  | { op: "mkdir"; path: string; mode?: number }
  | { op: "argv"; argv: string[]; optional?: boolean; rollbackDir?: string; stdin?: string; env?: NodeJS.ProcessEnv; cwd?: string }
  | { op: "write"; path: string; contents: string; mode?: number; exclusive?: boolean }
  | { op: "lock-root"; path: string; create: boolean }
  | { op: "init"; stateDir: string; port: number; days: number; force: boolean; noOwnerGrant: boolean }
  | { op: "user-token"; tokenDir: string; tokenPath: string; uid: number; gid: number }
  | { op: "place-token"; path: string }
  | { op: "remove"; path: string }
  | { op: "wait-healthz"; port: number; timeoutMs: number; nonce: string }
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
  /** Whether a `node_modules` directory on a module search path exists. Defaults to `existsSync`. */
  moduleDirExists?: (dir: string) => boolean;
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
  /**
   * True when that code directory can be changed by the invoking user.
   * Absent means the install reads the real ACL or mode.
   */
  codeProbe?: (dir: string) => boolean;
  /**
   * True when that path (the running Node, or an ancestor) can be changed by the invoking user.
   * Absent, together with `codeProbe`, means a test is stubbing the code check and the Node
   * binary is not lstat'd. Absent with no `codeProbe` means the real ACL or mode check.
   */
  execPathProbe?: (file: string) => boolean;
  /** Defaults to `process.execArgv`. An elevated command refuses a preload flag here. */
  execArgv?: readonly string[];
  /**
   * uid and mode for ancestors of the Linux and macOS install roots.
   * When set, the plan does not lstat them. Absent means lstat.
   */
  ancestorStat?: (dir: string) => { uid: number; mode: number; symlink?: boolean } | null;
  /** Test-only stand-in for the uid/gid child that writes the POSIX agent token. */
  spawnUserToken?: (spec: UserTokenSpawn) => ExecResult;
  /**
   * Machine ProgramData and Program Files. When omitted, install and uninstall
   * read them from HKLM. A shell value that differs is refused.
   */
  windowsMachineRoots?: WindowsMachineRoots;
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
  machine?: WindowsMachineRoots,
): string {
  if (platform === "win32") {
    const data = adoptWindowsInstallRoots(env, machine).programData;
    return path.win32.join(data, "Verax", "state");
  }
  if (platform === "darwin") return fixedPosix(posixRoot).darwinState;
  return fixedPosix(posixRoot).linuxState;
}

export function codeDirFor(
  platform: NodeJS.Platform | InstallPlatform,
  env: NodeJS.ProcessEnv = process.env,
  posixRoot?: string,
  machine?: WindowsMachineRoots,
): string {
  if (platform === "win32") {
    const files = adoptWindowsInstallRoots(env, machine).programFiles;
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

export function windowsAgentTokenPath(env: NodeJS.ProcessEnv, userSid: string, machine?: WindowsMachineRoots): string {
  const data = adoptWindowsInstallRoots(env, machine).programData;
  const sid = userSid.trim().replace(/^\*/, "");
  return path.win32.join(data, "Verax", "agent-token", sid, "agent.token");
}

function pathsFor(
  platform: InstallPlatform,
  env: NodeJS.ProcessEnv,
  posixRoot?: string,
  invokingHome?: string,
  userSid?: string,
  machine?: WindowsMachineRoots,
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
    if (profile === "") return { ok: false, code: EX_CONFIG, message: "verax install needs USERPROFILE\n" };
    const sid = userSid?.trim().replace(/^\*/, "") ?? "";
    try {
      const paths = {
        codeDir: codeDirFor("win32", env, undefined, machine),
        stateDir: stateDirFor("win32", env, undefined, machine),
        tokenPath: sid !== "" ? windowsAgentTokenPath(env, sid, machine) : "",
      };
      return { ok: true, paths, home: profile };
    } catch (err) {
      if (err instanceof SystemToolError) {
        return { ok: false, code: EX_CONFIG, message: err.message.endsWith("\n") ? err.message : `${err.message}\n` };
      }
      throw err;
    }
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
    psPrefixed(["Microsoft.PowerShell.Security"], `(Get-Acl -LiteralPath '${literal}').Sddl`),
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
 * UTF-8 JSON array for the batch reader's stdin. The command line never carries it:
 * a real install tree is far past CreateProcess's 32,767 characters.
 */
export function windowsSddlBatchStdin(paths: readonly string[]): string {
  return JSON.stringify(uniquePaths(paths));
}

/**
 * One PowerShell process reads every path. `paths` is not placed on this argv;
 * the caller passes `windowsSddlBatchStdin(paths)` as stdin. Stdout is one JSON
 * object: `{ "<path>": "<sddl>" | { "error": "<msg>" } }`.
 * PowerShell 5.1 unwraps a one-element JSON array, so the script re-wraps with
 * `| ForEach-Object { $_ }`.
 * JSON cmdlets are loaded with psModuleImports before first use. #119, measured
 * on windows-full 5a75875: autoload of ConvertFrom-Json took 23 to 30 s on a
 * GitHub Windows runner, and 0.27 s once the module was loaded from System32 first.
 */
export function windowsSddlBatchArgv(paths: readonly string[]): string[] {
  // Intentionally unused. Interpolating `paths` here is the overflow F17b closes.
  void paths;
  const script = `$ErrorActionPreference = 'Stop'
${psModuleImports(["Microsoft.PowerShell.Utility"])}
$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$raw = [Console]::In.ReadToEnd()
$paths = @($raw | ConvertFrom-Json | ForEach-Object { $_ })
$result = @{}
foreach ($p in $paths) {
  $key = [string]$p
  try {
    if ([System.IO.Directory]::Exists($key)) {
      $sec = [System.IO.Directory]::GetAccessControl($key)
    } else {
      $sec = [System.IO.File]::GetAccessControl($key)
    }
    $result[$key] = [string]$sec.GetSecurityDescriptorSddlForm('All')
  } catch {
    $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
    $err = @{ error = [string]$e.Message }
    $result[$key] = $err
  }
}
$result | ConvertTo-Json -Compress -Depth 4`;
  return toolArgv("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], "win32");
}

export type SddlHit = { status: number; text: string };

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
export function readSddlBatch(exec: ToolExec, paths: readonly string[]): Map<string, SddlHit> {
  const wanted = uniquePaths(paths);
  const map = new Map<string, SddlHit>();
  if (wanted.length === 0) return map;
  const ran = exec(windowsSddlBatchArgv(wanted), windowsSddlBatchStdin(wanted));
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

/**
 * ACE bodies, including a conditional tail with nested parentheses.
 * Null when a `(` is unclosed or any character sits outside an ACE.
 * Control flags are removed before this runs.
 */
function aceInners(body: string): string[] | null {
  const inners: string[] = [];
  let i = 0;
  while (i < body.length) {
    if (body[i] !== "(") return null;
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

/** DACL control flags. `NO_ACCESS_CONTROL` is a NULL DACL: everyone has full control. */
function splitDaclFlags(body: string): { nullDacl: boolean; aces: string } | null {
  let rest = body;
  let nullDacl = false;
  while (rest.length > 0 && rest[0] !== "(") {
    const match = /^(?:NO_ACCESS_CONTROL|AR|AI|P)/i.exec(rest);
    if (!match?.[0]) return null;
    if (match[0].toUpperCase() === "NO_ACCESS_CONTROL") nullDacl = true;
    rest = rest.slice(match[0].length);
  }
  return { nullDacl, aces: rest };
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
 * `nullDacl` is `NO_ACCESS_CONTROL` (with or without `P` / `AI` / `AR`): everyone has full control.
 * An empty body (`D:` or `D:P` and no ACEs) is a present DACL that denies everyone.
 * `unknownType === ""` means the body did not parse (unclosed `(`, leftover text, unknown flag).
 * A non-empty value names an ACE type this checker does not understand.
 */
function readDacl(text: string): { aces: SddlAce[]; unknownType: string | null; nullDacl: boolean } | null {
  const body = daclBody(text);
  if (body === null) return null;
  const split = splitDaclFlags(body);
  if (split === null) return { aces: [], unknownType: "", nullDacl: false };
  if (split.nullDacl) return { aces: [], unknownType: null, nullDacl: true };
  const inners = aceInners(split.aces);
  if (inners === null) return { aces: [], unknownType: "", nullDacl: false };
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
    return { aces: [], unknownType: type, nullDacl: false };
  }
  return { aces, unknownType: null, nullDacl: false };
}

/**
 * DACL ACEs. Inherit-only `(IO)` is flagged and does not apply to the object.
 * `OA` / `XA` / `ZA` are stored as allow; `OD` / `XD` as deny. SACL types are dropped.
 * Any other type fails closed (`null`); the refusal names it.
 */
export function parseSddlAces(text: string): SddlAce[] | null {
  const read = readDacl(text);
  if (read === null || read.unknownType !== null || read.nullDacl) return null;
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
    const bit = SDDL_RIGHTS[token];
    // An unknown two-letter alias is not zero rights. Callers treat `unknown` as write.
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

/** OWNER RIGHTS. A non-inherit-only allow ACE replaces the owner's implicit WRITE_DAC. */
const SID_OWNER_RIGHTS = "S-1-3-4";

/**
 * Without an OWNER RIGHTS ACE the owner holds WRITE_DAC even when the DACL
 * does not name them. Administrators, SYSTEM, TrustedInstaller, and `svcSid`
 * (only when this check already trusts that SID) are not that owner.
 * An inherit-only OWNER RIGHTS ACE does not apply to the object.
 */
function untrustedOwnerCanWrite(text: string, aces: readonly SddlAce[], ancestor: boolean, svcSid: string): boolean {
  const owner = sddlOwner(text);
  // An owner we cannot read is an owner we cannot trust.
  if (owner === null) return true;
  if (TRUSTED_WRITER_SIDS.has(owner)) return false;
  if (svcSid !== "" && owner === svcSid) return false;
  const limits = aces.filter((ace) => ace.type === "A" && ace.sid === SID_OWNER_RIGHTS && !ace.inheritOnly);
  if (limits.length === 0) return true;
  return limits.some((ace) => aceWrites(ace, ancestor));
}

/**
 * True when SDDL lets a principal other than Administrators, SYSTEM, or
 * TrustedInstaller change this object. Text that is not SDDL is untrusted.
 * `NO_ACCESS_CONTROL` is a NULL DACL and grants everyone full control.
 * An empty DACL (`D:` or `D:P` with no ACEs) denies everyone.
 * A DACL body that does not fully parse is untrusted.
 * An ACE type outside allow, deny, and ignored SACL types is an untrusted ACL.
 * The owner keeps implicit WRITE_DAC unless an OWNER RIGHTS ACE limits them.
 * `ancestor: true` counts only replace / re-point rights. `(IO)` does not apply.
 * `svcSid`, when set, is trusted the same way verifyServiceAcl trusts it.
 */
export function windowsUserCanWrite(
  text: string,
  opts?: { path?: string; userSid?: string; ancestor?: boolean; svcSid?: string },
): boolean {
  const read = readDacl(text);
  if (read === null || read.unknownType !== null || read.nullDacl) return true;
  const aces = read.aces;
  const ancestor = opts?.ancestor === true;
  const svc = opts?.svcSid?.trim().replace(/^\*/, "").toUpperCase() ?? "";
  for (const ace of aces) {
    if (!aceWrites(ace, ancestor)) continue;
    if (TRUSTED_WRITER_SIDS.has(ace.sid)) continue;
    if (svc !== "" && ace.sid === svc) continue;
    return true;
  }
  return untrustedOwnerCanWrite(text, aces, ancestor, svc);
}

/** Symlink or junction resolved. A missing path stays as given so a later ACL or stat check can refuse it. */
export function resolveTrustPath(file: string, platform: InstallPlatform): string {
  try {
    return platform === "win32" ? realpathSync.native(file) : realpathSync(file);
  } catch {
    return file;
  }
}

/** Windows loads a DLL from the directory that holds the executable, before the system directories. */
function executableParentIsObject(file: string, platform: InstallPlatform): boolean {
  return platform === "win32" && /\.exe$/i.test(file);
}

/**
 * The target, then each parent. The target itself is judged as the object.
 * When the target is a Windows executable (`node.exe`, a System32 tool, `process.execPath`),
 * its immediate parent is also judged as the object: add-file and add-subdirectory count.
 * Parents above that stay ancestors. A directory target is unchanged: only that
 * directory is the object, and every parent stays an ancestor.
 */
export function trustTargets(file: string, platform: InstallPlatform): { path: string; ancestor: boolean }[] {
  const resolved = resolveTrustPath(file, platform);
  const parentIsObject = executableParentIsObject(resolved, platform);
  return ancestry(resolved, platform).map((entry, index) => ({
    path: entry,
    ancestor: parentIsObject ? index > 1 : index > 0,
  }));
}

/**
 * The `node_modules` directories Node searches for a bare specifier that code
 * under `start` imports: `<dir>/node_modules` for `start` and every parent, up
 * to the root, skipping a directory that is itself named `node_modules`.
 * Stock Windows lets any authenticated user create a folder under `C:\`, so
 * `C:\node_modules` can be planted beside an elevated or service Node. Each
 * one that exists is judged as an object (add-file counts). A missing one is
 * not listed: the loader skips it, and refusing every machine for a folder
 * that is not there would refuse them all.
 */
export function moduleSearchDirs(
  start: string,
  platform: InstallPlatform,
  exists: (dir: string) => boolean = existsSync,
): string[] {
  const p = platform === "win32" ? path.win32 : path.posix;
  const out: string[] = [];
  let cur = p.normalize(start);
  for (;;) {
    if (p.basename(cur).toLowerCase() !== "node_modules") {
      const candidate = p.join(cur, "node_modules");
      if (exists(candidate)) out.push(candidate);
    }
    const parent = p.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return out;
}

/**
 * Another user can rename or replace this entry.
 * An ancestor with the sticky bit is kept: only its owner can rename a child (mode 1777, the way `/tmp` works).
 * The entry itself stays refused when it is group- or other-writable, sticky bit or not.
 * A symbolic link is refused either way.
 */
export function posixOthersCanReplace(st: { uid: number; mode: number; symlink?: boolean }, ancestor: boolean): boolean {
  if (st.symlink) return true;
  if (st.uid !== 0) return true;
  if ((st.mode & 0o022) === 0) return false;
  return !(ancestor && (st.mode & 0o1000) !== 0);
}

/** POSIX half of the elevated code check. `read` supplies uid and mode so a test does not lstat the machine. */
export function posixCodeDirectoryDetail(
  dir: string,
  platform: InstallPlatform,
  read: (file: string) => { uid: number; mode: number; symlink?: boolean } | null,
): string | false {
  for (const file of trustTargets(dir, platform)) {
    const st = read(file.path);
    if (st !== null && !posixOthersCanReplace({ uid: st.uid, mode: st.mode, symlink: st.symlink === true }, file.ancestor)) {
      continue;
    }
    if (st === null) return `${file.path} could not be read`;
    if (st.symlink) return `${file.path} is a symbolic link`;
    return `${file.path} owner uid ${st.uid}, mode ${(st.mode & 0o7777).toString(8)}`;
  }
  return false;
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
function adminOnlyDirGrant(dir: string): PlanOp {
  return {
    op: "argv",
    argv: toolArgv("icacls", [
      dir,
      "/inheritance:r",
      "/grant:r",
      `${ADMINISTRATORS_SID}:(OI)(CI)F`,
      "/grant:r",
      `${SYSTEM_SID}:(OI)(CI)F`,
    ], "win32"),
  };
}

function tokenUserDirGrant(dir: string, principal: string): PlanOp {
  return {
    op: "argv",
    argv: toolArgv("icacls", [
      dir,
      "/inheritance:r",
      "/grant:r",
      `${principal}:(OI)(CI)RX`,
      "/grant:r",
      `${ADMINISTRATORS_SID}:(OI)(CI)F`,
      "/grant:r",
      `${SYSTEM_SID}:(OI)(CI)F`,
    ], "win32"),
  };
}

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

function windowsAccountBody(create: boolean, tempDir: string): string {
  const user = create
    ? "New-LocalUser -Name 'verax-svc' -Password $sec -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires -Description 'Verax body service account'"
    : "Set-LocalUser -Name 'verax-svc' -Password $sec";
  const cfg = psSingle(path.win32.join(tempDir, "verax-rights.cfg"));
  const db = psSingle(path.win32.join(tempDir, "verax-rights.sdb"));
  const after = psSingle(path.win32.join(tempDir, "verax-rights-after.cfg"));
  return [
    psModuleImports([
      "Microsoft.PowerShell.Security",
      "Microsoft.PowerShell.LocalAccounts",
      "Microsoft.PowerShell.Management",
      "Microsoft.PowerShell.Utility",
    ]),
    "$plain = [Console]::In.ReadLine()",
    "if ([string]::IsNullOrEmpty($plain)) { exit 1 }",
    "$sec = ConvertTo-SecureString -String $plain -AsPlainText -Force",
    user,
    "$sid = (Get-LocalUser -Name 'verax-svc').SID.Value",
    "[Console]::Out.WriteLine(('VERAX_SVC_SID:' + $sid))",
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
}

function windowsAccountOps(password: string, create: boolean, tempDir: string): PlanOp[] {
  return [powershellStdin(windowsAccountBody(create, tempDir), password, tempDir)];
}

function windowsTaskBody(nodeBin: string, cliBin: string, envFile: string, logFile: string): string {
  const argument = `"${cliBin}" serve --env-file "${envFile}" --log-file "${logFile}"`;
  return [
    psModuleImports([
      "ScheduledTasks",
      "Microsoft.PowerShell.Utility",
      "Microsoft.PowerShell.LocalAccounts",
    ]),
    "$plain = [Console]::In.ReadLine()",
    "if ([string]::IsNullOrEmpty($plain)) { exit 1 }",
    `$action = New-ScheduledTaskAction -Execute ${psSingle(nodeBin)} -Argument ${psSingle(argument)}`,
    "$trigger = New-ScheduledTaskTrigger -AtStartup",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)",
    "$sid = (Get-LocalUser -Name 'verax-svc').SID.Value",
    "Register-ScheduledTask -TaskName 'Verax Body' -Action $action -Trigger $trigger -User $sid -Password $plain -RunLevel Limited -Settings $settings -Force",
    "Start-ScheduledTask -TaskName 'Verax Body'",
  ].join("; ");
}

function windowsTaskOp(password: string, nodeBin: string, cliBin: string, envFile: string, logFile: string, tempDir: string): PlanOp {
  return powershellStdin(windowsTaskBody(nodeBin, cliBin, envFile, logFile), password, tempDir);
}

/** Module import lines, then `command` unchanged. */
function psPrefixed(modules: readonly PsModule[], command: string): string {
  return `${psModuleImports(modules)}\n${command}`;
}

function aclOwnerCommand(dir: string): string {
  const literal = dir.replaceAll("'", "''");
  return psPrefixed(["Microsoft.PowerShell.Security"], `(Get-Acl -LiteralPath '${literal}').Owner`);
}

function directoryOwnerSidCommand(dir: string): string {
  const literal = dir.replaceAll("'", "''");
  return psPrefixed(
    ["Microsoft.PowerShell.Security"],
    `(Get-Acl -LiteralPath '${literal}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`,
  );
}

const WINDOWS_SERVICE_SID_COMMAND = psPrefixed(
  ["Microsoft.PowerShell.LocalAccounts"],
  "(Get-LocalUser -Name 'verax-svc').SID.Value",
);

function profileImagePathCommand(sid: string): string {
  return psPrefixed(
    ["Microsoft.PowerShell.Management"],
    `(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\${sid}').ProfileImagePath`,
  );
}

export type WindowsPowerShellScript = { id: string; script: string };

/**
 * Every PowerShell -Command install.ts runs, with sample paths.
 * Call sites: readWindowsMachineRoots, windowsSddlArgv, windowsSddlBatchArgv,
 * powershellStdin (account create, account update, scheduled task), ownerModeLine,
 * the service SID lookup in execute, directoryOwnerSid, the ProfileImagePath lookup,
 * and windowsServiceSid. desktop.ts local account SIDs are a separate command.
 */
export function windowsPowerShellScripts(): WindowsPowerShellScript[] {
  const temp = "C:\\ProgramData\\Verax\\install-tmp";
  return [
    { id: "machine-roots", script: MACHINE_ROOTS_SCRIPT },
    { id: "sddl", script: windowsSddlArgv("C:\\ProgramData\\Verax").at(-1) ?? "" },
    { id: "sddl-batch", script: windowsSddlBatchArgv(["C:\\ProgramData\\Verax"]).at(-1) ?? "" },
    { id: "acl-owner", script: aclOwnerCommand("C:\\ProgramData\\Verax") },
    { id: "directory-owner-sid", script: directoryOwnerSidCommand("C:\\ProgramData\\Verax") },
    { id: "service-sid", script: WINDOWS_SERVICE_SID_COMMAND },
    { id: "profile-image-path", script: profileImagePathCommand("S-1-5-21-1001") },
    { id: "account-create", script: powerShellScript(windowsAccountBody(true, temp)) },
    { id: "account-update", script: powerShellScript(windowsAccountBody(false, temp)) },
    {
      id: "scheduled-task",
      script: powerShellScript(windowsTaskBody(
        "C:\\Program Files\\nodejs\\node.exe",
        "C:\\Program Files\\Verax\\node_modules\\@verax-ai\\body\\dist\\cli.js",
        "C:\\ProgramData\\Verax\\state\\body.env",
        "C:\\ProgramData\\Verax\\state\\body.log",
      )),
    },
  ];
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

/** PowerShell single quotes: `'` is `''`. */
function psSingleQuoted(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

/** POSIX single quotes: `'` is `'\''`. */
function shSingleQuoted(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function successText(
  platform: InstallPlatform,
  info: { codeDir: string; stateDir: string; tokenPath: string; port: number },
): string {
  const origin = `http://127.0.0.1:${info.port}`;
  const claude =
    platform === "win32"
      ? `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(Get-Content -Raw ${psSingleQuoted(info.tokenPath)})"`
      : `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(cat ${shSingleQuoted(info.tokenPath)})"`;
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
      ? 'Approve held calls from the panel with a passkey. An elevated CLI approve is a fallback from a separate administrator account, not this account elevated, because that shell inherits environment variables and the PowerShell profile: & "$env:ProgramFiles\\verax-cli\\verax.cmd" approve'
      : `Approve held calls from the root-owned Node: ${posixRootOwnedCommand(platform, "approve")}`;
  const uninstall =
    platform === "win32"
      ? 'Uninstall from that copy: & "$env:ProgramFiles\\verax-cli\\verax.cmd" uninstall'
      : `Uninstall from the root-owned Node: ${posixRootOwnedCommand(platform, "uninstall")}`;
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
    uninstall,
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

function invokingIdsOf(env: NodeJS.ProcessEnv, opts: PlanOpts): { uid: number; gid: number } | { error: string } {
  const uidText = opts.invokingIds ? String(opts.invokingIds.uid) : (env.SUDO_UID?.trim() ?? "");
  const gidText = opts.invokingIds ? String(opts.invokingIds.gid) : (env.SUDO_GID?.trim() ?? "");
  if (!/^\d+$/.test(uidText) || !/^\d+$/.test(gidText)) {
    return { error: "verax install needs SUDO_UID and SUDO_GID for the invoking user" };
  }
  const uid = Number(uidText);
  const gid = Number(gidText);
  if (uid === 0) return { error: "refusing: the invoking uid is 0" };
  return { uid, gid };
}

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

/** One SDDL per line. Joined descriptors are not judged as a single ACL. */
function sddlDescriptorLines(text: string): string[] {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line !== "");
  return lines.length > 0 ? lines : [text];
}

/** Ancestors only. The code root and the state root are created by this install and are not in the list. */
function posixInstallAncestorDirs(platform: "linux" | "darwin", codeDir: string, stateDir: string, unitOrPlist: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const root of [codeDir, stateDir, unitOrPlist]) {
    for (const dir of ancestry(root, platform).slice(1)) {
      if (seen.has(dir)) continue;
      seen.add(dir);
      out.push(dir);
    }
  }
  return out;
}

function readInstallAncestor(
  dir: string,
  read: PlanOpts["ancestorStat"],
): { uid: number; mode: number; symlink: boolean } | "missing" | "unreadable" {
  if (read) {
    const st = read(dir);
    if (st === null) return "unreadable";
    return { uid: st.uid, mode: st.mode, symlink: st.symlink === true };
  }
  try {
    const st = lstatSync(dir);
    return { uid: st.uid, mode: st.mode, symlink: st.isSymbolicLink() };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    return "unreadable";
  }
}

function installAncestorPlanRefusal(
  platform: "linux" | "darwin",
  codeDir: string,
  stateDir: string,
  unitOrPlist: string,
  read: PlanOpts["ancestorStat"],
): InstallPlan | null {
  for (const dir of posixInstallAncestorDirs(platform, codeDir, stateDir, unitOrPlist)) {
    const st = readInstallAncestor(dir, read);
    if (st === "missing") continue;
    if (st === "unreadable") {
      return fail(
        EX_CONFIG,
        `refusing: ${dir} can be changed by other users (owner uid unknown, mode unknown); the service code under it could be replaced`,
      );
    }
    if (!posixOthersCanReplace(st, true)) continue;
    const mode = (st.mode & 0o7777).toString(8);
    return fail(
      EX_CONFIG,
      `refusing: ${dir} can be changed by other users (owner uid ${st.uid}, mode ${mode}); the service code under it could be replaced`,
    );
  }
  return null;
}

function tarballAclRows(opts: PlanOpts): { path: string; sddl: string; ancestor: boolean }[] {
  if (opts.tarballSddl !== undefined) return opts.tarballSddl;
  if (opts.tarballIcacls === undefined || opts.fromTarballs === undefined) return [];
  const lines = sddlDescriptorLines(opts.tarballIcacls);
  const paths = [opts.fromTarballs, ...(opts.tarballFiles ?? [])];
  if (lines.length === paths.length) {
    return lines.map((sddl, index) => ({ path: paths[index]!, sddl, ancestor: index === 0 }));
  }
  return lines.map((sddl) => ({ path: opts.fromTarballs!, sddl, ancestor: true }));
}

export function planInstall(platform: InstallPlatform, env: NodeJS.ProcessEnv, opts: PlanOpts): InstallPlan {
  const posixRoot = platform === "win32" ? undefined : opts.posixRoot;
  const fixed = fixedPosix(posixRoot);
  let machine: WindowsMachineRoots | undefined;
  if (platform === "win32") {
    try {
      machine = adoptWindowsInstallRoots(env, opts.windowsMachineRoots);
    } catch (err) {
      if (err instanceof SystemToolError) return fail(EX_CONFIG, err.message);
      throw err;
    }
  }
  const located = pathsFor(platform, env, posixRoot, opts.invokingHome, opts.userSid, machine);
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
  if (opts.nodeIcacls !== undefined) {
    for (const line of sddlDescriptorLines(opts.nodeIcacls)) {
      if (windowsUserCanWrite(line, { userSid: opts.userSid })) {
        return fail(EX_CONFIG, refuseAcl(line, nodeTrustMessageFor(opts.execPath, platform)));
      }
    }
  }
  if (opts.nodeModes !== undefined && linuxNodeUntrusted(opts.nodeModes)) {
    return fail(EX_CONFIG, nodeTrustMessageFor(opts.execPath, platform));
  }
  if (opts.fromTarballs) {
    for (const row of tarballAclRows(opts)) {
      if (windowsUserCanWrite(row.sddl, { path: row.path, userSid: opts.userSid, ancestor: row.ancestor })) {
        return fail(EX_CONFIG, refuseAcl(row.sddl, tarballTrustMessage(row.path)));
      }
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
  if (platform === "linux" || platform === "darwin") {
    const held = installAncestorPlanRefusal(
      platform,
      paths.codeDir,
      paths.stateDir,
      platform === "linux" ? fixed.systemdUnit : fixed.darwinPlist,
      opts.ancestorStat,
    );
    if (held) return held;
  }
  if (opts.stateExists && !opts.force) return fail(EX_CONFIG, `refusing: ${paths.stateDir} already exists`);
  const cliBin = cliBinFor(paths.codeDir, platform);
  const envFile = (platform === "win32" ? path.win32 : path.posix).join(paths.stateDir, "verax.env");
  const logFile = (platform === "win32" ? path.win32 : path.posix).join(paths.stateDir, "body.log");
  const winPassword = platform === "win32" ? windowsServicePassword() : "";
  const winCreate = platform === "win32" && !opts.winAccount?.exists;
  const tempDir = privateTempPath(platform, env, posixRoot, machine);
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
    const createAccount = !opts.linuxAccount?.exists;
    // The marker claims the login only after useradd has succeeded. -d / is the home uninstall re-checks.
    if (createAccount) {
      ops.push({
        op: "argv",
        argv: toolArgv("useradd", ["--system", "-U", "--no-create-home", "-d", "/", "--shell", "/usr/sbin/nologin", "verax"], "linux"),
      });
    }
    ops.push(
      {
        op: "write",
        path: path.posix.join(paths.codeDir, "install.json"),
        contents: installMarkerText(opts, paths, {
          createdUser: true,
          // -U creates the group in this install. Uninstall removes it only when the marker's gid matches.
          createdGroup: createAccount || Boolean(opts.linuxAccount?.createdGroup),
        }),
        mode: 0o644,
      },
      { op: "argv", argv: toolArgv("chown", ["verax:verax", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "linux") },
    );
  } else {
    const account = opts.darwinAccount ?? { uid: 280, gid: 280, createUser: true, createGroup: true, recordUser: true, recordGroup: true };
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
    ops.push({
      op: "write",
      path: fixed.darwinMarker,
      contents: installMarkerText(opts, paths, {
        createdUser: account.recordUser,
        createdGroup: account.recordGroup,
        accountUid: account.uid,
        accountGid: account.gid,
      }),
      mode: 0o644,
    });
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["root:wheel", fixed.darwinMarker], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0644", fixed.darwinMarker], "darwin") },
      { op: "argv", argv: toolArgv("chown", [`${DARWIN_USER}:${DARWIN_USER}`, paths.stateDir], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "darwin") },
    );
  }
  const healthNonce = randomBytes(32).toString("hex");
  const noncePath = (platform === "win32" ? path.win32 : path.posix).join(paths.stateDir, INSTALL_HEALTH_NONCE);
  let posixIds: { uid: number; gid: number } | null = null;
  if (platform === "win32") {
    if (!tokenWho || !("principal" in tokenWho) || paths.tokenPath === "") {
      return fail(EX_CONFIG, "verax install needs the invoking user's SID for the agent token");
    }
    const tokenDir = path.win32.dirname(paths.tokenPath);
    const tokenRoot = path.win32.dirname(tokenDir);
    ops.push(
      { op: "mkdir", path: tokenRoot, mode: 0o755 },
      setOwner(tokenRoot),
      adminOnlyDirGrant(tokenRoot),
      resetInherit(tokenRoot),
      { op: "mkdir", path: tokenDir, mode: 0o755 },
      setOwner(tokenDir),
      tokenUserDirGrant(tokenDir, tokenWho.principal),
      resetInherit(tokenDir),
    );
  } else {
    const ids = invokingIdsOf(env, opts);
    if ("error" in ids) return fail(EX_CONFIG, ids.error);
    posixIds = ids;
  }
  ops.push({
    op: "init",
    stateDir: paths.stateDir,
    port: limited.port,
    days: limited.days,
    force: Boolean(opts.force),
    noOwnerGrant: true,
  });
  // Before the service starts, so /healthz can echo a value only this install wrote.
  ops.push({ op: "write", path: noncePath, contents: `${healthNonce}\n`, mode: 0o600 });
  if (platform === "win32" && tokenWho && "principal" in tokenWho) {
    ops.push(
      resetInherit(paths.stateDir),
      setOwner(paths.stateDir),
      { op: "place-token", path: paths.tokenPath },
      grantFile(paths.tokenPath, tokenWho.principal, "R"),
    );
    ops.push(windowsTaskOp(winPassword, opts.execPath, cliBin, envFile, logFile, tempDir));
  } else if (platform === "linux" && posixIds) {
    const tokenDir = path.posix.dirname(paths.tokenPath);
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["-R", "verax:verax", paths.stateDir], "linux") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "linux") },
      { op: "user-token", tokenDir, tokenPath: paths.tokenPath, uid: posixIds.uid, gid: posixIds.gid },
      { op: "write", path: fixed.systemdUnit, contents: unitText(opts.execPath, cliBin, envFile, paths.stateDir, logFile), mode: 0o644 },
      { op: "argv", argv: toolArgv("systemctl", ["daemon-reload"], "linux") },
      { op: "argv", argv: toolArgv("systemctl", ["enable", "--now", "verax"], "linux") },
    );
  } else if (posixIds) {
    const tokenDir = path.posix.dirname(paths.tokenPath);
    const errFile = path.posix.join(paths.stateDir, "body.err");
    ops.push(
      { op: "argv", argv: toolArgv("chown", ["-R", `${DARWIN_USER}:${DARWIN_USER}`, paths.stateDir], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0700", paths.stateDir], "darwin") },
      { op: "user-token", tokenDir, tokenPath: paths.tokenPath, uid: posixIds.uid, gid: posixIds.gid },
      { op: "write", path: fixed.darwinPlist, contents: plistText(opts.execPath, cliBin, envFile, errFile, logFile), mode: 0o644 },
      { op: "argv", argv: toolArgv("chown", ["root:wheel", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("chmod", ["0644", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("plutil", ["-lint", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("launchctl", ["bootstrap", "system", fixed.darwinPlist], "darwin") },
      { op: "argv", argv: toolArgv("launchctl", ["enable", `system/${DARWIN_LABEL}`], "darwin") },
    );
  }
  ops.push(
    { op: "wait-healthz", port: limited.port, timeoutMs: HEALTH_WAIT_MS, nonce: healthNonce },
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
function privateTempPath(
  platform: InstallPlatform,
  env: NodeJS.ProcessEnv,
  posixRoot?: string,
  machine?: WindowsMachineRoots,
): string {
  const id = randomBytes(16).toString("hex");
  if (platform === "win32") {
    const data = (machine ?? adoptWindowsInstallRoots(env)).programData;
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
    /** Invoking user SID. Windows removes `%ProgramData%\\Verax\\agent-token\\<sid>`. */
    userSid?: string;
    windowsMachineRoots?: WindowsMachineRoots;
  },
): InstallPlan {
  let machine: WindowsMachineRoots | undefined;
  if (platform === "win32") {
    try {
      machine = adoptWindowsInstallRoots(env, opts.windowsMachineRoots);
    } catch (err) {
      if (err instanceof SystemToolError) return fail(EX_CONFIG, err.message);
      throw err;
    }
  }
  const located = pathsFor(platform, env, opts.posixRoot, undefined, opts.userSid, machine);
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
  if (platform === "win32" && paths.tokenPath !== "") {
    ops.push({ op: "remove", path: path.win32.dirname(paths.tokenPath) });
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
  const ownerAces = parseSddlAces(text);
  const svcSidKey = opts?.svcSid?.trim().replace(/^\*/, "").toUpperCase() ?? "";
  if (ownerAces !== null && untrustedOwnerCanWrite(text, ownerAces, false, svcSidKey)) {
    return fail("owner can change the object");
  }
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
  if (sid === SID_ADMINISTRATORS || sid === SID_SYSTEM || sid === SID_TRUSTED_INSTALLER) return true;
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

export function defaultExec(argv: string[], stdin?: string, env?: NodeJS.ProcessEnv, cwd?: string): ExecResult {
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

function applyLeafMode(target: string, mode: number): void {
  if (process.platform === "win32") return;
  try {
    chmodSync(target, mode);
  } catch {
    // The platform does not honour the mode bit.
  }
}

/**
 * Ancestors created along the way are 0755. Only `target` receives `mode`.
 * An existing real directory is kept and receives `mode`. A symlink or a file is EEXIST:
 * this run must not follow a link into a directory it did not create.
 */
/**
 * Create one directory. By default an existing target is EEXIST: the installer relies on that to
 * refuse a directory someone planted between its check and this call. `existingOk` (init --force)
 * keeps an existing real directory that this process's user owns.
 */
export function mkdirLeaf(target: string, mode: number, opts: { existingOk?: boolean } = {}): void {
  const parent = path.dirname(target);
  if (parent !== target && !existsSync(parent)) mkdirLeaf(parent, 0o755);
  let listed: ReturnType<typeof lstatSync> | undefined;
  try {
    listed = lstatSync(target);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (listed) {
    const ownUid = typeof process.getuid === "function" ? process.getuid() : undefined;
    const ownedHere = ownUid === undefined || listed.uid === ownUid;
    if (opts.existingOk !== true || listed.isSymbolicLink() || !listed.isDirectory() || !ownedHere) {
      const error = new Error(`EEXIST: file already exists, mkdir '${target}'`) as NodeJS.ErrnoException;
      error.code = "EEXIST";
      error.syscall = "mkdir";
      throw error;
    }
    applyLeafMode(target, mode);
    return;
  }
  mkdirSync(target, { mode });
  applyLeafMode(target, mode);
}

/** True when the body answered /healthz with this install's nonce. A bare 200 is not the service. */
export function healthzProvesService(body: string, nonce: string): boolean {
  try {
    const parsed = JSON.parse(body) as { ok?: unknown; nonce?: unknown };
    return parsed.ok === true && parsed.nonce === nonce;
  } catch {
    return false;
  }
}

function healthOnce(port: number, nonce: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = get({ host: "127.0.0.1", port, path: "/healthz", timeout: 1_000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        if (res.statusCode !== 200) {
          resolve(false);
          return;
        }
        resolve(healthzProvesService(Buffer.concat(chunks).toString("utf8"), nonce));
      });
    });
    req.once("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.once("error", () => resolve(false));
  });
}

/** Bind and release. False when something is already listening. */
export function loopbackPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createNetServer();
    server.once("error", () => resolve(false));
    server.listen(port, "127.0.0.1", () => {
      server.close(() => resolve(true));
    });
  });
}

export function serviceHealthIsNonce(port: number, nonce: string, timeoutMs = 1_000): Promise<boolean> {
  return waitHealth(port, timeoutMs, { stdout: { write() { return undefined; } }, stderr: { write() { return undefined; } } }, nonce);
}

async function waitHealth(port: number, timeoutMs: number, io: InstallIo, nonce: string): Promise<boolean> {
  const start = Date.now();
  let nextMark = 10_000;
  while (Date.now() - start < timeoutMs) {
    if (await healthOnce(port, nonce)) return true;
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
      aclOwnerCommand(dir),
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

/**
 * `getenforce` through the injected exec.
 * A missing binary, a non-zero status, or an empty answer is not "no SELinux":
 * read `/sys/fs/selinux/enforce` (1 = enforcing, 0 = permissive) before that conclusion.
 */
function selinuxMode(exec: (argv: string[]) => ExecResult): string | null {
  const ran = exec(toolArgv("getenforce", [], "linux"));
  if ((ran.status ?? 1) === 0) {
    const mode = (ran.stdout ?? "").trim();
    if (mode !== "") return mode;
  }
  const flag = exec(["/bin/cat", "/sys/fs/selinux/enforce"]);
  if ((flag.status ?? 1) !== 0) return null;
  const value = (flag.stdout ?? "").trim();
  if (value === "1") return "Enforcing";
  if (value === "0") return "Permissive";
  return null;
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
 * Permissive and Disabled are not a check. A missing getenforce still reads the kernel flag.
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
  if (label === null) return { id: "selinux", level: "warn", detail: "SELinux is Enforcing; service domain is unknown" };
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

/** Relative paths in MANIFEST.sha256. The manifest is written with forward slashes. */
function manifestCodeFiles(root: string): string[] {
  let text: string;
  try {
    text = readFileSync(path.win32.join(root, "MANIFEST.sha256"), "utf8");
  } catch {
    return [];
  }
  const files: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const sp = line.indexOf("  ");
    if (sp < 0) continue;
    const rel = line.slice(sp + 2).trim().replaceAll("\\", "/");
    const parts = rel.split("/");
    if (rel === "" || parts.some((part) => part === "" || part === "." || part === "..")) continue;
    files.push(path.win32.join(root, ...parts));
  }
  return files;
}

/** Files whose DACL must match the directory grant. Missing files are skipped by the caller. */
export function serviceAclFiles(root: string, kind: "code" | "state"): string[] {
  if (kind === "code") {
    const body = path.win32.join(root, "node_modules", "@verax-ai", "body");
    const listed = [
      path.win32.join(body, "package.json"),
      path.win32.join(body, "dist", "cli.js"),
      ...manifestCodeFiles(root),
    ];
    const seen = new Set<string>();
    const files: string[] = [];
    for (const file of listed) {
      const key = file.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      files.push(file);
    }
    return files;
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

/** A grant to the service account. Other `(OI)(CI)` grants (Administrators, the token folder's user) are not one. */
function serviceGrantKind(argv: readonly string[], svcSid: string): "code" | "state" | null {
  if (svcSid === "") return null;
  for (const arg of argv) {
    const match = /^\*(S-1-[0-9-]+):\(OI\)\(CI\)(RX|F)$/.exec(arg);
    if (!match || match[1]!.toUpperCase() !== svcSid.toUpperCase()) continue;
    return match[2] === "RX" ? "code" : "state";
  }
  return null;
}

type CreatedThisRun = {
  linuxUser: boolean;
  linuxGroup: boolean;
  /** uid/gid read after this run's useradd. Rollback deletes only these ids. */
  linuxUid?: number;
  linuxGid?: number;
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
    const pinsGroup = argv.includes("-U") || argv.includes("--user-group");
    const suppressesGroup = argv.includes("-N") || argv.includes("--no-user-group");
    if (pinsGroup && !suppressesGroup) created.linuxGroup = true;
  }
  if (tool === "groupadd" && argv[argv.length - 1] === "verax") created.linuxGroup = true;
  if (tool === "dscl" && argv.includes("-create")) {
    if (argv.includes(`/Users/${DARWIN_USER}`)) created.darwinUser = true;
    if (argv.includes(`/Groups/${DARWIN_USER}`)) created.darwinGroup = true;
  }
  if (tool === "powershell" && argv.some((arg) => arg.includes("New-LocalUser"))) created.winAccount = true;
  if (tool === "powershell" && argv.some((arg) => arg.includes("Register-ScheduledTask"))) created.winTask = true;
  if (tool === "launchctl" && argv.includes("bootstrap")) created.darwinService = true;
  if (tool === "systemctl" && argv.includes("enable") && argv.includes("--now")) created.linuxService = true;
}

/** Read the ids useradd just produced. Uninstall and rollback delete only these. */
function captureLinuxIds(created: CreatedThisRun, exec: ToolExec): void {
  if (created.linuxUser && created.linuxUid === undefined) {
    const account = linuxPasswdLine(exec);
    if (account) created.linuxUid = account.uid;
  }
  if (created.linuxGroup && created.linuxGid === undefined) {
    const gid = linuxGroupGid(exec);
    if (gid !== null) created.linuxGid = gid;
  }
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
type MarkerPrior = { path: string; prior: string | null };

function isInstallMarker(file: string): boolean {
  return /[/\\]install\.json$/i.test(file);
}

/** Put the service SID captured at create into a marker that claims the Windows account. */
function stampAccountSid(contents: string, sid: string): string {
  try {
    const parsed = JSON.parse(contents) as Record<string, unknown>;
    if (parsed.createdAccount !== true) return contents;
    if (typeof parsed.accountSid === "string" && parsed.accountSid !== "") return contents;
    parsed.accountSid = sid;
    return `${JSON.stringify(parsed, null, 2)}\n`;
  } catch {
    return contents;
  }
}

/** Record the uid and gid this run's useradd produced. A later reinstall keeps ids already in the text. */
function stampLinuxAccountIds(contents: string, created: CreatedThisRun): string {
  try {
    const parsed = JSON.parse(contents) as Record<string, unknown>;
    if (parsed.createdUser === true && created.linuxUid !== undefined && typeof parsed.accountUid !== "number") {
      parsed.accountUid = created.linuxUid;
    }
    if (parsed.createdGroup === true && created.linuxGid !== undefined && typeof parsed.accountGid !== "number") {
      parsed.accountGid = created.linuxGid;
    }
    return `${JSON.stringify(parsed, null, 2)}\n`;
  } catch {
    return contents;
  }
}

function restoreInstallMarker(saved: MarkerPrior | null, io: InstallIo): void {
  if (!saved) return;
  if (saved.prior === null) {
    removeRollbackPath(saved.path, io);
    return;
  }
  try {
    mkdirSync(path.dirname(saved.path), { recursive: true });
    writeFileSync(saved.path, saved.prior);
  } catch (err) {
    const message = err instanceof Error ? err.message : "restore failed";
    io.stderr.write(`rm exit 1: ${message}\n`);
  }
}

function rollbackCreatedThisRun(
  created: CreatedThisRun,
  plan: { codeDir: string; stateDir: string },
  call: ToolExec,
  io: InstallIo,
  markerPrior: MarkerPrior | null,
): void {
  const ignore = (argv: string[]): void => {
    call(argv);
  };
  const best = (argv: string[]): void => {
    const ran = call(argv);
    if ((ran.status ?? 1) === 0 || removalAlreadyGone(argv, ran)) return;
    reportToolFailure(io, argv, ran);
  };
  if (created.linuxService || created.linuxUser) ignore(toolArgv("systemctl", ["disable", "--now", "verax"], "linux"));
  if (created.darwinService) ignore(toolArgv("launchctl", ["bootout", `system/${DARWIN_LABEL}`], "darwin"));
  if (created.winTask) {
    ignore(toolArgv("schtasks", ["/End", "/TN", TASK_NAME], "win32"));
    ignore(toolArgv("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"], "win32"));
  }
  if (created.linuxUser) {
    const verdict = linuxUserVerdict(call, created.linuxUid);
    if (verdict.remove) best(toolArgv("userdel", ["verax"], "linux"));
  }
  if (created.linuxGroup) {
    const verdict = linuxGroupVerdict(call, created.linuxGid);
    if (verdict.remove) best(toolArgv("groupdel", ["verax"], "linux"));
  }
  if (created.darwinUser) best(toolArgv("dscl", [".", "-delete", `/Users/${DARWIN_USER}`], "darwin"));
  if (created.darwinGroup) best(toolArgv("dscl", [".", "-delete", `/Groups/${DARWIN_USER}`], "darwin"));
  if (created.winAccount) best(toolArgv("net", ["user", VERAX_SVC, "/delete"], "win32"));
  restoreInstallMarker(markerPrior, io);
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
  spawnUserToken?: (spec: UserTokenSpawn) => ExecResult,
): Promise<number> {
  const tempStep = plan.ops.find((op): op is Extract<PlanOp, { op: "private-temp" }> => op.op === "private-temp");
  const tempDir = tempStep?.path;
  const call: ToolExec = (argv, stdin, env, cwd) => {
    if (env) return exec(argv, stdin, env, cwd);
    if (!tempDir) return exec(argv, stdin, undefined, cwd);
    return exec(argv, stdin, systemToolEnv(platform, tempDir), cwd);
  };
  let svcSid = "";
  let winSid = "";
  let markerPrior: MarkerPrior | null = null;
  const serviceArgv = (argv: string[]): string[] | { error: string } => {
    if (!argv.some((arg) => arg.startsWith(`${VERAX_SVC}:`))) return argv;
    if (svcSid === "") {
      const ran = call(toolArgv("powershell", [
        "-NoProfile",
        "-Command",
        WINDOWS_SERVICE_SID_COMMAND,
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
        if (!failed) {
          const printed = /VERAX_SVC_SID:(S-1-[0-9-]+)/i.exec(ran.stdout ?? "");
          if (printed?.[1]) winSid = printed[1].toUpperCase();
          rememberCreatedAccount(created, resolved);
        }
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
      // Only the service's own roots carry the svc grant; the agent-token folder does not.
      const serviceRoot = resolved[1] === plan.stateDir || resolved[1] === plan.codeDir;
      const grantKind = platform === "win32" && serviceRoot ? serviceGrantKind(resolved, svcSid) : null;
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
      if (platform === "linux") captureLinuxIds(created, call);
      continue;
    }
    if (step.op === "write") {
      const service = step.path.endsWith("/verax.service") || step.path.endsWith("/com.verax-ai.body.plist");
      const priorService = service && existsSync(step.path);
      let contents = step.contents;
      if (isInstallMarker(step.path)) {
        if (markerPrior === null) {
          let prior: string | null = null;
          try {
            prior = readFileSync(step.path, "utf8");
          } catch {
            prior = null;
          }
          markerPrior = { path: step.path, prior };
        }
        if (winSid !== "") contents = stampAccountSid(contents, winSid);
        if (platform === "linux") contents = stampLinuxAccountIds(contents, created);
      }
      mkdirSync(path.dirname(step.path), { recursive: true });
      writeFileSync(step.path, contents, { encoding: "utf8", mode: step.mode ?? 0o644, flag: step.exclusive ? "wx" : "w" });
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
        { quiet: true, noOwnerGrant: step.noOwnerGrant, env: installEnv },
      );
      if (code !== 0) return finish(code);
      continue;
    }
    if (step.op === "place-token") {
      const placed = placeInstalledToken(plan.stateDir, step.path, platform);
      if (!placed.ok) {
        io.stderr.write(placed.error.endsWith("\n") ? placed.error : `${placed.error}\n`);
        return finish(EX_CONFIG);
      }
      continue;
    }
    if (step.op === "user-token") {
      if (step.uid === 0) {
        io.stderr.write("refusing: the invoking uid is 0\n");
        return finish(EX_CONFIG);
      }
      const stateToken = path.posix.join(plan.stateDir, "local-issuer", "agent.token");
      let token = "";
      try {
        token = readFileSync(stateToken, "utf8");
      } catch {
        io.stderr.write("agent token was not created in the state directory\n");
        return finish(EX_CONFIG);
      }
      const spec: UserTokenSpawn = {
        uid: step.uid,
        gid: step.gid,
        tokenDir: step.tokenDir,
        tokenPath: step.tokenPath,
        token,
      };
      const ran = spawnUserToken
        ? spawnUserToken(spec)
        : spawnSync(process.execPath, ["--input-type=module", "-e", USER_TOKEN_WRITER], {
            uid: step.uid,
            gid: step.gid,
            input: token,
            encoding: "utf8",
            shell: false,
            windowsHide: true,
            env: { VERAX_TOKEN_DIR: step.tokenDir, VERAX_TOKEN_PATH: step.tokenPath },
          });
      if ((ran.status ?? 1) !== 0) {
        const detail = `${ran.stderr || ran.stdout || "token was not written"}`.trim();
        io.stderr.write(detail.endsWith("\n") ? detail : `${detail}\n`);
        return finish(EX_CONFIG);
      }
      continue;
    }
    if (step.op === "remove") {
      rmSync(step.path, { recursive: true, force: true });
      continue;
    }
    if (step.op === "wait-healthz") {
      if (!(await waitHealth(step.port, healthTimeoutMs ?? step.timeoutMs, io, step.nonce))) {
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
    if (status !== 0) rollbackCreatedThisRun(created, plan, call, io, markerPrior);
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
  extra?: {
    createdAccount?: boolean;
    createdUser?: boolean;
    createdGroup?: boolean;
    accountUid?: number;
    accountGid?: number;
    accountSid?: string;
  },
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
  if (extra?.accountUid !== undefined) body.accountUid = extra.accountUid;
  if (extra?.accountGid !== undefined) body.accountGid = extra.accountGid;
  if (extra?.accountSid) body.accountSid = extra.accountSid;
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

function markerFlags(file: string): {
  createdAccount: boolean;
  createdUser: boolean;
  createdGroup: boolean;
  accountUid?: number;
  accountGid?: number;
  accountSid?: string;
} {
  const empty = { createdAccount: false, createdUser: false, createdGroup: false };
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as {
      createdAccount?: unknown;
      createdUser?: unknown;
      createdGroup?: unknown;
      accountUid?: unknown;
      accountGid?: unknown;
      accountSid?: unknown;
    };
    const uid = typeof parsed.accountUid === "number" && Number.isInteger(parsed.accountUid) ? parsed.accountUid : undefined;
    const gid = typeof parsed.accountGid === "number" && Number.isInteger(parsed.accountGid) ? parsed.accountGid : undefined;
    const sid = typeof parsed.accountSid === "string" && /^S-1-[0-9-]+$/i.test(parsed.accountSid) ? parsed.accountSid.toUpperCase() : undefined;
    return {
      createdAccount: parsed.createdAccount === true,
      createdUser: parsed.createdUser === true,
      createdGroup: parsed.createdGroup === true,
      ...(uid !== undefined ? { accountUid: uid } : {}),
      ...(gid !== undefined ? { accountGid: gid } : {}),
      ...(sid !== undefined ? { accountSid: sid } : {}),
    };
  } catch {
    return empty;
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

/**
 * By-path chown and chmod. `ensureTokenParent` does not run these.
 * It opens the directory and changes that descriptor.
 */
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

/** Owner SID of an existing directory, and the SID of this process. */
export function windowsDirectorySids(
  dir: string,
  exec: (argv: string[]) => ExecResult = defaultExec,
): { ownerSid: string | undefined; invokingSid: string | undefined } {
  return {
    ownerSid: directoryOwnerSid(dir, exec),
    invokingSid: invokingSid(exec),
  };
}

function directoryOwnerSid(dir: string, exec: (argv: string[]) => ExecResult): string | undefined {
  const cached = winOwnerCache?.owners;
  if (cached?.has(dir)) return cached.get(dir);
  const ran = exec(toolArgv("powershell", [
    "-NoProfile",
    "-Command",
    directoryOwnerSidCommand(dir),
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
 * POSIX directory is given to the invoking uid and mode 0700 through the
 * directory descriptor, after the dev/ino is checked against the lstat.
 * `beforeChange` runs after that lstat and the owner check, before the descriptor
 * is opened. Tests use it to swap the directory.
 */
export function ensureTokenParent(
  dir: string,
  env: NodeJS.ProcessEnv = process.env,
  exec: ToolExec = defaultExec,
  beforeChange?: () => void,
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
  if (platform === "win32") return;
  const repair = st.uid === 0 && invokingUid !== undefined && invokingUid !== 0;
  if (!repair && !beforeChange) return;
  beforeChange?.();
  const fd = openTokenParentNoFollow(dir);
  try {
    const opened = fstatSync(fd);
    if (!opened.isDirectory() || opened.dev !== st.dev || opened.ino !== st.ino) {
      throw new SystemToolError(`refusing: ${dir} dev/ino mismatch`);
    }
    if (!repair || invokingUid === undefined) return;
    try {
      fchownSync(fd, invokingUid, -1);
      fchmodSync(fd, 0o700);
    } catch (err) {
      const message = err instanceof Error ? err.message : "chown failed";
      throw new SystemToolError(message.trim() || "chown failed");
    }
  } finally {
    closeSync(fd);
  }
}

/** Directory descriptor for the lstat'd inode. A symlink is a dev/ino mismatch. */
function openTokenParentNoFollow(dir: string): number {
  const directory = constants.O_DIRECTORY ?? 0;
  const nofollow = constants.O_NOFOLLOW ?? 0;
  try {
    return openSync(dir, constants.O_RDONLY | directory | nofollow);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "ENOTDIR" || code === "ENOENT") {
      throw new SystemToolError(`refusing: ${dir} dev/ino mismatch`);
    }
    throw err;
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

/** Resolved path: root-owned and not group- or other-writable. A sticky ancestor is kept. The symlink itself is not the object. */
function posixEntryUntrusted(file: string, ancestor: boolean): boolean {
  try {
    const st = lstatSync(file);
    return posixOthersCanReplace({ uid: st.uid, mode: st.mode, symlink: st.isSymbolicLink() }, ancestor);
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
/**
 * Owner, Administrators and SYSTEM only. A directory that already holds files needs `directory`:
 * the grants then carry `(OI)(CI)`, so its children inherit them. Without it `/inheritance:r`
 * leaves every existing child with an empty DACL.
 */
export function restrictToOwnerWin32(target: string, spawn: ToolSpawn = defaultToolSpawn, directory = false): void {
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
  const rights = directory ? "(OI)(CI)F" : "F";
  const ran = spawn(icacls, [target, "/inheritance:r", "/grant:r", `*${sid}:${rights}`, `${ADMINISTRATORS_SID}:${rights}`, `${SYSTEM_SID}:${rights}`], opts);
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

/** The SID `whoami /user` names for this process. */
export function windowsInvokingSid(exec: (argv: string[]) => ExecResult = defaultExec): string | undefined {
  return invokingSid(exec);
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
): { dir: string; files: string[]; digests: { file: string; sha256: string }[]; sddl?: { path: string; sddl: string; ancestor: boolean }[]; modes?: { uid: number; mode: number }[] } | { error: true; code: number } {
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
    const rows: { path: string; sddl: string; ancestor: boolean }[] = [];
    for (const file of targets) {
      const acl = sddl?.get(file) ?? { status: 1, text: "" };
      const text = acl.text;
      const ancestor = file === dir;
      if (acl.status !== 0 || windowsUserCanWrite(text, { path: file, userSid: sid, ancestor })) {
        io.stderr.write(`${refuseAcl(text, tarballTrustMessage(file))}\n`);
        return { error: true, code: EX_CONFIG };
      }
      rows.push({ path: file, sddl: text, ancestor });
    }
    const hashed = hashTarballDigests(files, io);
    if ("error" in hashed) {
      io.stderr.write(hashed.error.endsWith("\n") ? hashed.error : `${hashed.error}\n`);
      return { error: true, code: EX_CONFIG };
    }
    return { dir, files, digests: hashed.digests, sddl: rows };
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

/**
 * Whether the user can change each code directory. Windows reads every SDDL the
 * check needs in one PowerShell process: one per path cost minutes on an elevated approve.
 */
function codeDirsWritable(dirs: readonly string[], platform: InstallPlatform, exec: ToolExec): (dir: string) => string | false {
  if (platform !== "win32") {
    return (dir) => posixCodeDirectoryDetail(dir, platform, (file) => {
      try {
        const st = lstatSync(file);
        return { uid: st.uid, mode: st.mode, symlink: st.isSymbolicLink() };
      } catch {
        return null;
      }
    });
  }
  const sid = invokingSid(exec);
  const read = readSddlBatch(exec, dirs.flatMap((dir) => trustTargets(dir, "win32").map((file) => file.path)));
  return (dir) => {
    for (const file of trustTargets(dir, "win32")) {
      const hit = sddlOrMiss(read, file.path);
      if (hit.status !== 0) return `${file.path}: ACL could not be read`;
      if (windowsUserCanWrite(hit.text, { path: file.path, userSid: sid, ancestor: file.ancestor })) return `${file.path}: ${hit.text.trim()}`;
    }
    return false;
  };
}

const PRELOAD_FLAGS = new Set(["--require", "-r", "--import", "--loader", "--experimental-loader"]);

/**
 * Code which already ran can hide itself: a preload can clear `NODE_OPTIONS` and
 * `execArgv` before this function reads them. This catches only what is still set.
 */
export function elevatedPreloadRefusal(env: NodeJS.ProcessEnv, execArgv: readonly string[]): string | null {
  const options = env.NODE_OPTIONS ?? "";
  const flagged = execArgv.some((arg) => PRELOAD_FLAGS.has((arg.split("=", 1)[0] ?? arg)));
  if (options.trim() !== "" || flagged) {
    return "refusing: NODE_OPTIONS or a preload flag is set; an elevated verax runs with none";
  }
  // NODE_PATH adds the caller's directories to the module search list of an elevated process.
  if ((env.NODE_PATH ?? "").trim() !== "") {
    return "refusing: NODE_PATH is set; an elevated verax resolves modules only from its own install";
  }
  return null;
}

export type NodeTrustProbe = {
  execPath?: string;
  execPathProbe?: (file: string) => boolean;
  execArgv?: readonly string[];
};

function nodeBinaryUntrusted(
  platform: InstallPlatform,
  execPath: string,
  exec: ToolExec,
  probe?: (file: string) => boolean,
): string | null {
  const files = trustTargets(execPath, platform);
  let hit: string | null = null;
  if (probe) {
    for (const file of files) {
      if (probe(file.path) && hit === null) hit = file.path;
    }
  } else if (platform === "win32") {
    let sid: string | undefined;
    try {
      sid = invokingSid(exec);
    } catch {
      sid = undefined;
    }
    const read = readSddlBatch(exec, files.map((file) => file.path));
    for (const file of files) {
      const acl = sddlOrMiss(read, file.path);
      if (acl.status !== 0 || windowsUserCanWrite(acl.text, { path: file.path, userSid: sid, ancestor: file.ancestor })) {
        hit = file.path;
        break;
      }
    }
  } else {
    for (const file of files) {
      if (posixEntryUntrusted(file.path, file.ancestor)) {
        hit = file.path;
        break;
      }
    }
  }
  return hit === null ? null : nodeTrustMessageFor(hit, platform);
}

export function refuseWritableCode(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  exec: ToolExec,
  probe?: (dir: string) => boolean,
  node?: NodeTrustProbe,
): string | null {
  if (platform !== "win32" && platform !== "linux" && platform !== "darwin") return null;
  const spec = platform;
  const dirs = veraxCodeDirectories();
  const codeRefusal = elevatedCodeRefusal(spec, dirs, {
    account: codeTrustAccount(platform, env),
    ...(probe ? { probe } : { userWritable: codeDirsWritable(dirs, spec, exec) }),
  });
  if (codeRefusal) return codeRefusal;
  // A code probe that does not pass execArgv is stubbing the gate. Production reads process.execArgv.
  const execArgv = node?.execArgv ?? (probe ? [] : process.execArgv);
  const preload = elevatedPreloadRefusal(env, execArgv);
  if (preload) return preload;
  // A code probe with no Node probe is a test stubbing directories. Production passes neither.
  if (probe && !node?.execPathProbe) return null;
  return nodeBinaryUntrusted(spec, node?.execPath ?? process.execPath, exec, node?.execPathProbe);
}

/** Elevated approve uses the process exec. Install and uninstall pass their own. */
export function elevatedCommandCodeRefusal(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  probe?: (dir: string) => boolean,
  node?: NodeTrustProbe,
): string | null {
  return refuseWritableCode(platform, env, defaultExec, probe, node);
}

/**
 * True when `posixOthersCanReplace` would refuse this entry, except a non-root owner
 * the invoking user is not: the installed state directory is owned by the service account.
 * Unknown invoking uid refuses every non-root owner, because that owner may be the user.
 */
function posixStateUntrusted(
  st: { uid: number; mode: number; symlink?: boolean },
  ancestor: boolean,
  invokingUid: number | null,
): boolean {
  if (!posixOthersCanReplace(st, ancestor)) return false;
  if (st.symlink) return true;
  if ((st.mode & 0o022) !== 0) return true;
  if (invokingUid === null) return true;
  return st.uid === invokingUid;
}

function invokingUserCanChangeState(dir: string, platform: NodeJS.Platform, env: NodeJS.ProcessEnv): boolean {
  if (platform !== "win32" && platform !== "linux" && platform !== "darwin") return false;
  try {
    if (lstatSync(dir).isSymbolicLink()) return true;
  } catch {
    return true;
  }
  const spec = platform;
  if (spec === "win32") {
    const files = trustTargets(dir, spec);
    let sid: string | undefined;
    try {
      sid = invokingSid(defaultExec);
    } catch {
      sid = undefined;
    }
    const read = readSddlBatch(defaultExec, files.map((file) => file.path));
    for (const file of files) {
      const acl = sddlOrMiss(read, file.path);
      if (acl.status !== 0 || windowsUserCanWrite(acl.text, { path: file.path, userSid: sid, ancestor: file.ancestor })) {
        return true;
      }
    }
    return false;
  }
  const uidText = env.SUDO_UID?.trim() ?? "";
  const invokingUid = /^\d+$/.test(uidText) ? Number(uidText) : null;
  for (const file of trustTargets(dir, spec)) {
    let st: ReturnType<typeof lstatSync>;
    try {
      st = lstatSync(file.path);
    } catch {
      return true;
    }
    if (posixStateUntrusted({ uid: st.uid, mode: st.mode, symlink: st.isSymbolicLink() }, file.ancestor, invokingUid)) {
      return true;
    }
  }
  return false;
}

/** Elevated approve opens a state directory only when the invoking user cannot change it. */
export function elevatedStateDirRefusal(
  dir: string,
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  probe?: (dir: string) => boolean,
): string | null {
  const writable = probe ? probe(dir) : invokingUserCanChangeState(dir, platform, env);
  if (!writable) return null;
  return `refusing: ${dir} can be changed by ${codeTrustAccount(platform, env)}; an elevated approve only opens the installed state directory`;
}

/**
 * Set by the CLI after one passing code check, so install and approve do not
 * run the same check again in that process. Cleared when the command returns.
 */
let cliCodeCheckPassed = false;

export function markCliCodeCheckPassed(): void {
  cliCodeCheckPassed = true;
}

export function clearCliCodeCheckPassed(): void {
  cliCodeCheckPassed = false;
}

export function cliCodeCheckPassedAlready(): boolean {
  return cliCodeCheckPassed;
}

/**
 * The ancestor rule the installer applies to ProgramData: a non-administrator
 * who can replace or re-point an ancestor is a refusal. A path whose ACL
 * cannot be read is a refusal too.
 */
export function windowsProgramDataRefusal(
  env: NodeJS.ProcessEnv,
  exec: ToolExec = defaultExec,
  machine?: WindowsMachineRoots,
): string | null {
  let data: string;
  try {
    data = adoptWindowsInstallRoots(env, machine ?? readWindowsMachineRoots(exec)).programData;
  } catch (err) {
    if (err instanceof SystemToolError) return err.message.endsWith("\n") ? err.message.slice(0, -1) : err.message;
    throw err;
  }
  const targets = trustTargets(data, "win32").map((entry) => ({ path: entry.path, ancestor: true }));
  let sid: string | undefined;
  try {
    sid = invokingSid(exec);
  } catch {
    sid = undefined;
  }
  const cache = readSddlBatch(exec, targets.map((entry) => entry.path));
  for (const file of targets) {
    const acl = sddlOrMiss(cache, file.path);
    if (acl.status !== 0 || windowsUserCanWrite(acl.text, { path: file.path, userSid: sid, ancestor: true })) {
      const line = refuseAcl(acl.text, `refusing: ${file.path} can be changed by a non-administrator`);
      return line.endsWith("\n") ? line.slice(0, -1) : line;
    }
  }
  return null;
}

function resolveInvokingIds(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  exec: ToolExec,
): { uid: number; gid: number } | { error: string } {
  const user = env.SUDO_USER?.trim() ?? "";
  const sudoUid = env.SUDO_UID?.trim() ?? "";
  const sudoGid = env.SUDO_GID?.trim() ?? "";
  if (user === "" || !/^\d+$/.test(sudoUid) || !/^\d+$/.test(sudoGid)) {
    return { error: "verax install needs SUDO_USER, SUDO_UID, and SUDO_GID" };
  }
  const spec = platform === "darwin" ? "darwin" : "linux";
  const uidRan = exec(toolArgv("id", ["-u", user], spec));
  const gidRan = exec(toolArgv("id", ["-g", user], spec));
  const uid = (uidRan.stdout ?? "").trim();
  const gid = (gidRan.stdout ?? "").trim();
  if ((uidRan.status ?? 1) !== 0 || (gidRan.status ?? 1) !== 0 || !/^\d+$/.test(uid) || !/^\d+$/.test(gid)) {
    return { error: `verax install could not read the uid of ${user} from id` };
  }
  if (uid !== sudoUid || gid !== sudoGid) {
    return { error: `refusing: id for ${user} is ${uid}:${gid}, not SUDO_UID ${sudoUid} SUDO_GID ${sudoGid}` };
  }
  if (Number(uid) === 0) return { error: "refusing: the invoking uid is 0" };
  return { uid: Number(uid), gid: Number(gid) };
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
  if (!cliCodeCheckPassed) {
    const codeRefusal = refuseWritableCode(platform, env, hooks.exec ?? defaultExec, hooks.codeProbe, {
      execPathProbe: hooks.execPathProbe,
      execArgv: hooks.execArgv,
    });
    if (codeRefusal) {
      io.stderr.write(codeRefusal.endsWith("\n") ? codeRefusal : `${codeRefusal}\n`);
      return EX_CONFIG;
    }
  }
  const parsed = parseInstallArgs(argv);
  if ("error" in parsed) {
    io.stderr.write(`${parsed.error}\n`);
    return EX_CONFIG;
  }
  if (!(await loopbackPortFree(parsed.port))) {
    io.stderr.write(`port-busy:${parsed.port}\n`);
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
  let stateDir: string;
  let adopted: WindowsMachineRoots | undefined;
  try {
    if (platform === "win32") windowsSystemRoot(plannedEnv);
    if (platform === "win32") adopted = adoptWindowsInstallRoots(plannedEnv, hooks.windowsMachineRoots ?? readWindowsMachineRoots(exec));
    stateDir = stateDirFor(platform, plannedEnv, posixRoot, adopted);
  } catch (err) {
    if (err instanceof SystemToolError) {
      io.stderr.write(err.message.endsWith("\n") ? err.message : `${err.message}\n`);
      return EX_CONFIG;
    }
    throw err;
  }
  const exists = hooks.stateExists ? hooks.stateExists(stateDir) : existsSync(stateDir);
  const trustPlat = platform === "win32" || platform === "linux" || platform === "darwin" ? platform as InstallPlatform : null;
  const trustFiles = trustPlat ? [...trustTargets(layout.execPath, trustPlat), ...trustTargets(layout.npmCli, trustPlat)] : [];
  if (platform === "win32") {
    try {
      const sys = windowsSystemRoot(plannedEnv);
      const data = adopted?.programData ?? adoptWindowsInstallRoots(plannedEnv, hooks.windowsMachineRoots).programData;
      const filesRoot = adopted?.programFiles ?? adoptWindowsInstallRoots(plannedEnv, hooks.windowsMachineRoots).programFiles;
      trustFiles.push(...trustTargets(path.win32.join(sys, "System32"), "win32"));
      for (const name of WIN32_TOOLS) trustFiles.push(...trustTargets(winToolUnder(sys, name), "win32"));
      // PowerShell 5.1 autoloads from here before System32, whatever PSModulePath says.
      const sharedModules = path.win32.join(filesRoot, "WindowsPowerShell", "Modules");
      if ((hooks.moduleDirExists ?? existsSync)(sharedModules)) trustFiles.push(...trustTargets(sharedModules, "win32"));
      // The install roots are parents of what the installer creates and locks, and stock ProgramData lets Users create
      // folders. They are judged by the ancestor rule (no write-DAC, owner or delete-child for a non-admin), not as objects.
      for (const root of [data, filesRoot]) {
        trustFiles.push(...trustTargets(root, "win32").map((entry) => ({ ...entry, ancestor: true })));
      }
    } catch (err) {
      if (err instanceof SystemToolError) {
        io.stderr.write(err.message.endsWith("\n") ? err.message : `${err.message}\n`);
        return EX_CONFIG;
      }
      throw err;
    }
  }
  if (trustPlat) {
    // npm (run by this install) and the installed body resolve bare specifiers
    // through every ancestor's node_modules. Each one on disk is judged as an object.
    const moduleExists = hooks.moduleDirExists ?? existsSync;
    const starts = [
      (trustPlat === "win32" ? path.win32 : path.posix).dirname(layout.npmCli),
      codeDirFor(trustPlat, plannedEnv, posixRoot, adopted),
    ];
    const seen = new Set<string>();
    for (const dir of starts.flatMap((start) => moduleSearchDirs(start, trustPlat, moduleExists))) {
      const key = trustPlat === "win32" ? dir.toLowerCase() : dir;
      if (seen.has(key)) continue;
      seen.add(key);
      trustFiles.push(...trustTargets(dir, trustPlat));
    }
  }
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
          const said = isModuleSearchDir(file.path) ? moduleDirTrustMessage(file.path, "win32") : nodeTrustMessage(file.path);
          io.stderr.write(`${refuseAcl(acl.text, said)}\n`);
          return EX_CONFIG;
        }
      }
    } else {
      for (const file of trustFiles) {
        if (posixEntryUntrusted(file.path, file.ancestor)) {
          const said = isModuleSearchDir(file.path) ? moduleDirTrustMessage(file.path, trustPlat) : nodeTrustMessageFor(file.path, trustPlat);
          io.stderr.write(`${said}\n`);
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
      profileImagePathCommand(sid),
    ], "win32"));
    // The agent token no longer lives in the profile (R14-8), so an unreadable
    // ProfileImagePath is not a refusal; a readable one that disagrees still is.
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
  let invokingIds: { uid: number; gid: number } | undefined;
  if (platform === "linux" || platform === "darwin") {
    const checked = resolveInvokingIds(platform, plannedEnv, exec);
    if ("error" in checked) {
      io.stderr.write(`${checked.error}\n`);
      return EX_CONFIG;
    }
    invokingIds = checked;
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
    invokingIds,
    ancestorStat: hooks.ancestorStat,
    windowsMachineRoots: adopted,
    ...(packed && !("error" in packed)
      ? { fromTarballs: packed.dir, tarballFiles: packed.files, tarballDigests: packed.digests, tarballSddl: packed.sddl, tarballModes: packed.modes }
      : {}),
  });
  if (!plan.ok) {
    io.stderr.write(plan.message);
    return plan.code;
  }
  return execute(plan, exec, io, platform, hooks.copyFile ?? copyFileSync, plannedEnv, hooks.healthTimeoutMs, hooks.spawnUserToken);
}

/** A non-zero tool result that means the install artifact is already gone. */
function toolAlreadyAbsent(ran: ExecResult): boolean {
  if ((ran.status ?? 1) === 0) return false;
  const text = `${ran.stdout ?? ""}\n${ran.stderr ?? ""}`.toLowerCase();
  if (text.trim() === "") return true;
  return /cannot find the file specified|does not exist|could not be found|could not find|no such file|not found|not loaded|isn't loaded|is not loaded/.test(text);
}

/** userdel, groupdel, `net user /delete`, and `dscl -delete`. Empty output is not absence. */
function isAccountDeleteArgv(argv: readonly string[]): boolean {
  const tool = systemToolName(argv[0] ?? "");
  if (tool === "userdel" || tool === "groupdel") return true;
  if (tool === "net" && argv.some((arg) => arg.toLowerCase() === "/delete")) return true;
  if (tool === "dscl" && argv.includes("-delete")) return true;
  return false;
}

/**
 * A delete that failed is not "already gone".
 * userdel and groupdel document exit 6 as "no such user/group".
 * Other tools need text that names a missing account.
 */
function accountDeleteAlreadyGone(argv: readonly string[], ran: ExecResult): boolean {
  if ((ran.status ?? 1) === 0) return false;
  const tool = systemToolName(argv[0] ?? "");
  if ((tool === "userdel" || tool === "groupdel") && ran.status === 6) return true;
  const text = `${ran.stdout ?? ""}\n${ran.stderr ?? ""}`.toLowerCase();
  if (text.trim() === "") return false;
  return /cannot find the file specified|does not exist|could not be found|could not find|no such (user|group|file)|not found|the user name could not be found|edsrecordnotfound/.test(text);
}

function removalAlreadyGone(argv: readonly string[], ran: ExecResult): boolean {
  if (isAccountDeleteArgv(argv)) return accountDeleteAlreadyGone(argv, ran);
  return toolAlreadyAbsent(ran);
}

function reportToolFailure(io: InstallIo, argv: readonly string[], ran: ExecResult): void {
  const tool = systemToolName(argv[0] ?? "") || (argv[0] ?? "command");
  const code = ran.status ?? 1;
  const err = `${ran.stderr ?? ""}`.replace(/\s+$/, "");
  io.stderr.write(err === "" ? `${tool} exit ${code}\n` : `${tool} exit ${code}: ${err}\n`);
}

const LINUX_SYSTEM_ID_MAX = 999;
const LINUX_NOLOGIN = "/usr/sbin/nologin";

function linuxSystemId(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= LINUX_SYSTEM_ID_MAX;
}

function linuxPasswdLine(exec: ToolExec): { uid: number; home: string; shell: string } | null {
  const ran = exec(toolArgv("getent", ["passwd", "verax"], "linux"));
  if ((ran.status ?? 1) !== 0) return null;
  const line = (ran.stdout ?? "").split(/\r?\n/).find((row) => row.startsWith("verax:"));
  if (!line) return null;
  const parts = line.split(":");
  if (parts.length < 7) return null;
  const uid = Number(parts[2]);
  if (!Number.isInteger(uid)) return null;
  return { uid, home: parts[5] ?? "", shell: parts[6] ?? "" };
}

function linuxGroupGid(exec: ToolExec): number | null {
  const ran = exec(toolArgv("getent", ["group", "verax"], "linux"));
  const line = (ran.status ?? 1) === 0 ? (ran.stdout ?? "").split(/\r?\n/).find((row) => row.startsWith("verax:")) : undefined;
  const gid = Number(line?.split(":")[2]);
  return Number.isInteger(gid) ? gid : null;
}

/**
 * The login useradd creates: system uid, nologin shell, home `/` or none.
 * When the marker recorded a uid, the live uid must be that uid.
 */
function linuxUserVerdict(exec: ToolExec, recordedUid?: number): { remove: true } | { remove: false; line: string } {
  const account = linuxPasswdLine(exec);
  if (!account) return { remove: false, line: "not removing account verax: live account is not the system user this install creates" };
  const homeOk = account.home === "/" || account.home === "";
  const shape = linuxSystemId(account.uid) && account.shell === LINUX_NOLOGIN && homeOk;
  if (shape && (recordedUid === undefined || account.uid === recordedUid)) return { remove: true };
  if (recordedUid !== undefined && account.uid !== recordedUid) {
    return { remove: false, line: `not removing account verax: live uid ${account.uid} does not match marker uid ${recordedUid}` };
  }
  const home = account.home === "" ? "none" : account.home;
  return { remove: false, line: `not removing account verax: uid ${account.uid}, shell ${account.shell}, home ${home}` };
}

/** System gid, and when the marker recorded one, that gid. */
function linuxGroupVerdict(exec: ToolExec, recordedGid?: number): { remove: true } | { remove: false; line: string } {
  const gid = linuxGroupGid(exec);
  if (gid !== null && linuxSystemId(gid) && (recordedGid === undefined || gid === recordedGid)) return { remove: true };
  if (recordedGid !== undefined && gid !== recordedGid) {
    const shown = gid === null ? "unknown" : String(gid);
    return { remove: false, line: `not removing group verax: live gid ${shown} does not match marker gid ${recordedGid}` };
  }
  const shown = gid === null ? "unknown" : String(gid);
  return { remove: false, line: `not removing group verax: gid ${shown} is outside the system range` };
}

function darwinNumber(exec: ToolExec, record: string, field: string): number | null {
  const ran = exec(toolArgv("dscl", [".", "-read", record, field], "darwin"));
  if ((ran.status ?? 1) !== 0) return null;
  const n = Number((ran.stdout ?? "").match(/(\d+)/)?.[1]);
  return Number.isInteger(n) ? n : null;
}

function darwinUserVerdict(
  exec: ToolExec,
  recordedUid: number | undefined,
  recordedGid: number | undefined,
): { remove: true } | { remove: false; line: string } {
  const uid = darwinNumber(exec, `/Users/${DARWIN_USER}`, "UniqueID");
  const gid = darwinNumber(exec, `/Users/${DARWIN_USER}`, "PrimaryGroupID");
  if (recordedUid !== undefined && recordedGid !== undefined && uid === recordedUid && gid === recordedGid) return { remove: true };
  return {
    remove: false,
    line: `not removing user ${DARWIN_USER}: live uid ${uid ?? "unknown"} gid ${gid ?? "unknown"} does not match marker uid ${recordedUid ?? "unset"} gid ${recordedGid ?? "unset"}`,
  };
}

function darwinGroupVerdict(exec: ToolExec, recordedGid: number | undefined): { remove: true } | { remove: false; line: string } {
  const gid = darwinNumber(exec, `/Groups/${DARWIN_USER}`, "PrimaryGroupID");
  if (recordedGid !== undefined && gid === recordedGid) return { remove: true };
  return {
    remove: false,
    line: `not removing group ${DARWIN_USER}: live gid ${gid ?? "unknown"} does not match marker gid ${recordedGid ?? "unset"}`,
  };
}

function windowsServiceSid(exec: ToolExec): string | null {
  const ran = exec(toolArgv("powershell", [
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    WINDOWS_SERVICE_SID_COMMAND,
  ], "win32"));
  if ((ran.status ?? 1) !== 0) return null;
  return (ran.stdout ?? "").match(/S-1-[0-9-]+/i)?.[0]?.toUpperCase() ?? null;
}

function windowsAccountVerdict(exec: ToolExec, recordedSid: string | undefined): { remove: true } | { remove: false; line: string } {
  const live = windowsServiceSid(exec);
  if (recordedSid !== undefined && live === recordedSid) return { remove: true };
  return {
    remove: false,
    line: `not removing account ${VERAX_SVC}: live SID ${live ?? "unknown"} does not match marker SID ${recordedSid ?? "unset"}`,
  };
}

/** Run one uninstall tool. Absent artifacts are not failures. Returns a non-zero code when the tool failed. */
function runUninstallTool(exec: ToolExec, io: InstallIo, argv: string[]): number | null {
  const ran = exec(argv);
  if ((ran.status ?? 1) === 0 || removalAlreadyGone(argv, ran)) return null;
  reportToolFailure(io, argv, ran);
  return ran.status ?? 1;
}

/** Refuse a junction or symlink at `target`, at an ancestor, or at a child. Does not follow one. */
function windowsRemovalRefusal(target: string): string | null {
  for (const entry of ancestry(target, "win32")) {
    if (windowsReparsePoint(entry)) return `refusing: ${entry} is a reparse point`;
  }
  const walk = (dir: string): string | null => {
    let listed: ReturnType<typeof lstatSync>;
    try {
      listed = lstatSync(dir);
    } catch {
      return null;
    }
    if (listed.isSymbolicLink()) return `refusing: ${dir} is a reparse point`;
    if (!listed.isDirectory()) return null;
    let names: { name: string; isSymbolicLink(): boolean; isDirectory(): boolean }[];
    try {
      names = readdirSync(dir, { withFileTypes: true });
    } catch {
      return `refusing: ${dir} could not be read`;
    }
    for (const name of names) {
      const sep = dir.includes("\\") ? "\\" : "/";
      const child = `${dir.replace(/[\\/]+$/, "")}${sep}${name.name}`;
      if (name.isSymbolicLink()) return `refusing: ${child} is a reparse point`;
      if (name.isDirectory()) {
        const nested = walk(child);
        if (nested) return nested;
      }
    }
    return null;
  };
  return walk(target);
}

function removeInstallPath(target: string, io: InstallIo, platform: NodeJS.Platform = process.platform): number | null {
  if (platform === "win32") {
    const refused = windowsRemovalRefusal(target);
    if (refused) {
      io.stderr.write(refused.endsWith("\n") ? refused : `${refused}\n`);
      return EX_CONFIG;
    }
  }
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
    accountUid?: number;
    accountGid?: number;
    accountSid?: string;
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
      const removed = removeInstallPath(unit, io, platform);
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
      return removeInstallPath(DARWIN_PLIST, io, platform);
    });
    if (failed !== null) {
      writeLines();
      return failed;
    }
  }

  const codeFailed = note(existsSync(plan.codeDir), plan.codeDir, () => removeInstallPath(plan.codeDir, io, platform));
  if (codeFailed !== null) {
    writeLines();
    return codeFailed;
  }
  if (platform === "darwin") {
    const markerFailed = note(existsSync(DARWIN_MARKER), DARWIN_MARKER, () => removeInstallPath(DARWIN_MARKER, io, platform));
    if (markerFailed !== null) {
      writeLines();
      return markerFailed;
    }
    const rootFailed = note(existsSync(DARWIN_ROOT), DARWIN_ROOT, () => removeInstallPath(DARWIN_ROOT, io, platform));
    if (rootFailed !== null) {
      writeLines();
      return rootFailed;
    }
  }
  if (!opts.keepState) {
    const stateFailed = note(existsSync(plan.stateDir), plan.stateDir, () => removeInstallPath(plan.stateDir, io, platform));
    if (stateFailed !== null) {
      writeLines();
      return stateFailed;
    }
  }
  if (platform === "win32" && plan.tokenPath.includes(`${path.win32.sep}agent-token${path.win32.sep}`)) {
    const tokenDir = path.win32.dirname(plan.tokenPath);
    const tokenFailed = note(existsSync(tokenDir), tokenDir, () => removeInstallPath(tokenDir, io, platform));
    if (tokenFailed !== null) {
      writeLines();
      return tokenFailed;
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
    if (query.status !== 0) {
      note(false, `account ${VERAX_SVC}`, () => null);
    } else {
      const verdict = windowsAccountVerdict(exec, opts.accountSid);
      if (!verdict.remove) {
        any = true;
        lines.push(verdict.line);
      } else {
        const failed = note(true, `account ${VERAX_SVC}`, () =>
          runUninstallTool(exec, io, toolArgv("net", ["user", VERAX_SVC, "/delete"], "win32")),
        );
        if (failed !== null) {
          writeLines();
          return failed;
        }
      }
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
    if (query.status !== 0) {
      note(false, `user ${DARWIN_USER}`, () => null);
    } else {
      const verdict = darwinUserVerdict(exec, opts.accountUid, opts.accountGid);
      if (!verdict.remove) {
        any = true;
        lines.push(verdict.line);
      } else {
        const failed = note(true, `user ${DARWIN_USER}`, () =>
          runUninstallTool(exec, io, toolArgv("dscl", [".", "-delete", `/Users/${DARWIN_USER}`], "darwin")),
        );
        if (failed !== null) {
          writeLines();
          return failed;
        }
      }
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
    if (query.status !== 0) {
      note(false, `group ${DARWIN_USER}`, () => null);
    } else {
      const verdict = darwinGroupVerdict(exec, opts.accountGid);
      if (!verdict.remove) {
        any = true;
        lines.push(verdict.line);
      } else {
        const failed = note(true, `group ${DARWIN_USER}`, () =>
          runUninstallTool(exec, io, toolArgv("dscl", [".", "-delete", `/Groups/${DARWIN_USER}`], "darwin")),
        );
        if (failed !== null) {
          writeLines();
          return failed;
        }
      }
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
    if (query.status !== 0) {
      note(false, "account verax", () => null);
    } else {
      const verdict = linuxUserVerdict(exec, opts.accountUid);
      if (!verdict.remove) {
        any = true;
        lines.push(verdict.line);
      } else {
        const failed = note(true, "account verax", () =>
          runUninstallTool(exec, io, toolArgv("userdel", ["verax"], "linux")),
        );
        if (failed !== null) {
          writeLines();
          return failed;
        }
      }
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
    if (query.status !== 0) {
      note(false, "group verax", () => null);
    } else {
      const verdict = linuxGroupVerdict(exec, opts.accountGid);
      if (!verdict.remove) {
        any = true;
        lines.push(verdict.line);
      } else {
        const failed = note(true, "group verax", () =>
          runUninstallTool(exec, io, toolArgv("groupdel", ["verax"], "linux")),
        );
        if (failed !== null) {
          writeLines();
          return failed;
        }
      }
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
  if (!cliCodeCheckPassed) {
    const codeRefusal = refuseWritableCode(platform, env, hooks.exec ?? defaultExec, hooks.codeProbe, {
      execPathProbe: hooks.execPathProbe,
      execArgv: hooks.execArgv,
    });
    if (codeRefusal) {
      io.stderr.write(codeRefusal.endsWith("\n") ? codeRefusal : `${codeRefusal}\n`);
      return EX_CONFIG;
    }
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
  let markerFile: string;
  let adopted: WindowsMachineRoots | undefined;
  try {
    if (platform === "win32") windowsSystemRoot(plannedEnv);
    if (platform === "win32") adopted = adoptWindowsInstallRoots(plannedEnv, hooks.windowsMachineRoots ?? readWindowsMachineRoots(exec));
    markerFile = platform === "win32"
      ? path.win32.join(path.win32.dirname(stateDirFor(platform, plannedEnv, undefined, adopted)), "install.json")
      : platform === "darwin"
        ? fixed.darwinMarker
        : path.posix.join(fixed.linuxCode, "install.json");
  } catch (err) {
    if (err instanceof SystemToolError) {
      io.stderr.write(err.message.endsWith("\n") ? err.message : `${err.message}\n`);
      return EX_CONFIG;
    }
    throw err;
  }
  const flags = markerFlags(markerFile);
  const userSid = platform === "win32" ? invokingSid(exec) : undefined;
  const plan = planUninstall(platform as InstallPlatform, plannedEnv, {
    keepState: parsed.keepState,
    removeWinAccount: flags.createdAccount,
    removeDarwinUser: flags.createdUser,
    removeDarwinGroup: flags.createdGroup,
    removeLinuxUser: flags.createdUser,
    removeLinuxGroup: flags.createdGroup,
    posixRoot,
    userSid,
    windowsMachineRoots: adopted,
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
    accountUid: flags.accountUid,
    accountGid: flags.accountGid,
    accountSid: flags.accountSid,
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
  exec: ToolExec = defaultExec,
): BoundaryCheck[] {
  let codeDir: string;
  let stateDir: string;
  try {
    const machine = platform === "win32" ? readWindowsMachineRoots(exec) : undefined;
    codeDir = codeDirFor(platform, env, undefined, machine);
    stateDir = stateDirFor(platform, env, undefined, machine);
  } catch (err) {
    if (err instanceof SystemToolError) {
      return [{ id: "install-root", level: "fail", detail: err.message.trim() }];
    }
    throw err;
  }
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
  try {
    const machine = platform === "win32" ? readWindowsMachineRoots() : undefined;
    const installed = stateDirFor(platform, env, undefined, machine);
    return directoryAccess(installed) === "missing" ? null : installed;
  } catch (err) {
    if (err instanceof SystemToolError) return null;
    throw err;
  }
}
