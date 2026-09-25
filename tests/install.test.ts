import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { type AddressInfo } from "node:net";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, win32 } from "node:path";
import { fileURLToPath } from "node:url";

import {
  installedBoundaryChecks,
  tokenParentRefusal,
  rootOwnedTokenParentArgv,
  windowsDirGrantArgs,
  windowsResetInheritArgs,
  LOGON_HOLDER_COMPARE,
  logonHolderMismatchLines,
  normalizeLogonHolders,
  planInstall,
  PS_ERROR_MARK,
  registryLockProblems,
  resolveTrustPath,
  restrictToOwnerWin32,
  runInstall,
  runUninstall,
  hashFileWithRetry,
  stageTarballCopies,
  verifyServiceAcl,
  systemToolEnv,
  systemToolName,
  systemToolPath,
  windowsUserCanWrite,
  windowsSddlBatchArgv,
  sddlRightsMask,
  type PlanOp,
} from "../packages/body/src/install.ts";
import { runInitLocal } from "../packages/body/src/init-local.ts";

const winEnv = {
  ProgramFiles: "C:\\Program Files",
  ProgramData: "C:\\ProgramData",
  USERPROFILE: "C:\\Users\\operator",
  USERNAME: "operator",
  USERDOMAIN: "DESKTOP",
};

const linuxEnv = {
  SUDO_USER: "runner",
  VERAX_INVOKING_HOME: "/home/runner",
};

const winOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "C:\\Program Files\\nodejs\\node.exe",
  bodyVersion: "0.3.0",
  npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
  stateExists: false,
};

const linuxOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
};

const darwinEnv = {
  SUDO_USER: "runner",
  VERAX_INVOKING_HOME: "/Users/runner",
};

const darwinOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/local/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/local/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
};

/** `getent passwd runner` for a Linux runInstall mock: the plan confirms VERAX_INVOKING_HOME against it. */
function getentAnswer(argv: readonly string[], home: string): { status: number; stdout: string; stderr: string } | null {
  const tool = argv[0] ?? "";
  if (tool.endsWith("getent") && argv[1] === "passwd") {
    return { status: 0, stdout: `${argv[2]}:x:1000:1000::${home}:/bin/bash\n`, stderr: "" };
  }
  // macOS asks Directory Services for the same thing.
  if (tool.endsWith("dscl") && argv.includes("NFSHomeDirectory")) {
    return { status: 0, stdout: `NFSHomeDirectory: ${home}\n`, stderr: "" };
  }
  return null;
}

function okPlan(platform: "win32" | "linux", env: NodeJS.ProcessEnv, opts: Parameters<typeof planInstall>[2]) {
  const plan = planInstall(platform, env, opts);
  if (!plan.ok) throw new Error(plan.message);
  return plan;
}

function argvs(ops: PlanOp[]): string[][] {
  return ops.filter((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv").map((op) => op.argv);
}

/** npm `install --prefix <codeDir>` stands in for a real registry install. */
/**
 * Read-back icacls text. Only the code dir, state dir, and install marker carry verax-svc.
 * Node and ancestor reads stay Administrators + SYSTEM so the invoking SID is not a write ACE.
 */
function winServiceAcl(dir: string): string {
  const base = dir.replace(/[\\/]+$/, "");
  const codeFile = /[/\\]node_modules[/\\]@verax-ai[/\\]body[/\\]package\.json$/i.test(base);
  const code = codeFile || /[/\\]Verax$/i.test(base);
  const state = /[/\\]state([/\\]|$)/i.test(base) || /install\.json$/i.test(base);
  if (!code && !state) return "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)";
  const rights = code ? "0x1200a9" : "FA";
  const flags = codeFile || /install\.json$/i.test(base) ? "ID" : "OICI";
  return `O:BAG:SYD:PAI(A;${flags};${rights};;;S-1-5-21-1)(A;${flags};FA;;;BA)(A;${flags};FA;;;SY)`;
}

/** Paths inside `windowsSddlBatchArgv`: base64 JSON, not a raw path. */
function sddlBatchPaths(argv: readonly string[]): string[] | null {
  const matched = argv.join("\n").match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/);
  if (!matched?.[1]) return null;
  try {
    const parsed = JSON.parse(Buffer.from(matched[1], "base64").toString("utf8")) as unknown;
    if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) return null;
    return parsed as string[];
  } catch {
    return null;
  }
}

function sddlJson(paths: readonly string[], sddlFor: (target: string) => string): string {
  const out: Record<string, string> = {};
  for (const target of paths) out[target] = sddlFor(target);
  return JSON.stringify(out);
}

function sddlPowerShell(argv: readonly string[]): boolean {
  return systemToolName(argv[0] ?? "") === "powershell" && argv.join("\n").includes(".Sddl");
}

function sddlStdout(argv: readonly string[]): string | null {
  const paths = sddlBatchPaths(argv);
  if (paths) return sddlJson(paths, winServiceAcl);
  const cmd = argv.join(" ");
  if (!cmd.includes(".Sddl")) return null;
  const matched = cmd.match(/LiteralPath '([^']*)'/);
  const target = (matched?.[1] ?? "").replace(/''/g, "'");
  return `${winServiceAcl(target)}\n`;
}

function stageRegistryInstall(argv: readonly string[], version: string): void {
  if (!argv.includes("install") || !argv.includes("--prefix")) return;
  const codeDir = argv[argv.indexOf("--prefix") + 1];
  if (!codeDir) return;
  const pkgDir = join(codeDir, "node_modules", "@verax-ai", "body");
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify({ name: "@verax-ai/body", version }));
  writeFileSync(
    join(codeDir, "package-lock.json"),
    JSON.stringify({
      packages: {
        "node_modules/@verax-ai/body": {
          resolved: `https://registry.npmjs.org/@verax-ai/body/-/body-${version}.tgz`,
        },
      },
    }),
  );
}

describe("verax install plan", () => {
  it("1 state ACL grants only verax-svc, Administrators, and SYSTEM, or verax mode 0700", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const stateAcl = argvs(win.ops).filter((argv) => systemToolName(argv[0] ?? "") === "icacls" && argv[1] === win.stateDir && argv.includes("/grant:r"));
    assert.ok(stateAcl.length >= 1);
    for (const argv of stateAcl) {
      const text = argv.join(" ");
      assert.equal(/LOCAL SERVICE/i.test(text), false);
      assert.match(text, /verax-svc:\(OI\)\(CI\)F/);
      assert.match(text, /\*S-1-5-32-544:\(OI\)\(CI\)F/);
      assert.match(text, /\*S-1-5-18:\(OI\)\(CI\)F/);
      assert.equal(text.includes("Users"), false);
      assert.equal(text.includes("Everyone"), false);
      assert.equal(text.includes("BUILTIN\\"), false);
      assert.equal(text.includes("NT AUTHORITY\\"), false);
      const grants = argv.filter((arg) => arg.includes(":("));
      for (const grant of grants) {
        const principal = grant.split(":")[0] ?? "";
        const allowed = principal === "verax-svc" || principal === "*S-1-5-32-544" || principal === "*S-1-5-18";
        assert.equal(allowed, true, grant);
      }
    }
    assert.match(stateAcl[0]!.join(" "), /\/inheritance:r/);

    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const lines = argvs(linux.ops);
    assert.ok(lines.some((argv) => systemToolName(argv[0] ?? "") === "useradd" && argv.slice(1).join(" ") === "--system --no-create-home --shell /usr/sbin/nologin verax"));
    assert.ok(lines.some((argv) => systemToolName(argv[0] ?? "") === "chown" && argv.join(" ").includes("verax:verax") && argv.includes(linux.stateDir)));
    assert.ok(lines.some((argv) => systemToolName(argv[0] ?? "") === "chmod" && argv.includes("0700") && argv.includes(linux.stateDir)));
  });

  it("2 agent token is in the invoking user's profile and not under the state dir", () => {
    const win = okPlan("win32", winEnv, winOpts);
    assert.equal(win.tokenPath, "C:\\Users\\operator\\.verax\\agent.token");
    assert.equal(win.tokenPath.startsWith(win.stateDir), false);
    const linux = okPlan("linux", linuxEnv, linuxOpts);
    assert.equal(linux.tokenPath, "/home/runner/.verax/agent.token");
    assert.equal(linux.tokenPath.startsWith(linux.stateDir), false);
    const init = linux.ops.find((op) => op.op === "init");
    assert.ok(init && init.op === "init");
    assert.equal(init.tokenPath, linux.tokenPath);
    assert.equal(init.tokenPath.startsWith(init.stateDir), false);
    assert.equal(init.noOwnerGrant, true);
  });

  it("install init carries no owner grant, and only the token icacls names the invoking user", () => {
    const sid = "S-1-5-21-1001";
    const win = okPlan("win32", { ...winEnv, USERNAME: "Everyone", USERDOMAIN: "" }, { ...winOpts, userSid: sid });
    const init = win.ops.find((op) => op.op === "init");
    assert.ok(init && init.op === "init");
    assert.equal(init.noOwnerGrant, true);
    for (const argv of argvs(win.ops)) {
      if (systemToolName(argv[0] ?? "") !== "icacls") continue;
      const grantsUser = argv.some((arg) => arg.includes(`*${sid}:(R)`));
      const grantsName = argv.some((arg) => /Everyone:\(R\)/.test(arg) || arg.includes("USERNAME"));
      if (argv[1] === win.tokenPath) {
        assert.equal(grantsUser, true, argv.join(" "));
        assert.equal(grantsName, false, argv.join(" "));
        continue;
      }
      assert.equal(grantsUser, false, argv.join(" "));
      assert.equal(grantsName, false, argv.join(" "));
    }
    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const linuxInit = linux.ops.find((op) => op.op === "init");
    assert.ok(linuxInit && linuxInit.op === "init");
    assert.equal(linuxInit.noOwnerGrant, true);
    for (const argv of argvs(linux.ops)) {
      const tool = systemToolName(argv[0] ?? "");
      if (tool !== "chown" && tool !== "chmod") continue;
      const touchesState = argv.includes(linux.stateDir);
      if (!touchesState) continue;
      assert.equal(argv.some((arg) => arg.includes(linuxEnv.SUDO_USER!)), false, argv.join(" "));
      if (tool === "chown") assert.match(argv.join(" "), /verax:verax/);
      if (tool === "chmod") assert.ok(argv.includes("0700"));
    }
    const tokenChowns = argvs(linux.ops).filter((argv) => systemToolName(argv[0] ?? "") === "chown" && argv.includes(linux.tokenPath));
    assert.equal(tokenChowns.length, 1);
    assert.match(tokenChowns[0]!.join(" "), new RegExp(`${linuxEnv.SUDO_USER}:`));
    const darwin = planInstall("darwin", darwinEnv, darwinOpts);
    if (!darwin.ok) throw new Error(darwin.message);
    const darwinInit = darwin.ops.find((op) => op.op === "init");
    assert.ok(darwinInit && darwinInit.op === "init");
    assert.equal(darwinInit.noOwnerGrant, true);
    for (const argv of argvs(darwin.ops)) {
      if (systemToolName(argv[0] ?? "") !== "chown" || !argv.includes(darwin.stateDir)) continue;
      assert.equal(argv.some((arg) => arg.includes(darwinEnv.SUDO_USER!)), false, argv.join(" "));
      assert.match(argv.join(" "), /_verax:_verax/);
    }
  });

  it("3 autostart runs the trusted node and the registry cli", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const task = win.ops.find((op) => op.op === "argv" && op.argv.some((arg) => arg.includes("Register-ScheduledTask")));
    if (!task || task.op !== "argv") throw new Error("missing scheduled task registration");
    const tr = task.argv.join(" ");
    assert.match(tr, /New-ScheduledTaskAction/);
    assert.match(tr, /C:\\Program Files\\nodejs\\node\.exe/);
    assert.match(tr, /C:\\Program Files\\Verax\\node_modules\\@verax-ai\\body\\dist\\cli\.js/);
    assert.match(tr, /serve --env-file/);
    assert.match(tr, /--log-file/);
    assert.match(tr, /body\.log/);
    assert.match(tr, /Start-ScheduledTask/);
    assert.equal(tr.includes("AppData"), false);
    assert.equal(tr.includes("\\Verax\\node.exe"), false);

    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const unit = linux.ops.find((op) => op.op === "write" && op.path === "/etc/systemd/system/verax.service");
    assert.ok(unit && unit.op === "write");
    assert.match(unit.contents, /ExecStart=\/usr\/bin\/node \/opt\/verax\/node_modules\/@verax-ai\/body\/dist\/cli\.js serve --env-file \/var\/lib\/verax\/verax\.env --log-file \/var\/lib\/verax\/body\.log/);
    const darwin = planInstall("darwin", darwinEnv, darwinOpts);
    if (!darwin.ok) throw new Error(darwin.message);
    for (const planned of [win, linux, darwin]) {
      const wait = planned.ops.find((op) => op.op === "wait-healthz");
      assert.ok(wait && wait.op === "wait-healthz");
      assert.equal(wait.timeoutMs, 60_000);
    }
    assert.equal(unit.contents.includes("/opt/verax/node "), false);
  });

  it("4 unit file carries the service sandbox", () => {
    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const unit = linux.ops.find((op) => op.op === "write" && op.path === "/etc/systemd/system/verax.service");
    assert.ok(unit && unit.op === "write");
    for (const line of [
      "User=verax",
      "NoNewPrivileges=yes",
      "ProtectSystem=strict",
      "ReadWritePaths=/var/lib/verax",
      "ProtectHome=yes",
    ]) {
      assert.equal(unit.contents.includes(line), true, line);
    }
  });

  it("5 without elevation install exits 77 and executes nothing", async () => {
    for (const platform of ["win32", "linux", "darwin"] as const) {
      let ran = 0;
      const err: string[] = [];
      const code = await runInstall(["install", "--port", "8801"], {
        platform,
        env: platform === "win32" ? winEnv : platform === "darwin" ? darwinEnv : linuxEnv,
        elevated: () => false,
        layout: platform === "win32" ? winOpts : platform === "darwin" ? darwinOpts : linuxOpts,
        stateExists: () => {
          ran += 1;
          return false;
        },
        exec: () => {
          ran += 1;
          return { status: 0 };
        },
        io: {
          stdout: { write: () => undefined },
          stderr: { write: (s: string) => err.push(s) },
        },
      });
      assert.equal(code, 77, platform);
      assert.equal(ran, 0, platform);
      assert.match(err.join(""), /verax install needs an elevated shell \(Administrator \/ root\)/);
    }
  });

  it("6 doctor flags a tampered manifest file and a foreign ACL principal", () => {
    const checks = installedBoundaryChecks({
      codeDir: "C:\\Program Files\\Verax",
      stateDir: "C:\\ProgramData\\Verax\\state",
      manifest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  node.exe\n",
      hashOf: () => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      aclText: "O:BAG:SYD:PAI(A;OICI;0x1200a9;;;BU)(A;;GR;;;WD)(A;OICI;FA;;;S-1-5-21-1)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",
      autostart: true,
    });
    const failed = checks.filter((c) => c.level === "fail").map((c) => c.detail);
    assert.ok(failed.some((line) => line.includes("node.exe")));
    assert.ok(failed.some((line) => line.includes("S-1-5-32-545")));
    assert.ok(failed.some((line) => line.includes("S-1-1-0")));
  });

  it("a refuses a node whose icacls grants BUILTIN\\Users modify", () => {
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      nodeIcacls: "C:\\Program Files\\nodejs\\node.exe BUILTIN\\Users:(M)\n",
    });
    if (plan.ok) throw new Error("accepted a user-writable node");
    assert.equal(plan.code, 78);
    assert.match(plan.message, /Node at C:\\Program Files\\nodejs\\node\.exe can be changed by your user account/);
    assert.match(plan.message, /nodejs\.org installer/);
  });

  it("b installs the running body from the registry and does not copy local trees", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const dumped = JSON.stringify(win.ops);
    assert.equal(dumped.includes("copy-file"), false);
    assert.equal(dumped.includes("copy-tree"), false);
    assert.equal(dumped.includes("stage-deps"), false);
    assert.equal(dumped.includes("AppData"), false);
    const temp = win.ops.find((op) => op.op === "private-temp");
    if (!temp || temp.op !== "private-temp") throw new Error("missing private temp");
    const install = argvs(win.ops).find((argv) => argv.includes("--omit=dev"));
    const audit = argvs(win.ops).find((argv) => argv.includes("signatures"));
    if (!install || !audit) throw new Error("missing npm install or npm audit signatures");
    assert.deepEqual(install, [
      winOpts.execPath,
      winOpts.npmCli,
      "install",
      "--prefix",
      win.codeDir,
      "--omit=dev",
      "--userconfig",
      win32.join(temp.path, "empty-npmrc"),
      "--globalconfig",
      win32.join(temp.path, "empty-globalrc"),
      "--registry",
      "https://registry.npmjs.org/",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--no-update-notifier",
      "@verax-ai/body@0.3.0",
    ]);
    assert.ok(audit.includes("audit"));
    assert.ok(audit.includes("--prefix"));
    assert.ok(audit.includes(win.codeDir));
    const manifestAt = win.ops.findIndex((op) => op.op === "manifest");
    const auditAt = win.ops.findIndex((op) => op.op === "argv" && op.argv.includes("signatures"));
    assert.ok(auditAt >= 0 && manifestAt > auditAt);
  });

  it("c refuses a pre-created state dir without install.json and a reparse point", () => {
    const pre = planInstall("win32", winEnv, { ...winOpts, stateExists: true });
    if (pre.ok) throw new Error("accepted state without install.json");
    assert.equal(pre.code, 78);
    assert.match(pre.message, /C:\\ProgramData\\Verax\\state/);

    const junction = planInstall("win32", winEnv, { ...winOpts, reparsePath: "C:\\ProgramData\\Verax" });
    if (junction.ok) throw new Error("accepted a reparse point");
    assert.equal(junction.code, 78);
    assert.match(junction.message, /reparse point/);
    assert.match(junction.message, /C:\\ProgramData\\Verax/);
  });

  it("refuses a grant or setowner argument that starts with a bare SID", () => {
    const refused = planInstall("win32", winEnv, { ...winOpts, userSid: "S-1-1-0" });
    if (refused.ok) throw new Error("accepted a well-known group as the token principal");
    assert.equal(refused.code, 78);
    assert.match(refused.message, /S-1-1-0/);
    assert.match(refused.message, /token principal/);

    const win = okPlan("win32", winEnv, { ...winOpts, userSid: "S-1-5-21-1003" });
    const tokenGrant = argvs(win.ops).find((argv) => argv[1] === win.tokenPath);
    assert.ok(tokenGrant?.includes("*S-1-5-21-1003:(R)"));
    for (const argv of argvs(win.ops)) {
      if (systemToolName(argv[0] ?? "") !== "icacls") continue;
      for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        if (flag !== "/grant" && flag !== "/grant:r" && flag !== "/setowner") continue;
        for (let j = i + 1; j < argv.length && !argv[j]!.startsWith("/"); j += 1) {
          const account = argv[j]!.split(":")[0] ?? "";
          assert.equal(account.startsWith("S-1-"), false, argv[j]);
          assert.ok(account.startsWith("*S-1-") || !account.includes("S-1-"), argv[j]);
        }
      }
    }
  });

  it("d sets the Administrators owner on the state and code dirs", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const owners = argvs(win.ops).filter((argv) => systemToolName(argv[0] ?? "") === "icacls" && argv.includes("/setowner") && argv.includes("*S-1-5-32-544"));
    assert.ok(owners.some((argv) => argv.includes(win.stateDir) && argv.includes("/T") && argv.includes("/C")));
    assert.ok(owners.some((argv) => argv.includes(win.codeDir) && argv.includes("/T") && argv.includes("/C")));
  });

  it("from-tarballs refuses a user-writable tarball directory", () => {
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      fromTarballs: "C:\\pack",
      tarballFiles: ["C:\\pack\\verax-ai-body-0.3.0.tgz"],
      tarballIcacls: "C:\\pack BUILTIN\\Users:(M)\n",
    });
    if (plan.ok) throw new Error("accepted a user-writable tarball directory");
    assert.equal(plan.code, 78);
    assert.match(plan.message, /C:\\pack/);
    assert.match(plan.message, /from-tarballs/);
  });

  it("doctor shows the red line for a tarball install", () => {
    const checks = installedBoundaryChecks({
      codeDir: "C:\\Program Files\\Verax",
      stateDir: "C:\\ProgramData\\Verax\\state",
      manifest: null,
      hashOf: () => null,
      autostart: true,
      installSource: "tarballs",
    });
    const line = checks.find((c) => c.detail === "code was not installed from the registry (release testing only)");
    if (!line) throw new Error("doctor did not name the tarball install");
    assert.equal(line.level, "fail");
  });

  it("poisoned PATH does not select whoami, icacls, or chown", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-path-"));
    const prev = process.env.PATH;
    const planTools = new Set(["icacls", "schtasks", "powershell", "useradd", "chown", "chmod", "systemctl"]);
    try {
      process.env.PATH = dir;
      if (process.platform === "win32") {
        writeFileSync(join(dir, "whoami.cmd"), "@echo S-1-5-21-999\r\n@exit /b 0\r\n");
        writeFileSync(join(dir, "icacls.cmd"), "@echo forged\r\n@exit /b 0\r\n");
        const seen: string[] = [];
        const grants: string[][] = [];
        restrictToOwnerWin32(join(dir, "target"), (file, args) => {
          seen.push(file);
          if (systemToolName(file) === "icacls") grants.push([...args]);
          if (systemToolName(file) === "whoami") return { status: 0, stdout: '"X","S-1-5-21-1"\n', stderr: "" };
          return { status: 0, stdout: "ok\n", stderr: "" };
        });
        assert.ok(grants.some((args) => args.includes("/grant:r") && args.includes("*S-1-5-21-1:F") && args.includes("*S-1-5-32-544:F") && args.includes("*S-1-5-18:F")));
        assert.equal(grants.some((args) => args.some((arg) => arg.startsWith("S-1-"))), false);
        assert.ok(seen.length >= 2);
        for (const file of seen) {
          assert.equal(win32.isAbsolute(file), true, file);
          assert.equal(file.toLowerCase().startsWith(dir.toLowerCase()), false, file);
        }
      } else {
        writeFileSync(join(dir, "whoami"), "#!/bin/sh\necho S-1-5-21-999\nexit 0\n", { mode: 0o755 });
        writeFileSync(join(dir, "chown"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      }
      const platform = process.platform === "win32" ? "win32" : "linux";
      const plan = okPlan(platform, platform === "win32" ? winEnv : linuxEnv, platform === "win32" ? winOpts : linuxOpts);
      const tools = argvs(plan.ops).filter((argv) => planTools.has(systemToolName(argv[0] ?? "")));
      assert.ok(tools.length > 0);
      for (const argv of tools) {
        const file = argv[0] ?? "";
        assert.equal(file.startsWith(dir), false, file);
        if (platform === "win32") assert.equal(win32.isAbsolute(file), true, file);
        else assert.equal(file.startsWith("/"), true, file);
        assert.equal(file, systemToolPath(systemToolName(file), platform));
      }
    } finally {
      if (prev === undefined) delete process.env.PATH;
      else process.env.PATH = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("darwin refuses a user-owned Homebrew Node", () => {
    const plan = planInstall("darwin", darwinEnv, {
      ...darwinOpts,
      execPath: "/opt/homebrew/bin/node",
      npmCli: "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js",
      nodeModes: [
        { uid: 501, mode: 0o755 },
        { uid: 0, mode: 0o755 },
      ],
    });
    if (plan.ok) throw new Error("accepted a user-owned Homebrew Node");
    assert.equal(plan.code, 78);
    assert.match(plan.message, /\/opt\/homebrew\/bin\/node/);
    assert.match(plan.message, /\/usr\/local\/lib\/verax-node/);
    assert.match(plan.message, /root:wheel/);
    assert.match(plan.message, /SHASUMS256\.txt/);
    assert.match(plan.message, new RegExp(`node-v${process.versions.node.replaceAll(".", "\\.")}-darwin-${process.arch}\\.tar\\.gz`));
    assert.match(plan.message, /\$\(which verax\) install/);
  });

  it("linux refusal names the official tarball under /usr/local/lib/verax-node", () => {
    const plan = planInstall("linux", linuxEnv, {
      ...linuxOpts,
      nodeModes: [
        { uid: 1000, mode: 0o755 },
        { uid: 0, mode: 0o755 },
      ],
    });
    if (plan.ok) throw new Error("accepted a user-owned Node");
    assert.equal(plan.code, 78);
    assert.match(plan.message, /\/usr\/bin\/node/);
    assert.match(plan.message, /\/usr\/local\/lib\/verax-node/);
    assert.match(plan.message, /root:root/);
    assert.match(plan.message, /sha256sum -c -/);
    assert.match(plan.message, new RegExp(`node-v${process.versions.node.replaceAll(".", "\\.")}-linux-${process.arch}\\.tar\\.gz`));
    assert.match(plan.message, /\$\(which verax\) install/);
  });

  it("darwin plist runs as _verax with the trusted Node and state is 0700", () => {
    const plan = planInstall("darwin", darwinEnv, darwinOpts);
    if (!plan.ok) throw new Error(plan.message);
    assert.equal(plan.stateDir, "/Library/Application Support/Verax/state");
    assert.equal(plan.tokenPath, "/Users/runner/.verax/agent.token");
    const plist = plan.ops.find((op) => op.op === "write" && op.path === "/Library/LaunchDaemons/com.verax-ai.body.plist");
    if (!plist || plist.op !== "write") throw new Error("missing launchd plist");
    assert.match(plist.contents, /<key>UserName<\/key>\s*<string>_verax<\/string>/);
    assert.match(plist.contents, /<key>GroupName<\/key>\s*<string>_verax<\/string>/);
    assert.match(plist.contents, /<key>KeepAlive<\/key>\s*<true\/>/);
    assert.match(plist.contents, /<string>\/usr\/local\/bin\/node<\/string>/);
    assert.match(plist.contents, /<string>\/Library\/Verax\/code\/node_modules\/@verax-ai\/body\/dist\/cli\.js<\/string>/);
    assert.match(plist.contents, /StandardErrorPath/);
    assert.match(plist.contents, /\/Library\/Application Support\/Verax\/state\/body\.err/);
    assert.match(plist.contents, /<string>--log-file<\/string>/);
    assert.match(plist.contents, /\/Library\/Application Support\/Verax\/state\/body\.log/);
    const lines = argvs(plan.ops);
    const parent = "/Library/Application Support/Verax";
    const parentMk = plan.ops.find((op) => op.op === "mkdir" && op.path === parent);
    if (!parentMk || parentMk.op !== "mkdir") throw new Error("missing Application Support/Verax mkdir");
    assert.equal(parentMk.mode, 0o755);
    assert.ok(lines.some((argv) => systemToolName(argv[0] ?? "") === "chown" && argv.includes("root:wheel") && argv.includes(parent)));
    assert.ok(lines.some((argv) => systemToolName(argv[0] ?? "") === "chmod" && argv.includes("0755") && argv.includes(parent)));
    const stateMk = plan.ops.find((op) => op.op === "mkdir" && op.path === plan.stateDir);
    if (!stateMk || stateMk.op !== "mkdir") throw new Error("missing state mkdir");
    assert.equal(stateMk.mode, 0o700);
    assert.ok(lines.some((argv) => argv.includes("0700") && argv.includes(plan.stateDir) && systemToolName(argv[0] ?? "") === "chmod"));
    assert.ok(lines.some((argv) => argv.includes("_verax:_verax") && argv.includes(plan.stateDir)));
    for (const argv of lines) {
      const file = argv[0] ?? "";
      assert.equal(file.startsWith("/"), true, file);
      if (file === darwinOpts.execPath) continue;
      assert.equal(file, systemToolPath(systemToolName(file), "darwin"), file);
    }
    const pre = planInstall("darwin", darwinEnv, {
      ...darwinOpts,
      darwinState: { exists: true, symlink: false },
    });
    if (pre.ok) throw new Error("accepted a pre-created state dir");
    assert.equal(pre.code, 78);
    assert.match(pre.message, /\/Library\/Application Support\/Verax\/state/);
    assert.match(pre.message, /was not created by verax install/);
  });

  it("install summary is the running service, not init-local", async () => {
    const cases = [
      ["win32", winEnv, winOpts],
      ["linux", linuxEnv, linuxOpts],
      ["darwin", darwinEnv, darwinOpts],
    ] as const;
    for (const [platform, env, opts] of cases) {
      const plan = planInstall(platform, env, opts);
      if (!plan.ok) throw new Error(plan.message);
      const printed = plan.ops.filter((op) => op.op === "print").map((op) => (op.op === "print" ? op.text : "")).join("\n");
      assert.equal(printed.includes("verax serve"), false, platform);
      assert.equal(printed.includes("A shell as the same user"), false, platform);
      assert.match(printed, /service is running/);
      assert.match(printed, /agent token/);
      assert.match(printed, /Claude Code:/);
      assert.match(printed, /mcp\.json/);
      if (platform === "win32") assert.match(printed, /Run as administrator: verax approve/);
      else assert.match(printed, /Approve held calls from an elevated terminal: sudo verax approve/);
    }
    const stateDir = mkdtempSync(join(tmpdir(), "verax-install-quiet-"));
    const out: string[] = [];
    try {
      const code = await runInitLocal(
        ["--local", stateDir, "--port", "8801"],
        { stdout: { write: (s: string) => out.push(s) }, stderr: { write: () => undefined } },
        { quiet: true },
      );
      assert.equal(code, 0);
      const text = out.join("");
      assert.equal(text.includes("verax serve"), false);
      assert.equal(text.includes("A shell as the same user"), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("runInstall prints the approve summary and not init-local text", async (t) => {
    const platform = process.platform === "win32" || process.platform === "linux" || process.platform === "darwin"
      ? process.platform
      : null;
    if (platform === null) {
      t.skip("verax install does not run on this operating system");
      return;
    }
    const root = mkdtempSync(join(tmpdir(), "verax-install-init-"));
    const home = join(root, "home");
    const env: NodeJS.ProcessEnv = platform === "win32"
      ? { ...winEnv, ProgramData: join(root, "data"), ProgramFiles: join(root, "files"), USERPROFILE: home }
      : { SUDO_USER: "runner", VERAX_INVOKING_HOME: home };
    const trustedStandIn = platform === "win32" ? undefined : ["/usr/bin/bash", "/bin/bash", "/usr/bin/dash", "/usr/bin/true", "/bin/true"].find((file) => {
      try {
        const st = lstatSync(file);
        return !st.isSymbolicLink() && st.uid === 0 && (st.mode & 0o022) === 0;
      } catch {
        return false;
      }
    });
    if (platform !== "win32" && trustedStandIn === undefined) {
      rmSync(root, { recursive: true, force: true });
      t.skip("no root-owned binary to stand in for Node");
      return;
    }
    const layout = platform === "win32"
      ? { execPath: winOpts.execPath, bodyVersion: winOpts.bodyVersion, npmCli: winOpts.npmCli }
      : { execPath: trustedStandIn!, bodyVersion: "0.3.0", npmCli: trustedStandIn! };
    const posixRoot = platform === "win32" ? undefined : join(root, "fsroot");
    const out: string[] = [];
    const err: string[] = [];
    const health = createServer((req, res) => {
      res.writeHead(req.url === "/healthz" ? 200 : 404);
      res.end();
    });
    await new Promise<void>((resolve) => health.listen(0, "127.0.0.1", () => resolve()));
    const port = (health.address() as AddressInfo).port;
    try {
      const code = await runInstall(["install", "--port", String(port)], {
        platform,
        env,
        elevated: () => true,
        layout,
        posixRoot,
        exec: (argv) => {
          const passwd = getentAnswer(argv, home);
          if (passwd) return passwd;
          const tool = systemToolName(argv[0] ?? "");
          const sddl = sddlStdout(argv);
          if (sddl !== null) return { status: 0, stdout: sddl, stderr: "" };
          if (tool === "whoami" || tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (tool === "id") return { status: 1, stdout: "", stderr: "" };
          if (tool === "dscl" && argv.includes("-read")) return { status: 1, stdout: "", stderr: "" };
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
          if (tool === "icacls" && argv.length === 2) return { status: 0, stdout: winServiceAcl(argv[1] ?? ""), stderr: "" };
          stageRegistryInstall(argv, layout.bodyVersion);
          return { status: 0, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => out.push(s) },
          stderr: { write: (s: string) => err.push(s) },
        },
      });
      assert.equal(code, 0);
      const text = `${out.join("")}${err.join("")}`;
      assert.equal(text.includes("verax serve"), false);
      assert.equal(text.includes("A shell as the same user"), false);
      if (platform === "win32") assert.match(text, /Run as administrator: verax approve/);
      else {
        assert.match(text, /Approve held calls from an elevated terminal: sudo verax approve/);
        assert.match(text, new RegExp(posixRoot!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      }
    } finally {
      await new Promise<void>((resolve) => health.close(() => resolve()));
      rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });

  it("runInstall rejects a registry body whose version is not the running body", async (t) => {
    const platform = process.platform === "win32" || process.platform === "linux" || process.platform === "darwin"
      ? process.platform
      : null;
    if (platform === null) {
      t.skip("verax install does not run on this operating system");
      return;
    }
    const root = mkdtempSync(join(tmpdir(), "verax-install-version-"));
    const home = join(root, "home");
    const env: NodeJS.ProcessEnv = platform === "win32"
      ? { ...winEnv, ProgramData: join(root, "data"), ProgramFiles: join(root, "files"), USERPROFILE: home }
      : { SUDO_USER: "runner", VERAX_INVOKING_HOME: home };
    const trustedStandIn = platform === "win32" ? undefined : ["/usr/bin/bash", "/bin/bash", "/usr/bin/dash", "/usr/bin/true", "/bin/true"].find((file) => {
      try {
        const st = lstatSync(file);
        return !st.isSymbolicLink() && st.uid === 0 && (st.mode & 0o022) === 0;
      } catch {
        return false;
      }
    });
    if (platform !== "win32" && trustedStandIn === undefined) {
      rmSync(root, { recursive: true, force: true });
      t.skip("no root-owned binary to stand in for Node");
      return;
    }
    const layout = platform === "win32"
      ? { execPath: winOpts.execPath, bodyVersion: winOpts.bodyVersion, npmCli: winOpts.npmCli }
      : { execPath: trustedStandIn!, bodyVersion: "0.3.0", npmCli: trustedStandIn! };
    const posixRoot = platform === "win32" ? undefined : join(root, "fsroot");
    const err: string[] = [];
    try {
      const code = await runInstall(["install", "--port", "8801"], {
        platform,
        env,
        elevated: () => true,
        layout,
        posixRoot,
        exec: (argv) => {
          const passwd = getentAnswer(argv, home);
          if (passwd) return passwd;
          const tool = systemToolName(argv[0] ?? "");
          const sddl = sddlStdout(argv);
          if (sddl !== null) return { status: 0, stdout: sddl, stderr: "" };
          if (tool === "whoami" || tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (tool === "id") return { status: 1, stdout: "", stderr: "" };
          if (tool === "dscl" && argv.includes("-read")) return { status: 1, stdout: "", stderr: "" };
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
          if (tool === "icacls" && argv.length === 2) return { status: 0, stdout: winServiceAcl(argv[1] ?? ""), stderr: "" };
          stageRegistryInstall(argv, "0.0.1");
          return { status: 0, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: () => undefined },
          stderr: { write: (s: string) => err.push(s) },
        },
      });
      assert.notEqual(code, 0);
      assert.match(err.join(""), new RegExp(`installed @verax-ai/body version 0\\.0\\.1 is not ${layout.bodyVersion}`));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("windows password stays out of install.json, stdout, and stderr", async () => {
    const win = okPlan("win32", winEnv, winOpts);
    const dumped = JSON.stringify(win.ops.filter((op) => op.op === "write" || op.op === "print"));
    assert.equal(dumped.includes("LOCAL SERVICE"), false);
    const root = mkdtempSync(join(tmpdir(), "verax-svc-"));
    const out: string[] = [];
    const err: string[] = [];
    let seen = "";
    try {
      await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env: {
          ...winEnv,
          ProgramData: join(root, "data"),
          ProgramFiles: join(root, "files"),
          USERPROFILE: join(root, "home"),
        },
        elevated: () => true,
        layout: winOpts,
        exec: (argv, stdin) => {
          const sddl = sddlStdout(argv);
          if (sddl !== null) return { status: 0, stdout: sddl, stderr: "" };
          if (systemToolName(argv[0] ?? "") === "powershell" && argv.some((arg) => arg.includes("New-LocalUser"))) {
            seen = (stdin ?? "").replace(/\r?\n$/, "");
            return { status: 1, stdout: "", stderr: `add failed ${seen}\n` };
          }
          if (systemToolName(argv[0] ?? "") === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (systemToolName(argv[0] ?? "") === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (systemToolName(argv[0] ?? "") === "fsutil") return { status: 1, stdout: "", stderr: "" };
          return { status: 0, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => out.push(s) },
          stderr: { write: (s: string) => err.push(s) },
        },
      });
      assert.equal(seen.length, 32);
      const written = textsUnder(root);
      const marker = join(root, "data", "Verax", "install.json");
      if (existsSync(marker)) assert.equal(readFileSync(marker, "utf8").includes(seen), false);
      assert.equal(out.join("").includes(seen), false);
      assert.equal(err.join("").includes(seen), false);
      assert.equal(written.includes(seen), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("windows password travels only in the powershell stdin field", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const secretOps = win.ops.filter((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && op.stdin !== undefined);
    assert.equal(secretOps.length, 2);
    const password = secretOps[0]!.stdin!.replace(/\r?\n$/, "");
    assert.equal(password.length, 32);
    const account = secretOps.find((op) => op.argv.some((arg) => arg.includes("New-LocalUser")));
    const task = secretOps.find((op) => op.argv.some((arg) => arg.includes("Register-ScheduledTask")));
    if (!account || !task) throw new Error("account and task scripts are both required");
    const accountScript = account.argv[account.argv.length - 1] ?? "";
    const taskScript = task.argv[task.argv.length - 1] ?? "";
    assert.match(accountScript, /\[Console\]::In\.ReadLine\(\)/);
    assert.match(accountScript, /ConvertTo-SecureString -String \$plain -AsPlainText -Force/);
    assert.match(accountScript, /Remove-LocalGroupMember -SID 'S-1-5-32-545'/);
    assert.match(accountScript, /SeBatchLogonRight/);
    assert.match(accountScript, /System32\\secedit\.exe/);
    assert.match(taskScript, /New-ScheduledTaskAction/);
    assert.match(taskScript, /-RunLevel Limited/);
    assert.match(taskScript, /-RestartCount 3/);
    assert.match(taskScript, /Start-ScheduledTask -TaskName 'Verax Body'/);
    assert.equal(accountScript.includes(password), false);
    assert.equal(taskScript.includes(password), false);
    for (const op of win.ops) {
      if (op.op !== "argv") continue;
      for (const arg of op.argv) assert.equal(arg.includes(password), false, arg.slice(0, 120));
      if (op.stdin !== undefined) assert.equal(op.stdin.replace(/\r?\n/g, ""), password);
    }
    assert.equal(argvs(win.ops).some((argv) => argv.includes("/RP") || argv.includes("/add")), false);
  });

  it("posixRoot relocates fixed install roots and --root is refused from argv", async () => {
    const root = "/tmp/verax-fsroot";
    const linux = planInstall("linux", linuxEnv, { ...linuxOpts, posixRoot: root });
    if (!linux.ok) throw new Error(linux.message);
    assert.equal(linux.codeDir, `${root}/opt/verax`);
    assert.equal(linux.stateDir, `${root}/var/lib/verax`);
    const unit = linux.ops.find((op) => op.op === "write" && op.path === `${root}/etc/systemd/system/verax.service`);
    if (!unit || unit.op !== "write") throw new Error("systemd unit was not relocated");
    assert.match(unit.contents, new RegExp(`ReadWritePaths=${root}/var/lib/verax`));
    const darwin = planInstall("darwin", darwinEnv, { ...darwinOpts, posixRoot: root });
    if (!darwin.ok) throw new Error(darwin.message);
    assert.equal(darwin.codeDir, `${root}/Library/Verax/code`);
    assert.equal(darwin.stateDir, `${root}/Library/Application Support/Verax/state`);
    assert.ok(darwin.ops.some((op) => op.op === "mkdir" && op.path === `${root}/Library/Application Support/Verax`));
    assert.ok(darwin.ops.some((op) => op.op === "write" && op.path === `${root}/Library/LaunchDaemons/com.verax-ai.body.plist`));
    const err: string[] = [];
    const code = await runInstall(["install", "--root", root], {
      platform: "linux",
      env: linuxEnv,
      elevated: () => true,
      layout: linuxOpts,
      exec: () => {
        throw new Error("argv must not reach install");
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
    });
    assert.equal(code, 78);
    assert.match(err.join(""), /flag-unknown:--root/);
  });

  it("accepts C:\\ add-subdirectory and inherit-only modify when Program Files is admin-only", async () => {
    const drive = "O:BAG:SYD:PAI(A;OICIIO;FA;;;AU)(A;;0x4;;;AU)";
    assert.equal(windowsUserCanWrite(drive, { path: "C:\\", ancestor: true }), false);
    const nodejs = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
    assert.equal(windowsUserCanWrite(nodejs, { path: "C:\\Program Files\\nodejs", ancestor: true }), false);
    const err: string[] = [];
    let sawAdd = false;
    const root = mkdtempSync(join(tmpdir(), "verax-ancestor-ok-"));
    try {
    await runInstall(["install", "--port", "8801"], {
      platform: "win32",
      env: { ...winEnv, ProgramData: join(root, "data"), ProgramFiles: join(root, "files"), USERPROFILE: join(root, "home") },
      elevated: () => true,
      layout: winOpts,
      exec: (argv) => {
        const paths = sddlBatchPaths(argv);
        if (paths) return { status: 0, stdout: sddlJson(paths, () => nodejs), stderr: "" };
        if (argv.join(" ").includes(".Sddl")) return { status: 0, stdout: `${nodejs}\n`, stderr: "" };
        if (systemToolName(argv[0] ?? "") === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
        if (systemToolName(argv[0] ?? "") === "powershell" && argv.some((arg) => arg.includes("New-LocalUser"))) {
          sawAdd = true;
          return { status: 1, stdout: "", stderr: "add failed\n" };
        }
        if (systemToolName(argv[0] ?? "") === "net") return { status: 2, stdout: "", stderr: "not found\n" };
        if (systemToolName(argv[0] ?? "") === "fsutil") return { status: 1, stdout: "", stderr: "" };
        return { status: 0, stdout: "", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
    });
    assert.equal(err.join("").includes("can be changed by your user account"), false);
    assert.equal(sawAdd, true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("SDDL rights are access masks; DC is write-data, and an unknown token is named", () => {
    const rows: [string, number][] = [
      ["GA", 0x10000000],
      ["GR", 0x80000000],
      ["GW", 0x40000000],
      ["GX", 0x20000000],
      ["RC", 0x20000],
      ["SD", 0x10000],
      ["WD", 0x40000],
      ["WO", 0x80000],
      ["RP", 0x10],
      ["WP", 0x20],
      ["CC", 0x1],
      ["DC", 0x2],
      ["LC", 0x4],
      ["SW", 0x8],
      ["LO", 0x80],
      ["DT", 0x40],
      ["CR", 0x100],
      ["FA", 0x1f01ff],
      ["FR", 0x120089],
      ["FW", 0x120116],
      ["FX", 0x1200a0],
      ["0x4", 0x4],
      ["DCLC", 0x6],
      ["KA", 0],
    ];
    for (const [token, mask] of rows) {
      const parsed = sddlRightsMask(token);
      if (!("mask" in parsed)) assert.fail(`${token} named unknown ${parsed.unknown}`);
      assert.equal(parsed.mask, mask >>> 0, token);
    }
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(A;OICIIO;FA;;;AU)(A;;0x4;;;AU)", { path: "C:\\", ancestor: true }), false);
    for (const sid of ["AU", "BU"]) {
      for (const rights of ["DT", "SD", "WD"]) {
        assert.equal(
          windowsUserCanWrite(`O:BAG:SYD:PAI(A;;${rights};;;${sid})`, { ancestor: true }),
          true,
          `${sid} ${rights}`,
        );
      }
    }
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(A;;DCLC;;;BU)"), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(A;;DCLC;;;BU)", { ancestor: true }), false);
    const bad = planInstall("win32", winEnv, { ...winOpts, nodeIcacls: "O:BAG:SYD:PAI(A;;AD;;;BU)" });
    assert.equal(bad.ok, false);
    if (!bad.ok) assert.match(bad.message, /unknown SDDL right AD/);
  });

  it("accepts a stock Windows 11 SDDL for C:\\, Program Files, and nodejs", async () => {
    const drive = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)";
    const programFiles = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)";
    const nodejs = "O:SYG:SYD:P(A;OICI;0x1200a9;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    assert.equal(windowsUserCanWrite(drive, { path: "C:\\", ancestor: true }), false);
    assert.equal(windowsUserCanWrite(programFiles, { path: "C:\\Program Files", ancestor: true }), false);
    assert.equal(windowsUserCanWrite(nodejs, { path: "C:\\Program Files\\nodejs", ancestor: false }), false);
    assert.equal(windowsUserCanWrite(`${nodejs}(A;;0x6;;;BU)`, { path: "C:\\Program Files\\nodejs", ancestor: false }), true);
    assert.equal(windowsUserCanWrite(`${programFiles}(A;;0x40;;;AU)`, { path: "C:\\Program Files", ancestor: true }), true);
    assert.equal(windowsUserCanWrite(`${nodejs}(A;;0x2;;;AC)`, { path: "C:\\Program Files\\nodejs", ancestor: false }), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(A;;0x1200a9;;;ZZ)", { ancestor: false }), false);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(A;OICIIO;FA;;;ZZ)(D;;FA;;;BU)", { ancestor: true }), false);
    const err: string[] = [];
    const root = mkdtempSync(join(tmpdir(), "verax-sddl-stock-"));
    try {
      await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env: { ...winEnv, ProgramData: join(root, "data"), ProgramFiles: join(root, "files"), USERPROFILE: join(root, "home") },
        elevated: () => true,
        layout: winOpts,
        exec: (argv) => {
          const stockSddl = (target: string): string => {
            if (target.toLowerCase().includes("nodejs")) return nodejs;
            if (target.toLowerCase().includes("program files")) return programFiles;
            return drive;
          };
          const paths = sddlBatchPaths(argv);
          if (paths) return { status: 0, stdout: sddlJson(paths, stockSddl), stderr: "" };
          const blob = argv.join(" ");
          if (blob.includes(".Sddl")) {
            const matched = blob.match(/LiteralPath '([^']*)'/);
            const target = (matched?.[1] ?? "").replace(/''/g, "'");
            return { status: 0, stdout: `${stockSddl(target)}\n`, stderr: "" };
          }
          if (systemToolName(argv[0] ?? "") === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (systemToolName(argv[0] ?? "") === "net") return { status: 2, stdout: "", stderr: "not found\n" };
          if (systemToolName(argv[0] ?? "") === "fsutil") return { status: 1, stdout: "", stderr: "" };
          return { status: 0, stdout: "", stderr: "" };
        },
        io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
      });
      assert.equal(err.join("").includes("can be changed by your user account"), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("treats object and callback allows as writes, skips callback deny, and names an unknown ACE type", () => {
    const xa = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(XA;;FA;;;S-1-5-21-1-2-3-1001;(Member_of {SID(BA)}))";
    assert.equal(windowsUserCanWrite(xa, { ancestor: false }), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(OA;;0x2;;;BU)", { ancestor: false }), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(ZA;;0x2;;;BU)", { ancestor: false }), true);
    const xd = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(XD;;FA;;;BU)";
    assert.equal(windowsUserCanWrite(xd), false);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(ML;;NW;;;HI)"), false);
    const qq = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(QQ;;FA;;;BU)";
    assert.equal(windowsUserCanWrite(qq), true);
    const bad = planInstall("win32", winEnv, { ...winOpts, nodeIcacls: qq });
    assert.equal(bad.ok, false);
    if (!bad.ok) assert.match(bad.message, /untrusted ACL, unknown SDDL ACE type QQ/);
  });

  it("refuses an ancestor that grants Users delete-child", async () => {
    const text = "O:BAG:SYD:PAI(A;;DT;;;BU)";
    assert.equal(windowsUserCanWrite(text, { path: "C:\\Program Files", ancestor: true }), true);
    const err: string[] = [];
    const code = await runInstall(["install", "--port", "8801"], {
      platform: "win32",
      env: winEnv,
      elevated: () => true,
      layout: winOpts,
      exec: (argv) => {
        if (systemToolName(argv[0] ?? "") === "icacls") {
          const target = argv[1] ?? "";
          if (target === "C:\\Program Files") return { status: 0, stdout: text, stderr: "" };
          return { status: 0, stdout: `${target} BUILTIN\\Administrators:(F)\n`, stderr: "" };
        }
        if (systemToolName(argv[0] ?? "") === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
        return { status: 0, stdout: "", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
    });
    assert.equal(code, 78);
    assert.match(err.join(""), /can be changed by your user account/);
    assert.match(err.join(""), /C:\\Program Files/);
  });

  it("refuses a node file that grants Users write", async () => {
    const text = "O:BAG:SYD:PAI(A;;FW;;;BU)";
    assert.equal(windowsUserCanWrite(text, { path: "C:\\Program Files\\nodejs\\node.exe", ancestor: false }), true);
    const err: string[] = [];
    const code = await runInstall(["install", "--port", "8801"], {
      platform: "win32",
      env: winEnv,
      elevated: () => true,
      layout: winOpts,
      exec: (argv) => {
        if (systemToolName(argv[0] ?? "") === "icacls") {
          const target = argv[1] ?? "";
          if (target.endsWith("node.exe")) return { status: 0, stdout: text, stderr: "" };
          return { status: 0, stdout: `${target} BUILTIN\\Administrators:(F)\n`, stderr: "" };
        }
        if (systemToolName(argv[0] ?? "") === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
        return { status: 0, stdout: "", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
    });
    assert.equal(code, 78);
    assert.match(err.join(""), /can be changed by your user account/);
    assert.match(err.join(""), /node\.exe/);
  });

  it("refuses a root-owned symlink whose target lives in a user-owned directory", async (t) => {
    const root = mkdtempSync(join(tmpdir(), "verax-link-"));
    const linkDir = join(root, "link");
    const userDir = join(root, "user");
    const target = join(userDir, "node");
    const link = join(linkDir, "node");
    const err: string[] = [];
    try {
      mkdirSync(linkDir);
      mkdirSync(userDir);
      writeFileSync(target, "");
      try {
        symlinkSync(target, link);
      } catch (error) {
        if (process.platform === "win32" && (error as NodeJS.ErrnoException).code === "EPERM") {
          t.skip("no symbolic-link privilege on this Windows account; the hosted Windows runner has it");
          return;
        }
        throw error;
      }
      const platform = process.platform === "win32" ? "win32" : "linux";
      const resolved = resolveTrustPath(link, platform);
      const expected =
        process.platform === "win32" ? realpathSync.native(target).toLowerCase() : realpathSync(target);
      const actual = process.platform === "win32" ? resolved.toLowerCase() : resolved;
      assert.equal(actual, expected);
      assert.notEqual(resolved, link);
      const code = await runInstall(["install", "--port", "8801"], {
        platform,
        env: platform === "win32" ? winEnv : linuxEnv,
        elevated: () => true,
        layout: { execPath: link, bodyVersion: "0.3.0", npmCli: target },
        exec: (argv) => {
          const passwd = getentAnswer(argv, linuxEnv.VERAX_INVOKING_HOME);
          if (passwd) return passwd;
          if (platform === "win32" && systemToolName(argv[0] ?? "") === "icacls") {
            return { status: 0, stdout: `${argv[1] ?? resolved} BUILTIN\\Users:(W)\n`, stderr: "" };
          }
          return { status: 0, stdout: "", stderr: "" };
        },
        io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
      });
      assert.equal(code, 78);
      assert.match(err.join(""), /can be changed by your user account/);
      const text = err.join("");
      const needle = platform === "win32" ? resolved.toLowerCase() : resolved;
      assert.ok((platform === "win32" ? text.toLowerCase() : text).includes(needle), text);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("powershell ops carry PATHEXT and never the caller PATH", () => {
    const poisoned = { ...winEnv, PATH: "C:\\evil", Path: "C:\\evil", PATHEXT: ".TXT" };
    const win = okPlan("win32", poisoned, winOpts);
    const scripts = win.ops.filter(
      (op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && systemToolName(op.argv[0] ?? "") === "powershell",
    );
    assert.ok(scripts.length >= 1);
    for (const op of scripts) {
      assert.match(op.env?.PATHEXT ?? "", /\.EXE/i);
      assert.equal(op.env?.PATH, undefined);
      assert.equal(op.env?.Path, undefined);
      assert.match(op.env?.ComSpec ?? "", /\\System32\\cmd\.exe$/i);
      assert.match(op.env?.SystemDrive ?? "", /^[A-Za-z]:$/);
      assert.ok(op.env?.SystemRoot);
      assert.ok(op.env?.windir);
    }
    const built = systemToolEnv("win32");
    assert.equal(built.PATH, undefined);
    assert.match(built.PATHEXT ?? "", /\.EXE/i);
  });

  it("generated powershell scripts stop on errors and check every native call", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const scripts = win.ops.filter(
      (op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && systemToolName(op.argv[0] ?? "") === "powershell",
    );
    assert.ok(scripts.length >= 1);
    for (const op of scripts) {
      const text = op.argv[op.argv.length - 1] ?? "";
      assert.ok(text.startsWith("$ErrorActionPreference = 'Stop'"));
      assert.match(text, /Set-StrictMode -Version 3/);
      assert.match(text, /catch\s*\{[^}]*exit\s+[1-9]/);
      const native = [...text.matchAll(/& \$(\w+)/g)];
      for (const call of native) {
        const after = text.slice((call.index ?? 0) + call[0].length);
        const next = after.slice(0, after.indexOf("& $") === -1 ? after.length : after.indexOf("& $"));
        assert.match(next, /\$LASTEXITCODE -ne 0/);
        assert.match(next, new RegExp(`${call[1]} exited \\$LASTEXITCODE`));
      }
    }
  });

  it("a powershell script failure prints stderr and stops, including a zero exit with an error marker", async () => {
    const err: string[] = [];
    let continued = false;
    let password = "";
    const root = mkdtempSync(join(tmpdir(), "verax-ps-fail-"));
    let code = 1;
    try {
    code = await runInstall(["install", "--port", "8801"], {
      platform: "win32",
      env: { ...winEnv, ProgramData: join(root, "data"), ProgramFiles: join(root, "files"), USERPROFILE: join(root, "home") },
      elevated: () => true,
      layout: winOpts,
      exec: (argv, stdin) => {
        const sddl = sddlStdout(argv);
        if (sddl !== null) return { status: 0, stdout: sddl, stderr: "" };
        if (systemToolName(argv[0] ?? "") === "powershell" && argv.some((arg) => arg.includes("New-LocalUser"))) {
          password = stdin ?? "";
          return { status: 0, stdout: stdin ?? "", stderr: `${PS_ERROR_MARK} secedit exited 1\n` };
        }
        if (systemToolName(argv[0] ?? "") === "powershell" && argv.some((arg) => arg.includes("Register-ScheduledTask"))) {
          continued = true;
        }
        if (systemToolName(argv[0] ?? "") === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
        if (systemToolName(argv[0] ?? "") === "net") return { status: 2, stdout: "", stderr: "not found\n" };
        if (systemToolName(argv[0] ?? "") === "fsutil") return { status: 1, stdout: "", stderr: "" };
        if (systemToolName(argv[0] ?? "") === "icacls") {
          const target = argv[1] ?? "";
          return { status: 0, stdout: `${target} BUILTIN\\Administrators:(F)\n  NT AUTHORITY\\SYSTEM:(F)\n`, stderr: "" };
        }
        return { status: 0, stdout: "", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
    });
    assert.equal(code, 1);
    assert.equal(continued, false);
    assert.ok(password.length >= 32);
    const written = err.join("");
    assert.match(written, new RegExp(PS_ERROR_MARK));
    assert.equal(written.includes(password), false);
    assert.equal(written.includes("New-LocalUser"), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("private install temp is admin-only under ProgramData and precedes every script", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const scripts = win.ops.filter(
      (op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && systemToolName(op.argv[0] ?? "") === "powershell",
    );
    assert.ok(scripts.length >= 1);
    const firstScript = win.ops.findIndex(
      (op) => op.op === "argv" && systemToolName(op.op === "argv" ? op.argv[0] ?? "" : "") === "powershell",
    );
    const tempAt = win.ops.findIndex((op) => op.op === "private-temp");
    assert.ok(tempAt >= 0 && firstScript > tempAt);
    const temp = win.ops[tempAt];
    if (!temp || temp.op !== "private-temp") throw new Error("missing private temp");
    assert.match(temp.path, /^C:\\ProgramData\\Verax\\install-tmp-[0-9a-f]{32}$/);
    assert.deepEqual(temp.acl, ["*S-1-5-32-544", "*S-1-5-18"]);
    assert.equal(temp.inheritance, "removed");
    assert.equal(temp.owner, "*S-1-5-32-544");
    for (const op of scripts) {
      assert.equal(op.env?.TEMP, temp.path);
      assert.equal(op.env?.TMP, temp.path);
      assert.match(op.env?.TEMP ?? "", /\\ProgramData\\Verax\\/);
      assert.equal((op.env?.TEMP ?? "").includes("AppData"), false);
    }
    const account = scripts.find((op) => (op.argv[op.argv.length - 1] ?? "").includes("SeBatchLogonRight"));
    if (!account) throw new Error("missing secedit script");
    const text = account.argv[account.argv.length - 1] ?? "";
    assert.equal(text.includes("$env:TEMP"), false);
    assert.match(text, /verax-rights\.cfg/);
    assert.match(text, /verax-rights-after\.cfg/);
    assert.match(text, /secedit \/export/);
    assert.match(text, /previous holders plus the service account/);
    assert.equal(text.includes(LOGON_HOLDER_COMPARE), true);
    assert.equal(text.includes("SetEquals"), false);
    assert.match(text, /Normalize-LogonHolders/);
    assert.match(
      text,
      /\(New-Object System\.Security\.Principal\.NTAccount\(\$n\)\)\.Translate\(\[System\.Security\.Principal\.SecurityIdentifier\]\)\.Value/,
    );
    assert.match(text, /'previous: '/);
    assert.match(text, /'expected: '/);
    assert.match(text, /'after: '/);
    assert.match(text, /'added: '/);
    assert.match(text, /'missing: '/);
    assert.match(text, /holders, service account added/);
    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const linuxTemp = linux.ops.find((op) => op.op === "private-temp");
    if (!linuxTemp || linuxTemp.op !== "private-temp") throw new Error("missing posix private temp");
    assert.equal(linuxTemp.mode, 0o700);
    assert.match(linuxTemp.path, /^\/var\/tmp\/verax-install-tmp-[0-9a-f]{32}$/);
  });

  it("an npm failure prints the debug log tail and icacls, then removes the private temp", async (t) => {
    const root = mkdtempSync(join(tmpdir(), "verax-npm-fail-"));
    const err: string[] = [];
    let tempPath = "";
    let codeDir = "";
    const posix = process.platform === "linux" || process.platform === "darwin" ? process.platform : null;
    const trustedStandIn = posix === null ? undefined : ["/usr/bin/bash", "/bin/bash", "/usr/bin/dash", "/usr/bin/true", "/bin/true"].find((file) => {
      try {
        const st = lstatSync(file);
        return !st.isSymbolicLink() && st.uid === 0 && (st.mode & 0o022) === 0;
      } catch {
        return false;
      }
    });
    if (posix !== null && trustedStandIn === undefined) {
      rmSync(root, { recursive: true, force: true });
      t.skip("no root-owned binary to stand in for Node");
      return;
    }
    try {
      const code = await runInstall(["install", "--port", "8801"], {
        platform: posix ?? "win32",
        env: posix
          ? { SUDO_USER: "runner", VERAX_INVOKING_HOME: join(root, "home") }
          : {
              ...winEnv,
              ProgramData: join(root, "data"),
              ProgramFiles: join(root, "files"),
              USERPROFILE: join(root, "home"),
            },
        elevated: () => true,
        layout: posix
          ? { execPath: trustedStandIn!, bodyVersion: "0.3.0", npmCli: trustedStandIn! }
          : winOpts,
        posixRoot: posix ? join(root, "fsroot") : undefined,
        exec: (argv) => {
          const passwd = getentAnswer(argv, join(root, "home"));
          if (passwd) return passwd;
          const tool = systemToolName(argv[0] ?? "");
          const sddl = sddlStdout(argv);
          if (sddl !== null) return { status: 0, stdout: sddl, stderr: "" };
          if (tool === "whoami" || tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
          if (tool === "id") return { status: 1, stdout: "", stderr: "" };
          const npmCli = posix ? trustedStandIn! : winOpts.npmCli;
          if (argv[0] === (posix ? trustedStandIn : winOpts.execPath) && argv[1] === npmCli) {
            const configAt = argv.indexOf("--userconfig");
            const config = configAt >= 0 ? argv[configAt + 1] : undefined;
            if (!config) throw new Error("npm argv is missing --userconfig");
            tempPath = dirname(config);
            codeDir = argv[argv.indexOf("--prefix") + 1] ?? "";
            const logs = join(tempPath, "cache", "_logs");
            mkdirSync(logs, { recursive: true });
            writeFileSync(join(logs, "2000-01-01T00_00_00_000Z-debug-0.log"), "debug-old\n");
            const dropped = "debug-dropped\n";
            const kept = Array.from({ length: 79 }, () => "debug-kept").join("\n");
            writeFileSync(join(logs, "2026-01-02T00_00_00_000Z-debug-0.log"), `${dropped}${kept}\nEPERM-debug-tail\n`);
            mkdirSync(join(codeDir, "node_modules"), { recursive: true });
            const early = "npm-stdout-dropped\n";
            const mid = Array.from({ length: 90 }, () => "npm-stdout-kept").join("\n");
            return { status: 1, stdout: `${early}${mid}\n`, stderr: "npm error code EPERM\n" };
          }
          if (tool === "icacls" && argv.length === 2) {
            if (tempPath === "") return { status: 0, stdout: winServiceAcl(argv[1] ?? ""), stderr: "" };
            return { status: 0, stdout: `acl ${argv[1]}\n`, stderr: "" };
          }
          if (tool === "ls") return { status: 0, stdout: `drwxr-xr-x ${argv[argv.length - 1] ?? ""}\n`, stderr: "" };
          if (tool === "stat") return { status: 0, stdout: `root|755|${argv[argv.length - 1] ?? ""}\n`, stderr: "" };
          return { status: 0, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: () => undefined },
          stderr: { write: (s: string) => err.push(s) },
        },
      });
      const text = err.join("");
      assert.equal(code, 1);
      assert.match(text, /npm error code EPERM/);
      assert.equal(text.includes("npm-stdout-dropped"), false);
      assert.match(text, /EPERM-debug-tail/);
      assert.equal(text.includes("debug-dropped"), false);
      assert.equal(text.includes("debug-old"), false);
      const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      if (posix) {
        assert.match(text, new RegExp(`drwxr-xr-x ${escape(codeDir)}`));
        assert.match(text, new RegExp(`root 0755 ${escape(codeDir)}`));
        assert.match(text, new RegExp(`drwxr-xr-x ${escape(join(codeDir, "node_modules"))}`));
        assert.match(text, new RegExp(`root 0755 ${escape(tempPath)}`));
      } else {
        assert.match(text, new RegExp(`acl ${escape(codeDir)}`));
        assert.match(text, new RegExp(`acl ${escape(win32.join(codeDir, "node_modules"))}`));
        assert.match(text, new RegExp(`acl ${escape(tempPath)}`));
      }
      assert.equal(existsSync(tempPath), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("a directory grant never combines /T with (OI) or (CI), and a reset follows each one", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const icacls = argvs(win.ops).filter((argv) => systemToolName(argv[0] ?? "") === "icacls");
    for (const argv of icacls) {
      const text = argv.join(" ");
      const grant = /\/grant/.test(text) && (/\(OI\)/.test(text) || /\(CI\)/.test(text));
      if (grant) assert.equal(argv.includes("/T"), false, text);
    }
    const treeGrants = icacls.filter((argv) => argv.includes("/grant:r") && argv.some((arg) => /\(OI\)|\(CI\)/.test(arg)));
    assert.ok(treeGrants.length >= 1);
    for (const grant of treeGrants) {
      const dir = grant[1] ?? "";
      const at = icacls.indexOf(grant);
      const next = icacls[at + 1];
      assert.ok(next, dir);
      assert.equal(next[1], `${dir}\\*`);
      assert.ok(next.includes("/reset") && next.includes("/T") && next.includes("/C"));
      assert.equal(next.some((arg) => /\(OI\)|\(CI\)/.test(arg)), false);
    }
  });

  it("file icacls targets never carry (OI) or (CI)", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const files = new Set([win.tokenPath, win32.join(win32.dirname(win.stateDir), "install.json")]);
    for (const argv of argvs(win.ops)) {
      if (systemToolName(argv[0] ?? "") !== "icacls") continue;
      if (!files.has(argv[1] ?? "")) continue;
      assert.equal(argv.some((arg) => /\(OI\)|\(CI\)/.test(arg)), false, argv.join(" "));
      if (argv.includes("/grant") || argv.includes("/grant:r")) {
        assert.ok(argv.some((arg) => /:(F|\(R\))$/.test(arg)), argv.join(" "));
      }
    }
  });

  it("the ACL verifier refuses an empty file DACL and a DACL missing the service account", () => {
    const file = "C:\\ProgramData\\Verax\\state\\local-issuer\\key.pem";
    const empty = verifyServiceAcl("Successfully processed 1 files", "state", { dir: file, file });
    assert.equal(empty.ok, false);
    if (!empty.ok) assert.match(empty.detail, new RegExp(`empty ACL on ${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    const noSvc = verifyServiceAcl("O:BAG:SYD:PAI(A;ID;FA;;;BA)(A;ID;FA;;;SY)", "state", { dir: file, file });
    assert.equal(noSvc.ok, false);
    if (!noSvc.ok) assert.match(noSvc.detail, /expected svc/);
    const inherited = verifyServiceAcl(
      "O:BAG:SYD:PAI(A;ID;FA;;;S-1-5-21-1)(A;ID;FA;;;BA)(A;ID;FA;;;SY)",
      "state",
      { dir: file, file, svcSid: "S-1-5-21-1" },
    );
    assert.equal(inherited.ok, true);
    const explicitOther = verifyServiceAcl(
      "O:BAG:SYD:PAI(A;ID;FA;;;S-1-5-21-1)(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;;FA;;;S-1-5-21-9)",
      "state",
      { dir: file, file, svcSid: "S-1-5-21-1" },
    );
    assert.equal(explicitOther.ok, false);
    if (!explicitOther.ok) assert.match(explicitOther.detail, /unexpected principal/);
    const checks = installedBoundaryChecks({
      codeDir: "C:\\Program Files\\Verax",
      stateDir: "C:\\ProgramData\\Verax\\state",
      manifest: null,
      hashOf: () => null,
      fileAcls: [{ path: file, text: "", kind: "state" }],
      autostart: true,
    });
    assert.ok(checks.some((check) => check.level === "fail" && check.detail.includes(file)));
  });

  it("dir grant plus reset leaves a child file readable with inherited ACEs", (t) => {
    if (process.platform !== "win32") {
      t.skip("Windows icacls inheritance is checked on a Windows dev machine");
      return;
    }
    const root = mkdtempSync(join(tmpdir(), "verax-acl-reset-"));
    const file = join(root, "key.pem");
    try {
      writeFileSync(file, "pem");
      const who = spawnSync(systemToolPath("whoami", "win32"), ["/user", "/fo", "csv", "/nh"], {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
      });
      const sid = /S-1-[0-9-]+/.exec(who.stdout ?? "")?.[0];
      assert.ok(sid, who.stderr || who.stdout);
      const icacls = systemToolPath("icacls", "win32");
      const grant = spawnSync(icacls, windowsDirGrantArgs(root, `*${sid}`, "F"), {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
      });
      assert.equal(grant.status, 0, `${grant.stdout}\n${grant.stderr}`);
      const reset = spawnSync(icacls, windowsResetInheritArgs(root), {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
      });
      assert.equal(reset.status, 0, `${reset.stdout}\n${reset.stderr}`);
      assert.equal(readFileSync(file, "utf8"), "pem");
      const listed = spawnSync(icacls, [file], { encoding: "utf8", windowsHide: true, shell: false });
      assert.equal(listed.status, 0, listed.stderr);
      assert.match(listed.stdout ?? "", /\(I\)/);
      const named = spawnSync(
        systemToolPath("powershell", "win32"),
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `(New-Object Security.Principal.SecurityIdentifier '${sid}').Translate([Security.Principal.NTAccount]).Value`,
        ],
        { encoding: "utf8", windowsHide: true, shell: false, env: systemToolEnv("win32") },
      );
      assert.equal(named.status, 0, `${named.stdout}\n${named.stderr}`);
      const account = (named.stdout ?? "").trim();
      assert.ok(account, named.stderr || named.stdout);
      const escaped = account.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      assert.match(listed.stdout ?? "", new RegExp(`${escaped}:\\(I\\)`));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  function logAclAndOwner(label: string, dir: string): void {
    const listed = spawnSync(systemToolPath("icacls", "win32"), [dir], {
      encoding: "utf8",
      windowsHide: true,
      shell: false,
    });
    const literal = dir.replace(/'/g, "''");
    const owner = spawnSync(
      systemToolPath("powershell", "win32"),
      ["-NoProfile", "-NonInteractive", "-Command", `(Get-Acl -LiteralPath '${literal}').Owner`],
      { encoding: "utf8", windowsHide: true, shell: false, env: systemToolEnv("win32") },
    );
    console.error(
      [`=== ${label} ===`, `icacls ${dir}`, listed.stdout ?? "", listed.stderr ?? "", `Owner: ${(owner.stdout ?? "").trim()}`, owner.stderr ?? ""].join("\n"),
    );
  }

  it("install-mode init leaves key.pem with only inherited ACEs", async (t) => {
    if (process.platform !== "win32") {
      t.skip("Windows icacls inheritance is checked on a Windows dev machine");
      return;
    }
    const root = mkdtempSync(join(tmpdir(), "verax-acl-init-"));
    const tokenPath = join(root, "..", `token-${process.pid}`);
    const err: string[] = [];
    try {
      const who = spawnSync(systemToolPath("whoami", "win32"), ["/user", "/fo", "csv", "/nh"], {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
      });
      const sid = /S-1-[0-9-]+/.exec(who.stdout ?? "")?.[0];
      assert.ok(sid, who.stderr || who.stdout);
      const icacls = systemToolPath("icacls", "win32");
      const grant = spawnSync(icacls, windowsDirGrantArgs(root, `*${sid}`, "F"), {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
      });
      assert.equal(grant.status, 0, `${grant.stdout}\n${grant.stderr}`);
      const started = Date.now();
      const code = await runInitLocal(
        ["--local", root, "--port", "8801"],
        { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
        { quiet: true, noOwnerGrant: true, tokenPath },
      );
      const elapsed = Date.now() - started;
      if (code !== 0) {
        logAclAndOwner("temp root", root);
        logAclAndOwner("token folder", dirname(tokenPath));
      }
      assert.equal(code, 0, `exit ${code} after ${elapsed}ms\n${err.join("")}`);
      const key = join(root, "local-issuer", "key.pem");
      const listed = spawnSync(icacls, [key], { encoding: "utf8", windowsHide: true, shell: false });
      assert.equal(listed.status, 0, listed.stderr);
      const aces = (listed.stdout ?? "").split(/\r?\n/).filter((line) => line.includes(":("));
      assert.ok(aces.length >= 1, listed.stdout);
      for (const line of aces) assert.match(line, /\(I\)/, line);
      const named = spawnSync(
        systemToolPath("powershell", "win32"),
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `(New-Object Security.Principal.SecurityIdentifier '${sid}').Translate([Security.Principal.NTAccount]).Value`,
        ],
        { encoding: "utf8", windowsHide: true, shell: false, env: systemToolEnv("win32") },
      );
      assert.equal(named.status, 0, `${named.stdout}\n${named.stderr}`);
      const account = (named.stdout ?? "").trim();
      assert.ok(account, named.stderr || named.stdout);
      const explicit = aces.filter((line) => line.toLowerCase().includes(account.toLowerCase()) && !/\(I\)/.test(line));
      assert.deepEqual(explicit, []);
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(tokenPath, { force: true });
    }
  });

  it("install-mode init accepts an existing token folder and leaves its ACL", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-token-parent-"));
    const tokenDir = join(root, "profile");
    const stateDir = join(root, "state");
    const tokenPath = join(tokenDir, "agent.token");
    const err: string[] = [];
    try {
      mkdirSync(tokenDir);
      if (process.platform !== "win32") chmodSync(tokenDir, 0o755);
      const beforeMode = lstatSync(tokenDir).mode;
      const icacls = process.platform === "win32" ? systemToolPath("icacls", "win32") : "";
      const beforeAcl = icacls === ""
        ? ""
        : spawnSync(icacls, [tokenDir], { encoding: "utf8", windowsHide: true, shell: false }).stdout ?? "";
      const started = Date.now();
      const code = await runInitLocal(
        ["--local", stateDir, "--port", "8801"],
        { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
        {
          quiet: true,
          noOwnerGrant: true,
          tokenPath,
          ...(process.platform === "win32" ? {} : { env: { SUDO_USER: userInfo().username } }),
        },
      );
      const elapsed = Date.now() - started;
      if (code !== 0 && process.platform === "win32") {
        logAclAndOwner("temp root", root);
        logAclAndOwner("token folder", tokenDir);
      }
      assert.equal(code, 0, `exit ${code} after ${elapsed}ms\n${err.join("")}`);
      assert.equal(existsSync(tokenPath), true);
      assert.equal(lstatSync(tokenDir).isSymbolicLink(), false);
      assert.equal(lstatSync(tokenDir).mode, beforeMode);
      if (icacls !== "") {
        const after = spawnSync(icacls, [tokenDir], { encoding: "utf8", windowsHide: true, shell: false }).stdout ?? "";
        assert.equal(after, beforeAcl);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("install-mode init refuses a symlink or junction token folder", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-token-link-"));
    const real = join(root, "real");
    const link = join(root, "link");
    const err: string[] = [];
    try {
      mkdirSync(real);
      symlinkSync(real, link, process.platform === "win32" ? "junction" : "dir");
      const code = await runInitLocal(
        ["--local", join(root, "state"), "--port", "8801"],
        { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
        { quiet: true, noOwnerGrant: true, tokenPath: join(link, "agent.token") },
      );
      assert.equal(code, 78, err.join(""));
      assert.match(err.join(""), new RegExp(`refusing: ${link.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} is a reparse point`));
      assert.equal(existsSync(join(real, "agent.token")), false);
    } finally {
      rmSync(link, { recursive: false, force: true });
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("accepts Administrators, SYSTEM, and root-owned token folders", () => {
    const win = {
      dir: "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp",
      symlink: false,
      directory: true,
      reparse: false,
      platform: "win32" as const,
      uid: 0,
      invokingSid: "S-1-5-21-1",
    };
    assert.equal(tokenParentRefusal({ ...win, ownerSid: "S-1-5-32-544" }), null);
    assert.equal(tokenParentRefusal({ ...win, ownerSid: "s-1-5-18" }), null);
    assert.equal(tokenParentRefusal({ ...win, ownerSid: "S-1-5-21-1" }), null);
    assert.match(tokenParentRefusal({ ...win, ownerSid: "S-1-5-21-99" }) ?? "", /not owned by the invoking user/);
    assert.equal(tokenParentRefusal({
      dir: "/home/runner/.verax",
      symlink: false,
      directory: true,
      reparse: false,
      platform: "linux",
      uid: 0,
      invokingUid: 1000,
    }), null);
    assert.match(tokenParentRefusal({
      dir: "/home/runner/.verax",
      symlink: false,
      directory: true,
      reparse: false,
      platform: "linux",
      uid: 1001,
      invokingUid: 1000,
    }) ?? "", /not owned by the invoking user/);
    const repair = rootOwnedTokenParentArgv("/home/runner/.verax", 1000, "linux");
    const chown = repair.find((argv) => systemToolName(argv[0] ?? "") === "chown");
    const mode = repair.find((argv) => systemToolName(argv[0] ?? "") === "chmod");
    assert.ok(chown?.includes("1000:") && chown.includes("/home/runner/.verax"));
    assert.ok(mode?.includes("0700") && mode.includes("/home/runner/.verax"));
    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const tokenDir = "/home/runner/.verax";
    const planned = argvs(linux.ops).filter((argv) => systemToolName(argv[0] ?? "") === "chown" && argv.includes(tokenDir));
    assert.ok(planned.some((argv) => argv.includes(`${linuxEnv.SUDO_USER}:`)));
    assert.ok(argvs(linux.ops).some((argv) => systemToolName(argv[0] ?? "") === "chmod" && argv.includes("0700") && argv.includes(tokenDir)));
  });

  it("refuses a POSIX token folder owned by another uid", async () => {
    const reason = tokenParentRefusal({
      dir: "/home/runner/.verax",
      symlink: false,
      directory: true,
      reparse: false,
      platform: "linux",
      uid: 1001,
      invokingUid: 1000,
    });
    assert.match(reason ?? "", /not owned by the invoking user/);
    assert.equal(tokenParentRefusal({
      dir: "/home/runner/.verax",
      symlink: false,
      directory: true,
      reparse: false,
      platform: "linux",
      uid: 1000,
      invokingUid: 1000,
    }), null);
    if (process.platform === "win32" || process.getuid?.() === 0) return;
    const root = mkdtempSync(join(tmpdir(), "verax-token-uid-"));
    const tokenDir = join(root, "profile");
    const err: string[] = [];
    try {
      mkdirSync(tokenDir);
      const code = await runInitLocal(
        ["--local", join(root, "state"), "--port", "8801"],
        { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
        { quiet: true, noOwnerGrant: true, tokenPath: join(tokenDir, "agent.token"), env: { SUDO_USER: "root" } },
      );
      assert.equal(code, 78, err.join(""));
      assert.match(err.join(""), /not owned by the invoking user/);
      assert.equal(existsSync(join(tokenDir, "agent.token")), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("code dir grants verax-svc RX and state dir grants F", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const code = argvs(win.ops).find((argv) => systemToolName(argv[0] ?? "") === "icacls" && argv[1] === win.codeDir && argv.includes("/grant:r"));
    const state = argvs(win.ops).find((argv) => systemToolName(argv[0] ?? "") === "icacls" && argv[1] === win.stateDir && argv.includes("/grant:r"));
    if (!code || !state) throw new Error("missing service grants");
    assert.ok(code.includes("verax-svc:(OI)(CI)RX"));
    assert.equal(code.includes("verax-svc:(OI)(CI)F"), false);
    assert.ok(state.includes("verax-svc:(OI)(CI)F"));
  });

  it("code ACL verifier refuses svc F, a missing service, and an extra Users ACE", () => {
    const dir = "C:\\Program Files\\Verax";
    const exact = "O:BAG:SYD:PAI(A;OICI;0x1200a9;;;S-1-5-21-1)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
    const full = verifyServiceAcl(exact.replace("0x1200a9", "FA"), "code", { dir, svcSid: "S-1-5-21-1" });
    assert.equal(full.ok, false);
    if (!full.ok) assert.match(full.detail, /\*S-1-5-21-1 F/);
    const missing = verifyServiceAcl("O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", "code", { dir });
    assert.equal(missing.ok, false);
    const extra = verifyServiceAcl(`${exact}(A;OICI;0x1200a9;;;BU)`, "code", { dir, svcSid: "S-1-5-21-1" });
    assert.equal(extra.ok, false);
    if (!extra.ok) assert.match(extra.detail, /S-1-5-32-545/);
    assert.equal(verifyServiceAcl(exact, "code", { dir, svcSid: "S-1-5-21-1" }).ok, true);
  });

  it("a tarball hash that fails twice with EPERM then succeeds proceeds and says it retried", () => {
    const root = mkdtempSync(join(tmpdir(), "verax-tgz-hash-"));
    const file = join(root, "verax-ai-proxy-0.3.0.tgz");
    writeFileSync(file, "tarball-bytes");
    const err: string[] = [];
    let attempts = 0;
    try {
      const hashed = hashFileWithRetry(
        file,
        () => {
          attempts += 1;
          if (attempts <= 2) {
            const error = new Error("open") as NodeJS.ErrnoException;
            error.code = "EPERM";
            throw error;
          }
          return readFileSync(file);
        },
        { stderr: { write: (chunk) => err.push(chunk) } },
        0,
      );
      assert.equal(hashed.ok, true);
      if (!hashed.ok) return;
      assert.equal(attempts, 3);
      assert.equal(hashed.sha256, createHash("sha256").update("tarball-bytes").digest("hex"));
      assert.match(err.join(""), new RegExp(`retried ${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("a tarball hash that keeps failing prints the file and the code", () => {
    const file = join(tmpdir(), "verax-ai-body-missing.tgz");
    const err: string[] = [];
    const hashed = hashFileWithRetry(
      file,
      () => {
        const error = new Error("sharing violation") as NodeJS.ErrnoException;
        error.code = "EPERM";
        throw error;
      },
      { stderr: { write: (chunk) => err.push(chunk) } },
      0,
    );
    assert.equal(hashed.ok, false);
    if (hashed.ok) return;
    assert.match(hashed.error, /could not hash/);
    assert.match(hashed.error, /verax-ai-body-missing\.tgz/);
    assert.match(hashed.error, /EPERM/);
    assert.equal(err.join("").includes("retried"), false);
  });

  it("a tarball copy that fails twice with EPERM then succeeds proceeds and says it retried", () => {
    const root = mkdtempSync(join(tmpdir(), "verax-tgz-retry-"));
    const source = join(root, "verax-ai-proxy-0.3.0.tgz");
    const dest = join(root, "copy.tgz");
    writeFileSync(source, "tarball-bytes");
    const sha256 = createHash("sha256").update("tarball-bytes").digest("hex");
    const err: string[] = [];
    let attempts = 0;
    try {
      const staged = stageTarballCopies(
        [{ source, sha256, dest }],
        (src, dst) => {
          attempts += 1;
          if (attempts <= 2) {
            const error = new Error("open") as NodeJS.ErrnoException;
            error.code = "EPERM";
            throw error;
          }
          copyFileSync(src, dst);
        },
        { stderr: { write: (chunk) => err.push(chunk) } },
        0,
      );
      assert.equal(staged.ok, true);
      assert.equal(attempts, 3);
      assert.match(err.join(""), new RegExp(`retried ${source.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
      assert.equal(readFileSync(dest, "utf8"), "tarball-bytes");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("a tarball whose bytes change between the trust check and the copy is refused", () => {
    const root = mkdtempSync(join(tmpdir(), "verax-tgz-swap-"));
    const source = join(root, "verax-ai-body-0.3.0.tgz");
    const dest = join(root, "copy.tgz");
    writeFileSync(source, "trusted-bytes");
    const sha256 = createHash("sha256").update("trusted-bytes").digest("hex");
    try {
      const staged = stageTarballCopies(
        [{ source, sha256, dest }],
        (_src, dst) => {
          writeFileSync(dst, "swapped-bytes");
        },
        { stderr: { write: () => undefined } },
        0,
      );
      assert.equal(staged.ok, false);
      if (staged.ok) return;
      assert.match(staged.error, /changed after the trust check/);
      assert.match(staged.error, /verax-ai-body-0\.3\.0\.tgz/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("from-tarballs npm install uses the private-temp copies", () => {
    const source = "C:\\pack\\verax-ai-proxy-0.3.0.tgz";
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      fromTarballs: "C:\\pack",
      tarballFiles: [source],
      tarballDigests: [{ file: source, sha256: "abc" }],
      tarballIcacls: "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)",
    });
    if (!plan.ok) throw new Error(plan.message);
    const stage = plan.ops.find((op) => op.op === "stage-tarballs");
    if (!stage || stage.op !== "stage-tarballs") throw new Error("missing tarball copy");
    assert.equal(stage.files[0]?.source, source);
    assert.equal(stage.files[0]?.sha256, "abc");
    assert.match(stage.files[0]?.dest ?? "", /\\install-tmp-[0-9a-f]{32}\\verax-ai-proxy-0\.3\.0\.tgz$/);
    const install = argvs(plan.ops).find((argv) => argv.includes("--omit=dev"));
    assert.equal(install?.includes(source), false);
    assert.ok(install?.includes(stage.files[0]!.dest));
    assert.equal(argvs(plan.ops).some((argv) => argv.includes("signatures")), false);
  });

  it("normalises SeBatchLogonRight holders to a SID set before the read-back compare", () => {
    const map = { Administrators: "S-1-5-32-544" };
    const namesAndSid = normalizeLogonHolders("Administrators,*S-1-5-32-551", map);
    const sidsOnly = normalizeLogonHolders("*S-1-5-32-544, *S-1-5-32-551 ,*S-1-5-32-544", map);
    assert.deepEqual(namesAndSid, ["S-1-5-32-544", "S-1-5-32-551"]);
    assert.deepEqual(sidsOnly, namesAndSid);
    const withExtra = normalizeLogonHolders("*S-1-5-32-544,*S-1-5-32-551,*S-1-5-99-7", map);
    const lines = logonHolderMismatchLines(namesAndSid, namesAndSid, withExtra);
    assert.equal(lines[3], "added: S-1-5-99-7");
    assert.equal(lines[4], "missing: ");
    assert.deepEqual(normalizeLogonHolders("Guest", {}), ["GUEST"]);
  });

  it("npm install drops the caller npm config and refuses a foreign lock resolution", () => {
    const hostile = {
      ...winEnv,
      HOME: "C:\\Users\\evil",
      npm_config_registry: "https://evil.example",
      NPM_CONFIG_REGISTRY: "https://evil.example",
    };
    const win = okPlan("win32", hostile, winOpts);
    const temp = win.ops.find((op) => op.op === "private-temp");
    if (!temp || temp.op !== "private-temp") throw new Error("missing private temp");
    const allowed = new Set([
      "SystemRoot",
      "windir",
      "PATHEXT",
      "ComSpec",
      "SystemDrive",
      "PATH",
      "HOME",
      "USERPROFILE",
      "APPDATA",
      "LOCALAPPDATA",
      "TEMP",
      "TMP",
      "npm_config_cache",
    ]);
    const npmOps = win.ops.filter(
      (op): op is Extract<PlanOp, { op: "argv" }> =>
        op.op === "argv" && (op.argv.includes("--omit=dev") || op.argv.includes("signatures")),
    );
    assert.equal(npmOps.length, 2);
    for (const op of npmOps) {
      for (const key of Object.keys(op.env ?? {})) assert.equal(allowed.has(key), true, key);
      assert.equal(op.env?.npm_config_registry, undefined);
      assert.equal(op.env?.NPM_CONFIG_REGISTRY, undefined);
      assert.equal(op.env?.HOME, temp.path);
      assert.equal(op.env?.USERPROFILE, temp.path);
      assert.equal(op.env?.APPDATA, temp.path);
      assert.equal(op.env?.LOCALAPPDATA, temp.path);
      assert.equal(op.env?.TEMP, temp.path);
      assert.equal(op.env?.TMP, temp.path);
      assert.equal(op.env?.npm_config_cache, win32.join(temp.path, "cache"));
      assert.match(op.env?.PATH ?? "", /nodejs/);
      assert.equal(op.cwd, temp.path);
      assert.ok(op.argv.includes("--userconfig"));
      assert.equal(op.argv[op.argv.indexOf("--userconfig") + 1], win32.join(temp.path, "empty-npmrc"));
      assert.equal(op.argv[op.argv.indexOf("--globalconfig") + 1], win32.join(temp.path, "empty-globalrc"));
      assert.equal(op.argv[op.argv.indexOf("--registry") + 1], "https://registry.npmjs.org/");
    }
    assert.ok(win.ops.some((op) => op.op === "write" && op.path === win32.join(temp.path, "empty-npmrc") && op.contents === ""));
    const linuxHostile = { ...linuxEnv, HOME: "/home/evil", npm_config_registry: "https://evil.example", NPM_CONFIG_REGISTRY: "https://evil.example" };
    const linux = okPlan("linux", linuxHostile, linuxOpts);
    const linuxTemp = linux.ops.find((op) => op.op === "private-temp");
    if (!linuxTemp || linuxTemp.op !== "private-temp") throw new Error("missing posix private temp");
    const linuxNpm = linux.ops.find((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && op.argv.includes("--omit=dev"));
    if (!linuxNpm) throw new Error("missing linux npm install");
    assert.equal(linuxNpm.env?.HOME, linuxTemp.path);
    assert.equal(linuxNpm.env?.npm_config_registry, undefined);
    assert.equal(linuxNpm.env?.NPM_CONFIG_REGISTRY, undefined);
    assert.equal(linuxNpm.argv[linuxNpm.argv.indexOf("--registry") + 1], "https://registry.npmjs.org/");
    const debugPlan = planInstall("win32", { ...hostile, VERAX_INSTALL_DEBUG: "1" }, winOpts);
    if (!debugPlan.ok) throw new Error(debugPlan.message);
    const debugInstall = debugPlan.ops.find((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && op.argv.includes("--omit=dev"));
    const debugAudit = debugPlan.ops.find((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv" && op.argv.includes("signatures"));
    if (!debugInstall || !debugAudit) throw new Error("missing debug npm ops");
    assert.ok(debugInstall.argv.includes("--loglevel"));
    assert.equal(debugInstall.argv[debugInstall.argv.indexOf("--loglevel") + 1], "verbose");
    assert.equal(debugAudit.argv.includes("--loglevel"), false);
    assert.equal(debugInstall.env?.VERAX_INSTALL_DEBUG, undefined);
    const bad = registryLockProblems(JSON.stringify({
      packages: { "node_modules/evil": { resolved: "https://evil.example/evil.tgz" } },
    }));
    assert.deepEqual(bad, ["https://evil.example/evil.tgz"]);
    const good = registryLockProblems(JSON.stringify({
      packages: { "node_modules/@verax-ai/body": { resolved: "https://registry.npmjs.org/@verax-ai/body/-/body-0.3.0.tgz" } },
    }));
    assert.deepEqual(good, []);
  });

  it(
    "powershell holder compare keeps one item and names an extra SID",
    { skip: process.platform === "win32" ? false : "runs %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
    () => {
      const env = systemToolEnv("win32");
      const ps = systemToolPath("powershell", "win32");
      const run = (setup: string) =>
        spawnSync(ps, ["-NoProfile", "-NonInteractive", "-Command", `${setup}; ${LOGON_HOLDER_COMPARE}`], {
          encoding: "utf8",
          windowsHide: true,
          shell: false,
          env,
        });
      const addedMissing = (stderr: string) => {
        const lines = stderr.split(/\r?\n/);
        return {
          added: lines.find((line) => line.startsWith("added: ")),
          missing: lines.find((line) => line.startsWith("missing: ")),
        };
      };
      const one = run("$prev = @('*S-1-5-32-544'); $want = @('*S-1-5-32-544'); $got = @('*S-1-5-32-544')");
      assert.equal(one.status, 0, one.stderr);
      assert.deepEqual(addedMissing(`${one.stderr}`), { added: "added: ", missing: "missing: " });
      const admin = run("$prev = @('Administrators'); $want = @('Administrators'); $got = @('*S-1-5-32-544')");
      assert.equal(admin.status, 0, admin.stderr);
      assert.deepEqual(addedMissing(`${admin.stderr}`), { added: "added: ", missing: "missing: " });
      const extra = run(
        "$prev = @('*S-1-5-32-544','*S-1-5-32-551'); $want = @('*S-1-5-32-544','*S-1-5-32-551'); $got = @('*S-1-5-32-544','*S-1-5-32-551','*S-1-5-99-7')",
      );
      assert.notEqual(extra.status, 0);
      assert.deepEqual(addedMissing(`${extra.stderr}`), { added: "added: S-1-5-99-7", missing: "missing: " });
      const emptyPrev = run("$prev = @(); $want = @('*S-1-5-21-9'); $got = @('*S-1-5-21-9')");
      assert.equal(emptyPrev.status, 0, emptyPrev.stderr);
      assert.deepEqual(addedMissing(`${emptyPrev.stderr}`), { added: "added: ", missing: "missing: " });
    },
  );

  it(
    "powershell with the product env runs whoami and rejects a missing exe",
    { skip: process.platform === "win32" ? false : "spawns the real powershell.exe" },
    () => {
      const env = systemToolEnv("win32");
      const ps = systemToolPath("powershell", "win32");
      const ok = spawnSync(
        ps,
        ["-NoProfile", "-NonInteractive", "-Command", "& (Join-Path $env:SystemRoot 'System32\\whoami.exe')"],
        { encoding: "utf8", windowsHide: true, shell: false, env },
      );
      assert.equal(ok.status, 0, ok.stderr);
      assert.match(`${ok.stdout}`, /\S/);
      const missing = spawnSync(
        ps,
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "try { & (Join-Path $env:SystemRoot 'System32\\verax-no-such.exe') } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }",
        ],
        { encoding: "utf8", windowsHide: true, shell: false, env },
      );
      assert.notEqual(missing.status, 0);
    },
  );
});

describe("verax uninstall", () => {
  const ioOf = (out: string[], err: string[]) => ({
    stdout: { write: (s: string) => out.push(s) },
    stderr: { write: (s: string) => err.push(s) },
  });

  it("a clean machine prints nothing to remove and exits 0", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-uninst-clean-"));
    const out: string[] = [];
    const err: string[] = [];
    const code = await runUninstall(["uninstall"], {
      platform: "win32",
      env: {
        ...winEnv,
        ProgramFiles: join(root, "files"),
        ProgramData: join(root, "data"),
        USERPROFILE: join(root, "home"),
      },
      elevated: () => true,
      exec: () => ({ status: 1, stdout: "", stderr: "" }),
      io: ioOf(out, err),
    });
    assert.equal(code, 0);
    assert.match(out.join(""), /nothing to remove/);
    assert.equal(err.join(""), "");
    rmSync(root, { recursive: true, force: true });
  });

  it("a failing schtasks or icacls step prints the tool, exit code, and stderr", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-uninst-fail-"));
    const out: string[] = [];
    const err: string[] = [];
    const code = await runUninstall(["uninstall"], {
      platform: "win32",
      env: {
        ...winEnv,
        ProgramFiles: join(root, "files"),
        ProgramData: join(root, "data"),
        USERPROFILE: join(root, "home"),
      },
      elevated: () => true,
      exec: (argv) => {
        const tool = systemToolName(argv[0] ?? "");
        if (tool === "schtasks" || tool === "icacls") return { status: 5, stdout: "", stderr: "access denied\n" };
        return { status: 0, stdout: "", stderr: "" };
      },
      io: ioOf(out, err),
    });
    assert.notEqual(code, 0);
    const written = err.join("");
    assert.match(written, /schtasks|icacls/);
    assert.match(written, /\b5\b/);
    assert.match(written, /access denied/);
    rmSync(root, { recursive: true, force: true });
  });

  it("every return 1 and finish(1) in install.ts is preceded by stderr in the same block", () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "install.ts"), "utf8");
    const lines = source.split(/\n/);
    const bare: string[] = [];
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      if (!/\breturn 1\b/.test(line) && !/finish\(1\)/.test(line)) continue;
      // orderTarballs ranks a filename; it is not a process exit.
      if (line.includes('base.includes("proxy")')) continue;
      const indent = /^ */.exec(line)?.[0].length ?? 0;
      let saw = false;
      for (let j = i - 1; j >= 0; j -= 1) {
        const prev = lines[j] ?? "";
        if (prev.trim() === "") continue;
        const prevIndent = /^ */.exec(prev)?.[0].length ?? 0;
        if (prevIndent < indent) break;
        if (prev.includes("io.stderr.write")) {
          saw = true;
          break;
        }
      }
      if (!saw) bare.push(`${i + 1}: ${line.trim()}`);
    }
    assert.deepEqual(bare, []);
  });

  it("the batch SDDL reader runs in the real Windows PowerShell and answers each path by its own key", { skip: process.platform !== "win32" && "runs powershell.exe" }, () => {
    // Mocks cannot see Windows PowerShell 5.1 quirks: an unrolled JSON array once joined every path into one.
    const root = process.env.SystemRoot ?? "C:\\Windows";
    const files = process.env.ProgramFiles ?? "C:\\Program Files";
    const missing = `${root}\\Yok'Olan Klasör [x]\\y`;
    const paths = [root, files, missing];
    const argv = windowsSddlBatchArgv(paths);
    const r = spawnSync(argv[0]!, argv.slice(1), { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const map = JSON.parse(r.stdout) as Record<string, unknown>;
    assert.deepEqual(Object.keys(map).sort(), [...paths].sort());
    for (const p of [root, files]) {
      assert.equal(typeof map[p], "string", `${p}: ${JSON.stringify(map[p])}`);
      assert.match(map[p] as string, /^O:/);
      assert.equal(windowsUserCanWrite(map[p] as string, { path: p, ancestor: true }), false, `${p} is writable: ${map[p] as string}`);
    }
    assert.equal(typeof (map[missing] as { error?: unknown })?.error, "string");
  });

  it("F10e the plan reads every SDDL in one PowerShell call", { skip: process.platform !== "win32" && "creates real Windows paths" }, async () => {
    const countPlan = async (env: NodeJS.ProcessEnv): Promise<{ acl: number; paths: number; locked: boolean; err: string; batch: string }> => {
      let acl = 0;
      let paths = 0;
      let locked = false;
      let batch = "";
      const err: string[] = [];
      await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env,
        elevated: () => true,
        layout: winOpts,
        exec: (argv) => {
          if (!locked && systemToolName(argv[0] ?? "") === "icacls") locked = true;
          if (!locked && sddlPowerShell(argv)) {
            acl += 1;
            paths = sddlBatchPaths(argv)?.length ?? 1;
            batch = argv.join("\n");
          }
          const sddl = sddlStdout(argv);
          if (sddl !== null) return { status: 0, stdout: sddl, stderr: "" };
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "whoami") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net") return { status: 2, stdout: "", stderr: "not found\n" };
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
          if (tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          return { status: 0, stdout: "", stderr: "" };
        },
        io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
      });
      return { acl, paths, locked, err: err.join(""), batch };
    };

    const fresh = mkdtempSync(join(tmpdir(), "verax-f10e-plan-"));
    try {
      const planned = await countPlan({
        ...winEnv,
        ProgramData: join(fresh, "data"),
        ProgramFiles: join(fresh, "files"),
        USERPROFILE: join(fresh, "home"),
      });
      // The task ceiling is 2. This tree reaches 1: Node, npm, and every ancestor in one call.
      assert.equal(planned.acl, 1, planned.err);
      assert.ok(planned.paths >= 2, `batch covered ${planned.paths} paths`);
      assert.equal(planned.batch.includes(winOpts.execPath), false);
      assert.equal(planned.locked, true, planned.err);
      assert.equal(planned.err.includes("can be changed by your user account"), false);
    } finally {
      rmSync(fresh, { recursive: true, force: true });
    }

    const refused = mkdtempSync(join(tmpdir(), "verax-f10e-root-"));
    const data = join(refused, "data");
    const verax = join(data, "Verax");
    try {
      mkdirSync(verax, { recursive: true });
      const early = await countPlan({
        ...winEnv,
        ProgramData: data,
        ProgramFiles: join(refused, "files"),
        USERPROFILE: join(refused, "home"),
      });
      // Pre-created root is inside the same plan read, so the refusal stays at 1.
      assert.equal(early.acl, 1, early.err);
      assert.equal(early.locked, false, early.err);
      assert.match(early.err, /was not created by verax install/);
      const covered = sddlBatchPaths(early.batch.split("\n")) ?? [];
      assert.ok(covered.some((file) => file.replace(/[\\/]+$/, "").toLowerCase() === verax.toLowerCase()));
    } finally {
      rmSync(refused, { recursive: true, force: true });
    }
  });
});

function textsUnder(dir: string): string {
  if (!existsSync(dir)) return "";
  const chunks: string[] = [];
  for (const name of readdirSync(dir, { recursive: true })) {
    const full = join(dir, String(name));
    try {
      chunks.push(readFileSync(full, "utf8"));
    } catch {
      // directories and unreadable entries are not secret files
    }
  }
  return chunks.join("\n");
}
