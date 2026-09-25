import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

import { existsSync, lstatSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";

import {
  installedBoundaryChecks,
  LOGON_HOLDER_COMPARE,
  logonHolderMismatchLines,
  normalizeLogonHolders,
  planInstall,
  PS_ERROR_MARK,
  registryLockProblems,
  resolveTrustPath,
  restrictToOwnerWin32,
  runInstall,
  systemToolEnv,
  systemToolName,
  systemToolPath,
  windowsUserCanWrite,
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

function okPlan(platform: "win32" | "linux", env: NodeJS.ProcessEnv, opts: typeof winOpts | typeof linuxOpts) {
  const plan = planInstall(platform, env, opts);
  if (!plan.ok) throw new Error(plan.message);
  return plan;
}

function argvs(ops: PlanOp[]): string[][] {
  return ops.filter((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv").map((op) => op.argv);
}

/** npm `install --prefix <codeDir>` stands in for a real registry install. */
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
      assert.match(text, /BUILTIN\\Administrators/);
      assert.match(text, /NT AUTHORITY\\SYSTEM/);
      assert.equal(text.includes("Users"), false);
      assert.equal(text.includes("Everyone"), false);
      const grants = argv.filter((arg) => arg.includes(":("));
      for (const grant of grants) {
        const principal = grant.split(":")[0] ?? "";
        const allowed = principal === "verax-svc" || principal === "BUILTIN\\Administrators" || principal === "NT AUTHORITY\\SYSTEM";
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
    assert.match(tr, /Start-ScheduledTask/);
    assert.equal(tr.includes("AppData"), false);
    assert.equal(tr.includes("\\Verax\\node.exe"), false);

    const linux = okPlan("linux", linuxEnv, linuxOpts);
    const unit = linux.ops.find((op) => op.op === "write" && op.path === "/etc/systemd/system/verax.service");
    assert.ok(unit && unit.op === "write");
    assert.match(unit.contents, /ExecStart=\/usr\/bin\/node \/opt\/verax\/node_modules\/@verax-ai\/body\/dist\/cli\.js serve --env-file \/var\/lib\/verax\/verax\.env/);
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
      aclText: [
        "BUILTIN\\Users:(OI)(CI)(RX)",
        "Everyone:(RX)",
        "verax-svc:(OI)(CI)(F)",
        "BUILTIN\\Administrators:(OI)(CI)(F)",
        "NT AUTHORITY\\SYSTEM:(OI)(CI)(F)",
      ].join("\n"),
      autostart: true,
    });
    const failed = checks.filter((c) => c.level === "fail").map((c) => c.detail);
    assert.ok(failed.some((line) => line.includes("node.exe")));
    assert.ok(failed.some((line) => line.includes("BUILTIN\\Users")));
    assert.ok(failed.some((line) => line.includes("Everyone")));
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
    const refused = planInstall("win32", { ...winEnv, USERNAME: "S-1-5-21-1003", USERDOMAIN: "" }, winOpts);
    if (refused.ok) throw new Error("accepted a bare SID grant");
    assert.equal(refused.code, 78);
    assert.match(refused.message, /S-1-5-21-1003:\(R\)/);
    assert.match(refused.message, /leading \*/);

    const win = okPlan("win32", winEnv, winOpts);
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
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "whoami" || tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (tool === "id") return { status: 1, stdout: "", stderr: "" };
          if (tool === "dscl" && argv.includes("-read")) return { status: 1, stdout: "", stderr: "" };
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
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
      rmSync(root, { recursive: true, force: true });
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
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "whoami" || tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (tool === "id") return { status: 1, stdout: "", stderr: "" };
          if (tool === "dscl" && argv.includes("-read")) return { status: 1, stdout: "", stderr: "" };
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
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
    const drive = [
      "C:\\ NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(M)",
      "C:\\ NT AUTHORITY\\Authenticated Users:(AD)",
    ].join("\n");
    assert.equal(windowsUserCanWrite(drive, { path: "C:\\", ancestor: true }), false);
    const nodejs = "C:\\Program Files\\nodejs BUILTIN\\Administrators:(OI)(CI)(F)\n  NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n";
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
        if (systemToolName(argv[0] ?? "") === "icacls") {
          const target = argv[1] ?? "";
          if (/^[A-Za-z]:\\$/.test(target)) return { status: 0, stdout: `${drive}\n`, stderr: "" };
          return { status: 0, stdout: `${target} BUILTIN\\Administrators:(F)\n  NT AUTHORITY\\SYSTEM:(F)\n`, stderr: "" };
        }
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

  it("refuses an ancestor that grants Users delete-child", async () => {
    const text = "C:\\Program Files BUILTIN\\Users:(DC)\n";
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
    const text = "C:\\Program Files\\nodejs\\node.exe Users:(W)\n";
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
    assert.deepEqual(temp.acl, ["BUILTIN\\Administrators", "NT AUTHORITY\\SYSTEM"]);
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

  it("an npm failure prints the debug log tail and icacls, then removes the private temp", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-npm-fail-"));
    const err: string[] = [];
    let tempPath = "";
    let codeDir = "";
    try {
      const code = await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env: {
          ...winEnv,
          ProgramData: join(root, "data"),
          ProgramFiles: join(root, "files"),
          USERPROFILE: join(root, "home"),
        },
        elevated: () => true,
        layout: winOpts,
        exec: (argv) => {
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "whoami" || tool === "powershell") return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
          if (tool === "net" && argv[1] === "user" && argv[2] === "verax-svc" && argv.length === 3) {
            return { status: 2, stdout: "", stderr: "not found\n" };
          }
          if (tool === "fsutil") return { status: 1, stdout: "", stderr: "" };
          if (argv[0] === winOpts.execPath && (argv[1] ?? "").replace(/\\/g, "/").endsWith("/npm-cli.js")) {
            const configAt = argv.indexOf("--userconfig");
            const config = configAt >= 0 ? argv[configAt + 1] : undefined;
            if (!config) throw new Error("npm argv is missing --userconfig");
            tempPath = win32.dirname(config);
            codeDir = argv[argv.indexOf("--prefix") + 1] ?? "";
            const logs = win32.join(tempPath, "cache", "_logs");
            mkdirSync(logs, { recursive: true });
            writeFileSync(win32.join(logs, "2000-01-01T00_00_00_000Z-debug-0.log"), "debug-old\n");
            const dropped = "debug-dropped\n";
            const kept = Array.from({ length: 79 }, () => "debug-kept").join("\n");
            writeFileSync(win32.join(logs, "2026-01-02T00_00_00_000Z-debug-0.log"), `${dropped}${kept}\nEPERM-debug-tail\n`);
            mkdirSync(win32.join(codeDir, "node_modules"), { recursive: true });
            const early = "npm-stdout-dropped\n";
            const mid = Array.from({ length: 90 }, () => "npm-stdout-kept").join("\n");
            return { status: 1, stdout: `${early}${mid}\n`, stderr: "npm error code EPERM\n" };
          }
          if (tool === "icacls" && argv.length === 2) {
            return { status: 0, stdout: `acl ${argv[1]}\n`, stderr: "" };
          }
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
      assert.match(text, new RegExp(`acl ${codeDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
      assert.match(text, new RegExp(`acl ${win32.join(codeDir, "node_modules").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
      assert.match(text, new RegExp(`acl ${tempPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
      assert.equal(existsSync(tempPath), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
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
