import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";

import {
  installedBoundaryChecks,
  planInstall,
  restrictToOwnerWin32,
  runInstall,
  systemToolName,
  systemToolPath,
  type PlanOp,
} from "../packages/body/src/install.ts";

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

function okPlan(platform: "win32" | "linux", env: NodeJS.ProcessEnv, opts: typeof winOpts | typeof linuxOpts) {
  const plan = planInstall(platform, env, opts);
  if (!plan.ok) throw new Error(plan.message);
  return plan;
}

function argvs(ops: PlanOp[]): string[][] {
  return ops.filter((op): op is Extract<PlanOp, { op: "argv" }> => op.op === "argv").map((op) => op.argv);
}

describe("verax install plan", () => {
  it("1 state ACL grants only LocalService and Administrators, or verax mode 0700", () => {
    const win = okPlan("win32", winEnv, winOpts);
    const stateAcl = argvs(win.ops).filter((argv) => systemToolName(argv[0] ?? "") === "icacls" && argv[1] === win.stateDir && argv.includes("/grant:r"));
    assert.ok(stateAcl.length >= 1);
    for (const argv of stateAcl) {
      const text = argv.join(" ");
      assert.match(text, /NT AUTHORITY\\LOCAL SERVICE/);
      assert.match(text, /BUILTIN\\Administrators/);
      assert.equal(text.includes("Users"), false);
      assert.equal(text.includes("Everyone"), false);
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
    const create = argvs(win.ops).find((argv) => systemToolName(argv[0] ?? "") === "schtasks" && argv.includes("/Create"));
    assert.ok(create);
    const tr = create!.join(" ");
    assert.match(tr, /C:\\Program Files\\nodejs\\node\.exe/);
    assert.match(tr, /C:\\Program Files\\Verax\\node_modules\\@verax-ai\\body\\dist\\cli\.js/);
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
    for (const platform of ["win32", "linux"] as const) {
      let ran = 0;
      const err: string[] = [];
      const code = await runInstall(["install", "--port", "8801"], {
        platform,
        env: platform === "win32" ? winEnv : linuxEnv,
        elevated: () => false,
        layout: platform === "win32" ? winOpts : linuxOpts,
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
        "NT AUTHORITY\\LOCAL SERVICE:(OI)(CI)(F)",
        "BUILTIN\\Administrators:(OI)(CI)(F)",
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
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
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
    const planTools = new Set(["icacls", "schtasks", "useradd", "chown", "chmod", "systemctl"]);
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
});
