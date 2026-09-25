// R3: installed-mode breaks R1/R2/CI did not cover. Each `it` asserts the safe
// behaviour. On the current tree the implementation does the unsafe thing, so
// the assertion fails. A fix should turn that assertion green without weakening it.

import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { EX_CONFIG } from "../packages/body/src/config.ts";
import { installedBoundaryChecks, planInstall, runInstall, type ExecResult } from "../packages/body/src/install.ts";

const winEnv = {
  ProgramFiles: "C:\\Program Files",
  ProgramData: "C:\\ProgramData",
  USERPROFILE: "C:\\Users\\operator",
  USERNAME: "operator",
  USERDOMAIN: "DESKTOP",
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

const adminAcl = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
const ATTACKER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";

function sddlBatchPaths(line: string): string[] | null {
  const matched = line.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/);
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

function sameWinPath(a: string, b: string): boolean {
  return a.replace(/[\\/]+$/, "").toLowerCase() === b.replace(/[\\/]+$/, "").toLowerCase();
}

function planText(plan: { ok: true; ops: unknown[] } | { ok: false; message: string }): string {
  return plan.ok ? JSON.stringify(plan.ops) : "";
}

describe("attack R3", () => {
  it("R3-1 a user-written install.json does not authorise a pre-created Verax root", { skip: process.platform !== "win32" && "creates real Windows paths" }, async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-r3-marker-"));
    const data = join(root, "data");
    const files = join(root, "files");
    const verax = join(data, "Verax");
    const err: string[] = [];
    mkdirSync(verax, { recursive: true });
    writeFileSync(
      join(verax, "install.json"),
      JSON.stringify({
        version: "0.3.0",
        codeDir: join(files, "Verax"),
        createdAccount: true,
      }),
    );
    const exec = (argv: string[]): ExecResult => {
      const line = argv.join(" ");
      if (line.includes("reparsepoint")) return { status: 1, stdout: "", stderr: "not a reparse" };
      if (/net\.exe/i.test(argv[0] ?? "") && argv.includes("user")) {
        return { status: 1, stdout: "", stderr: "The user name could not be found." };
      }
      const attacker = `O:${ATTACKER_SID}G:${ATTACKER_SID}D:(A;OICI;FA;;;${ATTACKER_SID})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)`;
      const paths = sddlBatchPaths(line);
      if (paths) {
        return { status: 0, stdout: sddlJson(paths, (file) => (sameWinPath(file, verax) ? attacker : adminAcl)), stderr: "" };
      }
      // The attacker made the root: a standard user owns it and holds full control. Everything else is admin-only.
      if (line.includes("Get-Acl") && line.includes(`${verax}'`)) {
        return { status: 0, stdout: attacker, stderr: "" };
      }
      return { status: 0, stdout: adminAcl, stderr: "" };
    };
    try {
      const code = await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env: { ...winEnv, ProgramData: data, ProgramFiles: files, USERPROFILE: join(root, "home") },
        elevated: () => true,
        layout: { execPath: winOpts.execPath, bodyVersion: winOpts.bodyVersion, npmCli: winOpts.npmCli },
        exec,
        io: {
          stdout: { write: () => undefined },
          stderr: { write: (s: string) => err.push(s) },
        },
      });
      const text = err.join("");
      assert.equal(code, EX_CONFIG);
      assert.match(text, /was not created by verax install|not owned by Administrators/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("W1 a root whose DACL changes between plan and lock is refused at the lock", { skip: process.platform !== "win32" && "creates real Windows paths" }, async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-w1-toctou-"));
    const data = join(root, "data");
    const files = join(root, "files");
    const verax = join(data, "Verax");
    const err: string[] = [];
    mkdirSync(verax, { recursive: true });
    writeFileSync(join(verax, "install.json"), JSON.stringify({ version: "0.3.0", codeDir: join(files, "Verax") }));
    let rootReads = 0;
    const exec = (argv: string[]): ExecResult => {
      const line = argv.join(" ");
      if (line.includes("reparsepoint")) return { status: 1, stdout: "", stderr: "not a reparse" };
      if (/net\.exe/i.test(argv[0] ?? "") && argv.includes("user")) {
        return { status: 1, stdout: "", stderr: "The user name could not be found." };
      }
      const dirtyAcl = `${adminAcl}(A;OICI;FA;;;${ATTACKER_SID})`;
      const paths = sddlBatchPaths(line);
      if (paths) {
        if (paths.some((file) => sameWinPath(file, verax))) rootReads += 1;
        const dirty = rootReads >= 2;
        return {
          status: 0,
          stdout: sddlJson(paths, (file) => (sameWinPath(file, verax) && dirty ? dirtyAcl : adminAcl)),
          stderr: "",
        };
      }
      if (line.includes("Get-Acl") && line.includes(`${verax}'`)) {
        rootReads += 1;
        // Clean when the plan reads it; a user write ACE by the time the lock re-reads it.
        return rootReads === 1
          ? { status: 0, stdout: adminAcl, stderr: "" }
          : { status: 0, stdout: dirtyAcl, stderr: "" };
      }
      return { status: 0, stdout: adminAcl, stderr: "" };
    };
    try {
      const code = await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env: { ...winEnv, ProgramData: data, ProgramFiles: files, USERPROFILE: join(root, "home") },
        elevated: () => true,
        layout: { execPath: winOpts.execPath, bodyVersion: winOpts.bodyVersion, npmCli: winOpts.npmCli },
        exec,
        io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
      });
      assert.ok(rootReads >= 2, `the lock did not re-read the root (${rootReads} reads)`);
      assert.equal(code, EX_CONFIG, err.join(""));
      assert.match(err.join(""), /was not created by verax install/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("R3-2 the agent token ACE is not taken from USERNAME", () => {
    const plan = planInstall("win32", { ...winEnv, USERNAME: "Everyone", USERDOMAIN: "" }, winOpts);
    const blob = planText(plan);
    assert.equal(/Everyone:\(R\)/.test(blob), false);
    if (!plan.ok) assert.match(plan.message, /token|principal|USERNAME/i);
  });

  it("R3-3 verax-svc is the local account, not a bare name lookup", () => {
    const plan = planInstall("win32", winEnv, winOpts);
    if (!plan.ok) throw new Error(plan.message);
    const text = JSON.stringify(plan.ops);
    assert.equal(/NTAccount\('verax-svc'\)/.test(text), false);
    assert.equal(/-User 'verax-svc'/.test(text), false);
    assert.equal(/-Member 'verax-svc'/.test(text), false);
    assert.match(text, /New-LocalUser -Name 'verax-svc'/);
  });

  it("R3-4 VERAX_INVOKING_HOME cannot move the agent token", () => {
    const plan = planInstall(
      "linux",
      { SUDO_USER: "runner", VERAX_INVOKING_HOME: "/tmp/not-the-user" },
      linuxOpts,
    );
    const blob = planText(plan);
    assert.equal(blob.includes("/tmp/not-the-user"), false);
    if (plan.ok) assert.equal(plan.tokenPath, "/home/runner/.verax/agent.token");
    else assert.match(plan.message, /home|token/i);
  });

  it("R3-4 a home that getent cannot confirm is refused, not taken from VERAX_INVOKING_HOME", async () => {
    const err: string[] = [];
    const seen: string[][] = [];
    const code = await runInstall(["install", "--port", "8801"], {
      platform: "linux",
      env: { SUDO_USER: "runner", VERAX_INVOKING_HOME: "/tmp/not-the-user" },
      elevated: () => true,
      layout: linuxOpts,
      exec: (argv: string[]) => {
        seen.push(argv);
        return { status: 2, stdout: "", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
    });
    assert.equal(code, EX_CONFIG);
    assert.match(err.join(""), /could not read the home of runner/);
    assert.equal(seen.length, 1, "only the getent lookup may run");
  });

  it("R3-5 an existing Linux verax login that we did not create is refused", () => {
    const plan = planInstall("linux", { SUDO_USER: "runner", VERAX_INVOKING_HOME: "/home/runner" }, {
      ...linuxOpts,
      linuxAccount: { exists: true, createdByUs: false },
    });
    assert.equal(plan.ok, false);
    if (plan.ok) return;
    assert.equal(plan.code, EX_CONFIG);
    assert.match(plan.message, /verax already exists and was not created by verax install/);
  });

  it("W1 the root lock is the first op and the empty npmrc files are exclusive", () => {
    const plan = planInstall("win32", winEnv, winOpts);
    if (!plan.ok) throw new Error(plan.message);
    assert.equal(plan.ops[0]?.op, "lock-root");
    const tempAt = plan.ops.findIndex((op) => op.op === "private-temp");
    const mkdirAt = plan.ops.findIndex((op) => op.op === "mkdir" && op.path.startsWith(`${winEnv.ProgramData}\\Verax`));
    assert.ok(tempAt > 0);
    assert.ok(mkdirAt > 0);
    const npmrc = plan.ops.find((op) => op.op === "write" && op.path.endsWith("empty-npmrc"));
    if (!npmrc || npmrc.op !== "write") throw new Error("missing empty npmrc");
    assert.equal(npmrc.exclusive, true);
  });

  it("W1 a raced child in a fresh root is refused and removed", { skip: process.platform !== "win32" && "creates real Windows paths" }, async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-w1-race-"));
    const data = join(root, "data");
    const verax = join(data, "Verax");
    const err: string[] = [];
    const exec = (argv: string[]): ExecResult => {
      if (argv.includes("/setowner") && argv[1] === verax) {
        mkdirSync(join(verax, "keys"));
        return { status: 0, stdout: "", stderr: "" };
      }
      if (argv.join(" ").includes("reparsepoint")) return { status: 1, stdout: "", stderr: "" };
      if (/net\.exe/i.test(argv[0] ?? "") && argv.includes("user")) return { status: 1, stdout: "", stderr: "not found" };
      if (/whoami/i.test(argv[0] ?? "")) return { status: 0, stdout: "S-1-5-21-1001\n", stderr: "" };
      const paths = sddlBatchPaths(argv.join("\n"));
      if (paths) return { status: 0, stdout: sddlJson(paths, () => adminAcl), stderr: "" };
      return { status: 0, stdout: adminAcl, stderr: "" };
    };
    try {
      const code = await runInstall(["install", "--port", "8801"], {
        platform: "win32",
        env: { ...winEnv, ProgramData: data, ProgramFiles: join(root, "files"), USERPROFILE: join(root, "home") },
        elevated: () => true,
        layout: { execPath: winOpts.execPath, bodyVersion: winOpts.bodyVersion, npmCli: winOpts.npmCli },
        exec,
        io: { stdout: { write: () => undefined }, stderr: { write: (s: string) => err.push(s) } },
      });
      assert.equal(code, EX_CONFIG);
      assert.match(err.join(""), /keys/);
      assert.equal(existsSync(verax), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("W1 an existing root owned by a user is refused", () => {
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      veraxRootExists: true,
      markerExists: true,
      winRootOwner: "DESKTOP\\operator",
      winRootAcl: adminAcl,
    });
    assert.equal(plan.ok, false);
    if (plan.ok) return;
    assert.match(plan.message, /C:\\ProgramData\\Verax was not created by verax install/);
  });

  it("W1 an existing root with a Users write ACE is refused", () => {
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      veraxRootExists: true,
      markerExists: true,
      winRootOwner: "BUILTIN\\Administrators",
      winRootAcl: "BUILTIN\\Users:(OI)(CI)(M)\nBUILTIN\\Administrators:(OI)(CI)(F)\nNT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n",
    });
    assert.equal(plan.ok, false);
    if (plan.ok) return;
    assert.match(plan.message, /was not created by verax install/);
  });

  it("W1 a user-written marker on a user-owned root is refused", () => {
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      veraxRootExists: true,
      markerExists: true,
      winRootOwner: "DESKTOP\\operator",
      winRootAcl: "DESKTOP\\operator:(OI)(CI)(F)\n",
    });
    assert.equal(plan.ok, false);
    if (plan.ok) return;
    assert.match(plan.message, /was not created by verax install/);
  });

  it("W1 a locked root with our marker is accepted and still locked first", () => {
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      veraxRootExists: true,
      markerExists: true,
      winRootOwner: "BUILTIN\\Administrators",
      winRootAcl: adminAcl,
    });
    if (!plan.ok) throw new Error(plan.message);
    assert.equal(plan.ops[0]?.op, "lock-root");
    const lock = plan.ops[0];
    if (lock.op !== "lock-root") throw new Error("missing root lock");
    assert.equal(lock.create, false);
  });

  it("W1 doctor fails a Users write ACE on the Verax root", () => {
    const checks = installedBoundaryChecks({
      codeDir: "C:\\Program Files\\Verax",
      stateDir: "C:\\ProgramData\\Verax\\state",
      manifest: null,
      hashOf: () => null,
      autostart: true,
      rootDir: "C:\\ProgramData\\Verax",
      rootAclText: "O:BAG:SYD:PAI(A;CI;DCLC;;;BU)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",
    });
    const failed = checks.filter((c) => c.id === "install-root-acl" && c.level === "fail");
    assert.equal(failed.length, 1);
  });
});
