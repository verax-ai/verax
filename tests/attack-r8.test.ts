// R8: the surface added since R7, then one more pass over the product.
// Each `it` asserts the safe behaviour. On the current tree the
// implementation does the unsafe thing, so the assertion fails. A fix
// should turn that assertion green without weakening it.

import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { linuxSelinuxNodeRefusal, planInstall, runUninstall, systemToolName, verifyServiceAcl, windowsUserCanWrite } from "../packages/body/src/install.ts";
import type { PlanOp } from "../packages/body/src/install.ts";

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
  veraxRootExists: true,
  markerExists: true,
  winRootOwner: "S-1-5-32-544",
};

const linuxEnv = {
  SUDO_USER: "runner",
  VERAX_INVOKING_HOME: "/home/runner",
};

const linuxOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
  linuxAccount: { exists: false, createdByUs: false, createdGroup: false },
};

const darwinEnv = {
  SUDO_USER: "runner",
  VERAX_INVOKING_HOME: "/Users/runner",
};

const darwinOpts = {
  port: 8801,
  days: 30,
  force: false,
  execPath: "/usr/bin/node",
  bodyVersion: "0.3.0",
  npmCli: "/usr/lib/node_modules/npm/bin/npm-cli.js",
  stateExists: false,
  darwinAccount: {
    uid: 280,
    gid: 280,
    createUser: true,
    createGroup: true,
    recordUser: true,
    recordGroup: true,
  },
};

/** Administrators and SYSTEM full control. Owner is Administrators. */
const ADMIN_ONLY = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)";
/** Same DACL, owned by a standard user. No OWNER RIGHTS ACE. */
const USER_OWNS_ADMIN_DACL = "O:S-1-5-21-100-200-300-1001G:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)";
/** OWNER RIGHTS grants the owner read, which replaces the implicit WRITE_DAC. */
const USER_OWNS_WITH_OW = "O:S-1-5-21-100-200-300-1001G:SYD:PAI(A;;GR;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";

const NULL_DACLS = [
  "O:BAG:SYD:NO_ACCESS_CONTROL",
  "o:bag:syd:no_access_control",
  "O:BAG:SYD: NO_ACCESS_CONTROL",
];

function markerClaimsCreationBeforeAccount(
  ops: readonly PlanOp[],
  toolSuffix: string,
  accountArg: string,
): boolean {
  const markerAt = ops.findIndex((op) => op.op === "write" && op.path.endsWith("/install.json"));
  if (markerAt < 0) return false;
  const marker = ops[markerAt];
  if (!marker || marker.op !== "write") return false;
  const body = JSON.parse(marker.contents) as { createdUser?: unknown; createdGroup?: unknown; createdAccount?: unknown };
  const claims = body.createdUser === true || body.createdGroup === true || body.createdAccount === true;
  if (!claims) return false;
  const createAt = ops.findIndex(
    (op) => op.op === "argv" && op.argv[0]?.endsWith(toolSuffix) === true && op.argv.includes(accountArg),
  );
  if (createAt < 0) return true;
  return markerAt < createAt;
}

describe("attack R8", () => {
  it("R8-1 a NULL DACL is refused and an empty DACL is not", () => {
    for (const sddl of NULL_DACLS) {
      assert.equal(windowsUserCanWrite(sddl), true, sddl);
      assert.equal(windowsUserCanWrite(sddl, { ancestor: true }), true, sddl);
    }
    assert.equal(windowsUserCanWrite("O:BAG:SYD:P"), false);
    assert.equal(windowsUserCanWrite("O:BAG:SYS:AU"), true);
    const root = planInstall("win32", winEnv, {
      ...winOpts,
      winRootAcl: "O:BAG:SYD:NO_ACCESS_CONTROL",
      nodeIcacls: ADMIN_ONLY,
    });
    assert.equal(root.ok, false);
    if (!root.ok) assert.match(root.message, /was not created by verax install|can be changed by your user account/);
    const node = planInstall("win32", winEnv, {
      ...winOpts,
      winRootAcl: ADMIN_ONLY,
      nodeIcacls: "O:BAG:SYD:NO_ACCESS_CONTROL",
    });
    assert.equal(node.ok, false);
    if (!node.ok) assert.match(node.message, /can be changed by your user account/);
  });

  it("R8-2 a non-admin owner without an OWNER RIGHTS ACE can still change the object", () => {
    assert.equal(windowsUserCanWrite(ADMIN_ONLY), false);
    assert.equal(windowsUserCanWrite(ADMIN_ONLY, { ancestor: true }), false);
    assert.equal(windowsUserCanWrite(USER_OWNS_WITH_OW), false);
    assert.equal(windowsUserCanWrite(USER_OWNS_ADMIN_DACL), true);
    assert.equal(windowsUserCanWrite(USER_OWNS_ADMIN_DACL, { ancestor: true }), true);
    const plan = planInstall("win32", winEnv, {
      ...winOpts,
      winRootAcl: ADMIN_ONLY,
      nodeIcacls: USER_OWNS_ADMIN_DACL,
    });
    assert.equal(plan.ok, false);
    if (!plan.ok) assert.match(plan.message, /can be changed by your user account/);
  });

  it("R8-3 the install marker does not claim an account before that account is created", () => {
    const linux = planInstall("linux", linuxEnv, linuxOpts);
    assert.equal(linux.ok, true, linux.ok ? "" : linux.message);
    if (linux.ok) {
      assert.equal(markerClaimsCreationBeforeAccount(linux.ops, "useradd", "verax"), false);
    }
    const darwin = planInstall("darwin", darwinEnv, darwinOpts);
    assert.equal(darwin.ok, true, darwin.ok ? "" : darwin.message);
    if (darwin.ok) {
      assert.equal(markerClaimsCreationBeforeAccount(darwin.ops, "dscl", "/Users/_verax"), false);
    }
  });

  it("R8-4 a missing getenforce still refuses a non-entrypoint label when the kernel is enforcing", () => {
    const refusal = linuxSelinuxNodeRefusal((argv) => {
      const file = argv[0] ?? "";
      if (file.endsWith("getenforce")) return { status: 127, stdout: "", stderr: "not found" };
      const target = argv[argv.length - 1] ?? "";
      if (target.includes("selinux/enforce")) return { status: 0, stdout: "1\n", stderr: "" };
      if (file.endsWith("stat")) return { status: 0, stdout: "system_u:object_r:lib_t:s0\n", stderr: "" };
      return { status: 1, stdout: "", stderr: "" };
    }, "/opt/verax-node/bin/node");
    assert.equal(typeof refusal, "string");
    assert.match(refusal ?? "", /lib_t/);
  });

  it("an empty DACL is not writable and a flagged NULL DACL or an unparsed DACL is", () => {
    assert.equal(windowsUserCanWrite("O:BAG:SYD:"), false);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:P"), false);
    // With no owner field the owner is unknown, and an unknown owner keeps an implicit WRITE_DAC.
    assert.equal(windowsUserCanWrite("D:"), true);
    assert.equal(windowsUserCanWrite("D:P"), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:PNO_ACCESS_CONTROL"), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:AINO_ACCESS_CONTROL", { ancestor: true }), true);
    assert.equal(windowsUserCanWrite("D:ARNO_ACCESS_CONTROL"), true);
    assert.equal(windowsUserCanWrite("O:BAG:SYD:NOT_A_DACL"), true);
  });

  it("an OWNER RIGHTS ACE that grants only read keeps a user-owned file closed", () => {
    assert.equal(windowsUserCanWrite(USER_OWNS_WITH_OW), false);
    assert.equal(windowsUserCanWrite(USER_OWNS_WITH_OW, { ancestor: true }), false);
    const owDac = "O:S-1-5-21-100-200-300-1001G:SYD:PAI(A;;WD;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";
    assert.equal(windowsUserCanWrite(owDac), true);
    assert.equal(windowsUserCanWrite(owDac, { ancestor: true }), true);
    const owOwner = "O:S-1-5-21-100-200-300-1001G:SYD:PAI(A;;WO;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";
    assert.equal(windowsUserCanWrite(owOwner), true);
    const ownedBySvc = "O:S-1-5-21-9G:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)";
    assert.equal(windowsUserCanWrite(ownedBySvc, { svcSid: "S-1-5-21-9" }), false);
    assert.equal(windowsUserCanWrite(ownedBySvc), true);
    const userOwnedService = "O:S-1-5-21-100-200-300-1001G:SYD:PAI(A;OICI;FA;;;S-1-5-21-9)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
    assert.equal(verifyServiceAcl(userOwnedService, "state", { svcSid: "S-1-5-21-9" }).ok, false);
  });

  it("uninstall with a marker whose recorded uid or SID does not match the live account does not delete it", async () => {
    const root = mkdtempSync(join(tmpdir(), "verax-r8-account-"));
    const deleted = (seen: string[][], tool: string, arg: string): boolean =>
      seen.some((argv) => systemToolName(argv[0] ?? "") === tool && argv.includes(arg));
    try {
      const posixRoot = root.replaceAll("\\", "/");
      const linuxMarker = `${posixRoot}/opt/verax/install.json`;
      mkdirSync(join(posixRoot, "opt", "verax"), { recursive: true });
      writeFileSync(linuxMarker, `${JSON.stringify({ createdUser: true, createdGroup: true })}\n`);
      const linuxSeen: string[][] = [];
      const linuxOut: string[] = [];
      const linuxCode = await runUninstall(["uninstall"], {
        platform: "linux",
        env: linuxEnv,
        posixRoot,
        elevated: () => true,
        exec: (argv) => {
          linuxSeen.push([...argv]);
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "getent" && argv[1] === "passwd" && argv[2] === "runner") {
            return { status: 0, stdout: "runner:x:1000:1000::/home/runner:/bin/bash\n", stderr: "" };
          }
          if (tool === "getent" && argv[1] === "passwd") {
            return { status: 0, stdout: "verax:x:1000:1000::/home/verax:/bin/bash\n", stderr: "" };
          }
          if (tool === "getent" && argv[1] === "group") return { status: 0, stdout: "verax:x:1000:\n", stderr: "" };
          if (tool === "id") return { status: 0, stdout: "uid=1000(verax)\n", stderr: "" };
          return { status: 1, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => linuxOut.push(s) },
          stderr: { write: (s: string) => linuxOut.push(s) },
        },
      });
      assert.equal(linuxCode, 0, linuxOut.join(""));
      assert.equal(deleted(linuxSeen, "userdel", "verax"), false, linuxOut.join(""));
      assert.equal(deleted(linuxSeen, "groupdel", "verax"), false, linuxOut.join(""));
      assert.match(linuxOut.join(""), /not removing account verax/);

      const darwinMarker = `${posixRoot}/Library/Verax/install.json`;
      mkdirSync(join(posixRoot, "Library", "Verax"), { recursive: true });
      writeFileSync(darwinMarker, `${JSON.stringify({ createdUser: true, accountUid: 280, accountGid: 280 })}\n`);
      const darwinSeen: string[][] = [];
      const darwinOut: string[] = [];
      const darwinCode = await runUninstall(["uninstall"], {
        platform: "darwin",
        env: { SUDO_USER: "runner", VERAX_INVOKING_HOME: "/Users/runner" },
        posixRoot,
        elevated: () => true,
        exec: (argv) => {
          darwinSeen.push([...argv]);
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "dscl" && argv.includes("NFSHomeDirectory")) {
            return { status: 0, stdout: "NFSHomeDirectory: /Users/runner\n", stderr: "" };
          }
          if (tool === "id") return { status: 0, stdout: "501\n", stderr: "" };
          if (tool === "dscl" && argv.includes("UniqueID")) return { status: 0, stdout: "UniqueID: 501\n", stderr: "" };
          if (tool === "dscl" && argv.includes("PrimaryGroupID")) return { status: 0, stdout: "PrimaryGroupID: 20\n", stderr: "" };
          return { status: 1, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => darwinOut.push(s) },
          stderr: { write: (s: string) => darwinOut.push(s) },
        },
      });
      assert.equal(darwinCode, 0, darwinOut.join(""));
      assert.equal(darwinSeen.some((argv) => systemToolName(argv[0] ?? "") === "dscl" && argv.includes("-delete")), false, darwinOut.join(""));
      assert.match(darwinOut.join(""), /not removing user _verax/);

      // The Windows marker is read from a real Windows path; elsewhere that path does not resolve.
      if (process.platform !== "win32") return;
      const data = join(root, "data");
      mkdirSync(join(data, "Verax"), { recursive: true });
      writeFileSync(join(data, "Verax", "install.json"), `${JSON.stringify({ createdAccount: true, accountSid: "S-1-5-21-1" })}\n`);
      const winSeen: string[][] = [];
      const winOut: string[] = [];
      const winCode = await runUninstall(["uninstall"], {
        platform: "win32",
        env: { ...winEnv, ProgramData: data, ProgramFiles: join(root, "files"), USERPROFILE: join(root, "home") },
        elevated: () => true,
        exec: (argv) => {
          winSeen.push([...argv]);
          const tool = systemToolName(argv[0] ?? "");
          if (tool === "schtasks") return { status: 1, stdout: "", stderr: "" };
          if (tool === "net" && argv.includes("/delete")) return { status: 0, stdout: "", stderr: "" };
          if (tool === "net") return { status: 0, stdout: "verax-svc\n", stderr: "" };
          if (tool === "powershell") return { status: 0, stdout: "S-1-5-21-9\n", stderr: "" };
          return { status: 1, stdout: "", stderr: "" };
        },
        io: {
          stdout: { write: (s: string) => winOut.push(s) },
          stderr: { write: () => undefined },
        },
      });
      assert.equal(winCode, 0, winOut.join(""));
      assert.equal(deleted(winSeen, "net", "/delete"), false, winOut.join(""));
      assert.match(winOut.join(""), /not removing account verax-svc/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
