import { strict as assert } from "node:assert";
import { realpathSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  elevatedPreloadRefusal,
  moduleSearchDirs,
  runInstall,
  veraxCodeDirectories,
} from "../packages/body/src/install.ts";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");

const winLayout = {
  execPath: "C:\\Program Files\\nodejs\\node.exe",
  bodyVersion: "0.3.0",
  npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
};
const adminSddl = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)";
// What `mkdir C:\node_modules` leaves when a standard user runs it: that user owns it with Modify.
const plantedSddl = "O:S-1-5-21-9G:S-1-5-21-9D:AI(A;OICIID;0x1301bf;;;S-1-5-21-9)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)";

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = addr && typeof addr !== "string" ? addr.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function installWith(opts: { moduleDirs: string[]; sddlFor: (file: string) => string }) {
  const asked: string[] = [];
  const err: string[] = [];
  const code = await runInstall(["install", "--port", String(await freePort())], {
    platform: "win32",
    env: {
      ProgramFiles: "C:\\Program Files",
      ProgramData: "C:\\ProgramData",
      USERPROFILE: "C:\\Users\\operator",
      USERNAME: "operator",
    },
    windowsMachineRoots: { programData: "C:\\ProgramData", programFiles: "C:\\Program Files" },
    elevated: () => true,
    codeProbe: () => false,
    layout: winLayout,
    moduleDirExists: (dir) => opts.moduleDirs.some((d) => d.toLowerCase() === dir.toLowerCase()),
    exec: (_argv, stdin) => {
      if (stdin && stdin.startsWith("[")) {
        const out: Record<string, string> = {};
        for (const file of JSON.parse(stdin) as string[]) {
          asked.push(file.toLowerCase());
          out[file] = opts.sddlFor(file);
        }
        return { status: 0, stdout: JSON.stringify(out), stderr: "" };
      }
      return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
    },
    io: { stdout: { write: () => undefined }, stderr: { write: (line) => err.push(line) } },
  });
  return { code, asked, err: err.join("") };
}

/**
 * Node resolves a bare specifier through `<ancestor>\node_modules` of the
 * loading file, up to the drive root. Stock Windows lets any authenticated
 * user create `C:\node_modules`, and the ancestor rule passed `C:\` on
 * purpose. A module planted there loads into the elevated install's npm or the
 * service the moment a dependency try-requires a name the tree does not ship.
 */
describe("module search directories are trust-checked", () => {
  it("lists every existing ancestor node_modules and skips node_modules segments", () => {
    const present = new Set([
      "C:\\Program Files\\Verax\\node_modules",
      "C:\\node_modules",
      "C:\\a\\node_modules",
    ]);
    assert.deepEqual(
      moduleSearchDirs("C:\\Program Files\\Verax", "win32", (d) => present.has(d)),
      ["C:\\Program Files\\Verax\\node_modules", "C:\\node_modules"],
    );
    // Node never looks in node_modules\node_modules.
    const seen: string[] = [];
    moduleSearchDirs("C:\\a\\node_modules\\pkg", "win32", (d) => {
      seen.push(d);
      return false;
    });
    assert.deepEqual(seen, ["C:\\a\\node_modules\\pkg\\node_modules", "C:\\a\\node_modules", "C:\\node_modules"]);
    assert.deepEqual(
      moduleSearchDirs("/opt/verax/lib", "linux", (d) => d === "/node_modules"),
      ["/node_modules"],
    );
  });

  it("refuses an install when a standard user planted C:\\node_modules", async () => {
    const planted = await installWith({
      moduleDirs: ["C:\\node_modules"],
      sddlFor: (file) => (file.toLowerCase() === "c:\\node_modules" ? plantedSddl : adminSddl),
    });
    assert.notEqual(planted.code, 0, planted.err);
    assert.ok(planted.asked.includes("c:\\node_modules"), planted.asked.join("\n"));
    assert.match(planted.err, /C:\\node_modules/);
    // The remedy is that directory, not another Node.
    assert.match(planted.err, /Module directory C:\\node_modules .*Remove it/);
    assert.doesNotMatch(planted.err, /install Node for all users/);
  });

  it("does not ask about a node_modules that is not on disk", async () => {
    // ProgramData is made untrusted so the install stops at the trust check either way.
    const absent = await installWith({
      moduleDirs: [],
      sddlFor: (file) => (file.toLowerCase() === "c:\\programdata" ? plantedSddl : adminSddl),
    });
    assert.notEqual(absent.code, 0, absent.err);
    assert.equal(absent.asked.includes("c:\\node_modules"), false);
    assert.doesNotMatch(absent.err, /node_modules/);
  });

  it("refuses an install when Users can write the shared PowerShell module directory", async () => {
    // R26 F-I2: PowerShell 5.1 puts this directory in front of the pinned PSModulePath.
    // `Install-Module -Scope AllUsers` guides sometimes loosen it for Users.
    const shared = "C:\\Program Files\\WindowsPowerShell\\Modules";
    const loosened = "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BU)";
    const refused = await installWith({
      moduleDirs: [shared],
      sddlFor: (file) => (file.toLowerCase() === shared.toLowerCase() ? loosened : adminSddl),
    });
    assert.notEqual(refused.code, 0, refused.err);
    assert.ok(refused.asked.includes(shared.toLowerCase()), refused.asked.join("\n"));
    assert.match(refused.err, /WindowsPowerShell\\Modules/);
  });

  it("puts the checkout's ancestor node_modules on the elevated code list", () => {
    const dirs = veraxCodeDirectories();
    assert.ok(dirs.includes(realpathSync(join(repo, "node_modules"))), dirs.join("\n"));
  });

  it("refuses NODE_PATH in an elevated process", () => {
    assert.match(elevatedPreloadRefusal({ NODE_PATH: "C:\\Users\\agent\\mods" }, []) ?? "", /NODE_PATH/);
    assert.equal(elevatedPreloadRefusal({ NODE_PATH: "  " }, []), null);
    assert.equal(elevatedPreloadRefusal({}, []), null);
  });
});
