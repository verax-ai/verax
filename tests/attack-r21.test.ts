// R21: each `it` asserts the behaviour after the fix. On 5c8c4e9 plus the
// uncommitted F28c tree the implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import path, { join } from "node:path";
import { describe, it } from "node:test";

import { forwardIpv6Loopback, runDesktop } from "../packages/body/src/desktop.ts";
import {
  ensureTokenParent,
  systemToolEnv,
  systemToolPath,
  SystemToolError,
  windowsSystemRoot,
} from "../packages/body/src/install.ts";
import { elevatedRunner } from "./elevated-refusal.ts";

function ownerDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function ownerDirectoryHooks(): {
  restrictOwner: () => void;
  windowsDirectoryOwner?: () => { ownerSid: string; invokingSid: string };
  windowsDirectoryDacl?: () => string;
} {
  const restrictOwner = () => {};
  if (process.platform !== "win32") return { restrictOwner };
  const sid = "S-1-5-21-1";
  return {
    restrictOwner,
    windowsDirectoryOwner: () => ({ ownerSid: sid, invokingSid: sid }),
    windowsDirectoryDacl: () => `O:${sid}D:(A;;FA;;;${sid})`,
  };
}

async function ipv6LeftFree(port: number): Promise<void> {
  const opened = await forwardIpv6Loopback(port);
  if (!opened.ok) {
    assert.equal(opened.reason, "unsupported");
    return;
  }
  await new Promise<void>((resolve) => opened.server.close(() => resolve()));
}

function takePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close(() => reject(new Error("free-port")));
        return;
      }
      const port = addr.port;
      server.close(() => resolve(port));
    });
  });
}

function entryIsUnder(entry: string, root: string): boolean {
  const norm = (value: string) => value.replace(/[\\/]+/g, "\\").replace(/\\+$/, "").toLowerCase();
  const child = norm(entry);
  const base = norm(root);
  if (base === "") return false;
  return child === base || child.startsWith(`${base}\\`);
}

describe("attack R21", () => {
  it("R21-1 a live body on the state directory is refused before the issuer port is claimed", async () => {
    const dir = ownerDir("verax-r21-attach-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1, token: "t", port: bodyPort })}\n`,
      "utf8",
    );
    const err: string[] = [];
    const spawned: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          ...ownerDirectoryHooks(),
          listenerPid: () => process.pid,
          spawn: (name) => {
            spawned.push(name);
            throw new Error("spawned while a body was already running");
          },
        },
      );
      const text = err.join("");
      assert.equal(code, 1, text);
      assert.match(text, new RegExp(`desktop-body-running:${bodyPort}`));
      assert.match(text, /verax unlock is for a dead lock only/);
      assert.deepEqual(spawned, []);
      await ipv6LeftFree(bodyPort);
      await ipv6LeftFree(issuerPort);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R21-2 systemToolEnv sets PSModulePath to the System32 Windows PowerShell modules", () => {
    const expected = path.win32.join(windowsSystemRoot(), "System32", "WindowsPowerShell", "v1.0", "Modules");
    assert.equal(systemToolEnv("win32").PSModulePath, expected);
    if (process.platform !== "win32") return;
    // This child is Windows PowerShell, not the verax CLI. An elevated runner
    // still has to execute it; skipIfElevated would skip the check.
    const ran = spawnSync(
      systemToolPath("powershell", "win32"),
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Write-Output $env:PSModulePath; Write-Output ([Environment]::GetFolderPath('MyDocuments'))",
      ],
      {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
        env: systemToolEnv("win32"),
      },
    );
    assert.equal(ran.status, 0, `elevated=${elevatedRunner}\n${ran.stderr ?? ""}\n${ran.stdout ?? ""}`);
    const lines = `${ran.stdout ?? ""}`.split(/\r?\n/).map((line) => line.trim()).filter((line) => line !== "");
    assert.ok(lines.length >= 2, ran.stdout ?? "");
    const documents = lines[lines.length - 1] ?? "";
    const modules = lines.slice(0, -1).join("\n");
    const home = homedir();
    for (const entry of modules.split(";")) {
      const item = entry.trim();
      if (item === "") continue;
      assert.equal(entryIsUnder(item, home), false, item);
      assert.equal(entryIsUnder(item, documents), false, item);
    }
  });

  it(
    "R21-3 ensureTokenParent refuses a token folder swapped for a symlink before the owner change",
    { skip: process.platform === "win32" ? "POSIX only" : false },
    () => {
      const mine = process.getuid?.();
      assert.equal(typeof mine, "number");
      const invoking = mine === 0 ? 1000 : mine!;
      const root = ownerDir("verax-r21-token-");
      const dir = join(root, "token-parent");
      const other = join(root, "other");
      try {
        mkdirSync(dir);
        mkdirSync(other);
        chmodSync(dir, 0o700);
        // 0755, not 0700: a chmod of the link target would change this mode.
        chmodSync(other, 0o755);
        const before = lstatSync(other);
        assert.throws(
          () =>
            ensureTokenParent(dir, { SUDO_USER: "invoker" }, (argv) => {
              if (argv.includes("-u")) return { status: 0, stdout: `${invoking}\n`, stderr: "" };
              return { status: 1, stdout: "", stderr: `unexpected ${argv.join(" ")}` };
            }, () => {
              rmSync(dir, { recursive: true, force: true });
              symlinkSync(other, dir);
            }),
          (err: unknown) => {
            assert.ok(err instanceof SystemToolError);
            assert.match((err as Error).message, /dev\/ino mismatch/);
            return true;
          },
        );
        const after = lstatSync(other);
        assert.equal(after.uid, before.uid);
        assert.equal(after.mode, before.mode);
        assert.equal(lstatSync(dir).isSymbolicLink(), true);
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
  );
});
