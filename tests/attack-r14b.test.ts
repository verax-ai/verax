// R14-10 and R14-11. On 202e358 each `it` fails.

import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  bodyReadyLine,
  desktopMode,
  issuerJwksPinPath,
  issuerReadyLine,
  panelReadyLine,
  runDesktop,
  type DesktopSpawnName,
} from "../packages/body/src/desktop.ts";

function nodeEval(code: string): ChildProcess {
  return spawn(process.execPath, ["-e", code], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
}

function hold(line: string): ChildProcess {
  return nodeEval(`process.stderr.write(${JSON.stringify(`${line}\n`)}); setInterval(() => {}, 1e9);`);
}

function modeOf(dir: string): number {
  return lstatSync(dir).mode & 0o777;
}

function writeLock(dir: string, pid: number, port?: number): void {
  const body: { pid: number; startedAt: number; token: string; port?: number } = {
    pid,
    startedAt: 1,
    token: "t",
  };
  if (port !== undefined) body.port = port;
  writeFileSync(join(dir, "ledger.lock"), `${JSON.stringify(body)}\n`, "utf8");
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

/** Run far enough that the state directory and the browser profile both exist. */
async function driveDesktop(stateDir: string, restrictOwner?: (dir: string) => void): Promise<void> {
  const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
  const jwks = JSON.stringify({ keys: [{ kty: "EC", kid: "verax-dev", alg: "ES256" }] });
  await runDesktop(
    { stateDir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
    () => {},
    {
      readyMs: 2_000,
      ...(restrictOwner ? { restrictOwner } : {}),
      spawn: (name: DesktopSpawnName) => {
        if (name === "issuer") {
          const dir = join(stateDir, "dev-issuer");
          mkdirSync(dir, { recursive: true });
          if (process.platform !== "win32") chmodSync(dir, 0o700);
          writeFileSync(issuerJwksPinPath(stateDir), `${jwks}\n`, { mode: 0o600 });
          writeFileSync(join(stateDir, "dev-token"), "fresh-token\n", { mode: 0o600 });
          return hold(issuerReadyLine(issuerPort));
        }
        if (name === "body") return hold(bodyReadyLine(bodyPort));
        if (name === "panel") return hold(`  Local:   ${panelReadyLine(panelPort)}/`);
        return nodeEval("process.exit(0)");
      },
    },
  );
}

describe("attack R14b", () => {
  it("R14-10 attaches only when the lock port and the listener pid are the same", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-r14b-lock-"));
    const port = 8787;
    try {
      writeLock(dir, process.pid);
      assert.deepEqual(await desktopMode(dir, port, () => process.pid), {
        error: "desktop-body-locked",
        pid: process.pid,
        lockPort: null,
      });

      writeLock(dir, process.pid, port + 1);
      assert.deepEqual(await desktopMode(dir, port, () => process.pid), {
        error: "desktop-body-locked",
        pid: process.pid,
        lockPort: port + 1,
      });

      writeLock(dir, process.pid, port);
      assert.deepEqual(await desktopMode(dir, port, () => process.pid + 1), {
        error: "desktop-body-locked",
        pid: process.pid,
        lockPort: port,
      });

      assert.deepEqual(await desktopMode(dir, port, () => process.pid), {
        mode: "attach",
        pid: process.pid,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R14-11 leaves the state directory and the browser profile owner-only", async () => {
    if (process.platform === "win32") {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-r14b-acl-"));
      const seen: string[] = [];
      try {
        await driveDesktop(stateDir, (dir) => seen.push(dir));
        assert.ok(seen.includes(stateDir), seen.join("\n"));
        assert.ok(seen.includes(join(stateDir, "browser-profile")), seen.join("\n"));
      } finally {
        rmSync(stateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
      }
      return;
    }

    const parent = mkdtempSync(join(tmpdir(), "verax-r14b-new-"));
    chmodSync(parent, 0o700);
    const created = join(parent, "state");
    const loose = mkdtempSync(join(tmpdir(), "verax-r14b-loose-"));
    chmodSync(loose, 0o755);
    const profile = join(loose, "browser-profile");
    mkdirSync(profile);
    chmodSync(profile, 0o755);
    try {
      await driveDesktop(created);
      assert.equal(modeOf(created), 0o700);
      assert.equal(modeOf(join(created, "browser-profile")), 0o700);

      await driveDesktop(loose);
      assert.equal(modeOf(loose), 0o700);
      assert.equal(modeOf(profile), 0o700);
    } finally {
      rmSync(parent, { recursive: true, force: true });
      rmSync(loose, { recursive: true, force: true });
    }
  });
});
