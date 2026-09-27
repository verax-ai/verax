// R23: each `it` asserts the behaviour after the fix. On 7628f9c the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { forwardIpv6Loopback, runDesktop } from "../packages/body/src/desktop.ts";

function ownerDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
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

async function ipv6LeftFree(port: number): Promise<void> {
  const opened = await forwardIpv6Loopback(port);
  if (!opened.ok) {
    assert.equal(opened.reason, "unsupported");
    return;
  }
  await new Promise<void>((resolve) => opened.server.close(() => resolve()));
}

describe("attack R23", () => {
  it("R23-1 a live lock and a listener pid are refused, with nothing left on [::1]", async () => {
    const dir = ownerDir("verax-r23-live-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1, token: "t", port: bodyPort })}\n`,
      "utf8",
    );
    const err: string[] = [];
    const spawned: string[] = [];
    const sid = "S-1-5-21-1";
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          restrictOwner: () => {},
          ...(process.platform === "win32"
            ? {
                windowsDirectoryOwner: () => ({ ownerSid: sid, invokingSid: sid }),
                windowsDirectoryDacl: () => `O:${sid}D:(A;;FA;;;${sid})`,
              }
            : {}),
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
      assert.match(text, /use the panel of the desktop that started it/);
      assert.match(text, /verax unlock is for a dead lock only/);
      assert.deepEqual(spawned, []);
      await ipv6LeftFree(bodyPort);
      await ipv6LeftFree(issuerPort);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R23-2 an existing directory mode 0777 is refused and left unchanged", async (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX mode bits");
      return;
    }
    const dir = ownerDir("verax-r23-mode-");
    chmodSync(dir, 0o777);
    const before = statSync(dir).mode & 0o777;
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    const err: string[] = [];
    const spawned: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          restrictOwner: () => {},
          spawn: (name) => {
            spawned.push(name);
            throw new Error("spawned for a directory others could write");
          },
        },
      );
      const text = err.join("");
      assert.equal(before, 0o777);
      assert.equal(code, 1, text);
      assert.ok(text.includes(`desktop-dir-refused:${dir}`), text);
      assert.match(text, /writable by others/);
      assert.match(text, /use a new directory/);
      assert.equal(statSync(dir).mode & 0o777, before);
      assert.deepEqual(spawned, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R23-2 an existing 0700 directory with a dev-issuer symlink is refused", async (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX symlink");
      return;
    }
    const dir = ownerDir("verax-r23-link-");
    const outside = ownerDir("verax-r23-out-");
    symlinkSync(outside, join(dir, "dev-issuer"));
    const before = statSync(dir).mode & 0o777;
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    const err: string[] = [];
    const spawned: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          restrictOwner: () => {},
          spawn: (name) => {
            spawned.push(name);
            throw new Error("spawned while dev-issuer was a symlink");
          },
        },
      );
      const text = err.join("");
      assert.equal(code, 1, text);
      assert.ok(text.includes(`desktop-dir-refused:${dir}`), text);
      assert.match(text, /dev-issuer in that directory is a symlink or junction/);
      assert.equal(statSync(dir).mode & 0o777, before);
      assert.deepEqual(spawned, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("R23-2 a Windows DACL that grants write to another SID is refused", async () => {
    const dir = ownerDir("verax-r23-dacl-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    const owner = "S-1-5-21-1";
    const other = "S-1-5-21-999";
    const err: string[] = [];
    const spawned: string[] = [];
    let restricted = 0;
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          platform: "win32",
          windowsDirectoryOwner: () => ({ ownerSid: owner, invokingSid: owner }),
          windowsDirectoryDacl: () => `D:(A;;0x2;;;${other})`,
          restrictOwner: () => {
            restricted += 1;
          },
          spawn: (name) => {
            spawned.push(name);
            throw new Error("spawned for a directory others could write");
          },
        },
      );
      const text = err.join("");
      assert.equal(code, 1, text);
      assert.ok(text.includes(`desktop-dir-refused:${dir}`), text);
      assert.match(text, /writable by others/);
      assert.match(text, /use a new directory/);
      assert.equal(restricted, 0);
      assert.deepEqual(spawned, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
