// R20: each `it` asserts the behaviour after the fix. On de516d2 the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  forwardIpv6Loopback,
  ipv6LoopbackAvailable,
  runDesktop,
} from "../packages/body/src/desktop.ts";
import {
  adoptWindowsInstallRoots,
  planInstall,
  readWindowsMachineRoots,
  runUninstall,
  successText,
} from "../packages/body/src/install.ts";

function ownerDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function listen(server: Server, port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host, ipv6Only: host === "::1" }, () => resolve());
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
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

function linkDir(target: string, path: string): void {
  if (process.platform === "win32") symlinkSync(target, path, "junction");
  else symlinkSync(target, path);
}

const winPlan = {
  execPath: "C:\\Program Files\\nodejs\\node.exe",
  bodyVersion: "0.3.0",
  npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
  stateExists: false,
  userSid: "S-1-5-21-1001",
};

describe("attack R20", () => {
  it("R20-1 a listener on [::1] is refused, and a connection there reaches the 127.0.0.1 listener", async (t) => {
    if (!(await ipv6LoopbackAvailable())) {
      t.skip("this host has no IPv6 loopback");
      return;
    }
    const dir = ownerDir("verax-r20-desk-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    const occupant = createServer();
    const err: string[] = [];
    try {
      await listen(occupant, issuerPort, "::1");
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          restrictOwner: () => {},
          spawn: () => {
            throw new Error("spawned while [::1] was already taken");
          },
        },
      );
      assert.equal(code, 1, err.join(""));
      assert.match(err.join(""), new RegExp(`desktop-port-busy:issuer:${issuerPort}:ipv6`));
    } finally {
      await close(occupant);
      rmSync(dir, { recursive: true, force: true });
    }

    const port = await takePort();
    const received: Buffer[] = [];
    const child = createServer((socket) => {
      socket.on("data", (chunk) => received.push(Buffer.from(chunk)));
      socket.end("pong");
    });
    const held = await forwardIpv6Loopback(port);
    try {
      await listen(child, port, "127.0.0.1");
      assert.equal(held.ok, true);
      if (!held.ok) return;
      const reply = await new Promise<string>((resolve, reject) => {
        const sock = createConnection({ host: "::1", port }, () => sock.write("ping"));
        const chunks: Buffer[] = [];
        sock.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        sock.on("end", () => resolve(Buffer.concat(chunks).toString()));
        sock.on("error", reject);
      });
      assert.equal(reply, "pong");
      assert.equal(Buffer.concat(received).toString(), "ping");
    } finally {
      if (held.ok) await close(held.server);
      await close(child);
    }
  });

  it("R20-1 attach refuses [::1] on the body port when another process holds it", async (t) => {
    if (!(await ipv6LoopbackAvailable())) {
      t.skip("this host has no IPv6 loopback");
      return;
    }
    const dir = ownerDir("verax-r20-attach-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    // Live lock, same port, listener pid injected: desktopMode returns attach without a real body.
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1, token: "t", port: bodyPort })}\n`,
      "utf8",
    );
    const occupant = createServer();
    const err: string[] = [];
    const spawned: string[] = [];
    try {
      await listen(occupant, bodyPort, "::1");
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          restrictOwner: () => {},
          listenerPid: () => process.pid,
          spawn: (name) => {
            spawned.push(name);
            throw new Error("spawned while attaching with [::1] already taken");
          },
        },
      );
      assert.equal(code, 1, err.join(""));
      assert.match(err.join(""), new RegExp(`desktop-port-busy:body:${bodyPort}:ipv6`));
      assert.deepEqual(spawned, []);
    } finally {
      await close(occupant);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R20-2 install roots come from the machine, and uninstall does not follow a reparse point", async () => {
    const drifted = planInstall(
      "win32",
      {
        ProgramFiles: "C:\\Program Files",
        ProgramData: "C:\\Users\\agent\\junction",
        USERPROFILE: "C:\\Users\\operator",
      },
      {
        ...winPlan,
        windowsMachineRoots: { programData: "C:\\ProgramData", programFiles: "C:\\Program Files" },
      },
    );
    assert.equal(drifted.ok, false);
    if (!drifted.ok) {
      assert.match(
        drifted.message,
        /refusing: ProgramData in this shell is C:\\Users\\agent\\junction, the machine says C:\\ProgramData/,
      );
    }

    const expanded = readWindowsMachineRoots(() => ({
      status: 0,
      stdout: "ProgramFilesDir=C:\\Program Files\nProgramData=%SystemDrive%\\ProgramData\nSystemDrive=C:\n",
      stderr: "",
    }));
    assert.equal(expanded.programData, "C:\\ProgramData");
    assert.equal(expanded.programFiles, "C:\\Program Files");
    assert.throws(
      () =>
        readWindowsMachineRoots(() => ({
          status: 0,
          stdout: "ProgramFilesDir=C:\\Program Files\nProgramData=%SystemRoot%\\ProgramData\nSystemDrive=C:\n",
          stderr: "",
        })),
      /unexpanded variable/,
    );

    // The rest builds real junctions and Windows paths on disk; elsewhere a
    // POSIX temp path read with win32 rules names nothing.
    if (process.platform !== "win32") return;
    const root = ownerDir("verax-r20-root-");
    const real = join(root, "real");
    const link = join(root, "link");
    const keep = join(real, "Verax", "state", "keep.txt");
    try {
      mkdirSync(join(real, "Verax", "state"), { recursive: true });
      if (process.platform !== "win32") chmodSync(join(real, "Verax", "state"), 0o700);
      writeFileSync(keep, "stay\n", { mode: 0o600 });
      linkDir(real, link);
      assert.throws(
        () =>
          adoptWindowsInstallRoots(
            { ProgramData: link, ProgramFiles: "C:\\Program Files" },
            { programData: link, programFiles: "C:\\Program Files" },
          ),
        /reparse point/,
      );

      const data = join(root, "data");
      mkdirSync(data);
      if (process.platform !== "win32") chmodSync(data, 0o700);
      linkDir(join(real, "Verax"), join(data, "Verax"));
      const err: string[] = [];
      const code = await runUninstall(["uninstall"], {
        platform: "win32",
        env: {
          ProgramFiles: "C:\\Program Files",
          ProgramData: data,
          USERPROFILE: join(root, "home"),
          USERNAME: "operator",
          USERDOMAIN: "DESKTOP",
        },
        windowsMachineRoots: { programData: data, programFiles: "C:\\Program Files" },
        elevated: () => true,
        codeProbe: () => false,
        exec: () => ({ status: 1, stdout: "", stderr: "" }),
        io: {
          stdout: { write: () => undefined },
          stderr: { write: (line: string) => err.push(String(line)) },
        },
      });
      assert.equal(code, 78, err.join(""));
      assert.match(err.join(""), /reparse point/);
      assert.equal(existsSync(keep), true);
      assert.equal(readFileSync(keep, "utf8"), "stay\n");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("R20-3 success text escapes a quote inside the token path", () => {
    const win = successText("win32", {
      codeDir: "C:\\Program Files\\Verax",
      stateDir: "C:\\ProgramData\\Verax\\state",
      tokenPath: "C:\\ProgramData\\Verax\\agent-token\\O'Brien\\agent.token",
      port: 8787,
    });
    assert.ok(win.includes("$(Get-Content -Raw 'C:\\ProgramData\\Verax\\agent-token\\O''Brien\\agent.token')"));
    const posix = successText("linux", {
      codeDir: "/opt/verax",
      stateDir: "/var/lib/verax",
      tokenPath: "/home/o'brien/.verax/agent.token",
      port: 8787,
    });
    assert.ok(posix.includes("$(cat '/home/o'\\''brien/.verax/agent.token')"));
  });
});
