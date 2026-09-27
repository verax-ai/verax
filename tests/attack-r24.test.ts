// R24: each `it` asserts the behaviour after the fix. On e94c1f7 the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { chmodSync, existsSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { describe, it } from "node:test";

import { DESKTOP_PARENT_PID, watchDesktopParent } from "../packages/body/src/desktop-parent.ts";
import {
  DESKTOP_CHILD_OUTPUT_CAP,
  bodyReadyLine,
  issuerJwksPinPath,
  issuerReadyLine,
  killTree,
  panelReadyLine,
  parseDesktopArgs,
  rememberChildOutput,
  runDesktop,
  type DesktopSignalHost,
  type DesktopSpawnName,
} from "../packages/body/src/desktop.ts";
import { desktopAncestorDaclHook, privateTempDir } from "./private-temp.ts";

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

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function ownDir(prefix: string): string {
  const dir = privateTempDir(prefix);
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function fakeChild(pid: number): ChildProcess {
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const child = new EventEmitter();
  return Object.assign(child, {
    pid,
    exitCode: null as number | null,
    signalCode: null,
    stdout,
    stderr,
    stdin: null,
    kill: () => true,
  }) as unknown as ChildProcess;
}

function emitSoon(child: ChildProcess, line: string): void {
  setImmediate(() => {
    child.stdout?.emit("data", `${line}\n`);
  });
}

const JWKS = JSON.stringify({ keys: [{ kty: "EC", kid: "verax-dev", alg: "ES256" }] });

function plantIssuer(dir: string): void {
  const pinDir = join(dir, "dev-issuer");
  mkdirSync(pinDir, { recursive: true });
  if (process.platform !== "win32") chmodSync(pinDir, 0o700);
  writeFileSync(issuerJwksPinPath(dir), `${JWKS}\n`, { mode: 0o600 });
  writeFileSync(join(dir, "dev-token"), "fresh-token\n", { mode: 0o600 });
}

const OTHER = "S-1-5-21-999";
const OWNER = "S-1-5-21-1";

describe("attack R24", () => {
  it("R24-1 SIGHUP kills every child", async () => {
    await stopOnSignal("SIGHUP", "linux");
  });

  it("R24-1 SIGHUP on Windows (console window closed) kills every child", async () => {
    await stopOnSignal("SIGHUP", "win32");
  });

  it("R24-1 SIGBREAK kills every child", async () => {
    await stopOnSignal("SIGBREAK", "win32");
  });

  it("R24-1 an uncaught exception kills every child and exits non-zero", async () => {
    await stopOnSignal("uncaughtException", "linux");
  });

  it("R24-1 process exit kills every child", async () => {
    await stopOnSignal("exit", "linux");
  });

  it("R24-1 child output stays within the cap after 5 MiB", async () => {
    let buf = "";
    const block = "x".repeat(1024 * 1024);
    for (let i = 0; i < 5; i += 1) buf = rememberChildOutput(buf, block);
    assert.ok(buf.length <= DESKTOP_CHILD_OUTPUT_CAP);

    const dir = ownDir("verax-r24-buf-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    let stored = "";
    const err: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          ...dirHooks(),
          readyMs: 2_000,
          kill: () => {},
          childOutput: (name, text) => {
            if (name === "issuer") stored = text;
          },
          spawn: (name) => {
            const child = fakeChild(name === "issuer" ? 11 : 12);
            if (name === "issuer") {
              setImmediate(() => {
                child.stdout?.emit("data", "y".repeat(5 * 1024 * 1024));
                child.stdout?.emit("data", `${issuerReadyLine(issuerPort)}\n`);
              });
            }
            if (name === "body") setImmediate(() => child.emit("exit", 1, null));
            return child;
          },
        },
      );
      assert.equal(code, 1, err.join(""));
      assert.ok(stored.length <= DESKTOP_CHILD_OUTPUT_CAP, String(stored.length));
      assert.ok(stored.includes(issuerReadyLine(issuerPort)), stored.slice(-80));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // A fake child with pid 1 once reached stopAll here: POSIX kill(-1) ended every process of the test user.
  it("killTree never signals pid 0 or 1", (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX kill(-1)");
      return;
    }
    const sent: number[] = [];
    const real = process.kill;
    process.kill = ((pid: number) => {
      sent.push(pid);
      return true;
    }) as typeof process.kill;
    try {
      killTree(1);
      killTree(0);
    } finally {
      process.kill = real;
    }
    assert.deepEqual(sent, []);
  });

  it("R24-1 the parent watch exits when the watched pid is not alive", () => {
    let code: number | null = null;
    let pending: (() => void) | undefined;
    let alive = true;
    watchDesktopParent({
      env: { [DESKTOP_PARENT_PID]: "4242" },
      pidAlive: () => alive,
      exit: (status) => {
        code = status;
      },
      schedule: (fn) => {
        pending = fn;
        return { unref() {} };
      },
    });
    assert.equal(code, null, "exited while the parent was alive");
    alive = false;
    pending?.();
    assert.equal(code, 1);
  });

  it("R24-2 a state directory under a 0777 non-sticky parent is refused", async (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX mode bits");
      return;
    }
    const parent = ownDir("verax-r24-0777-");
    chmodSync(parent, 0o777);
    const dir = join(parent, "state");
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(dir, 0o700);
    const spawned: string[] = [];
    try {
      const text = await refuseRun(dir, spawned);
      assert.match(text, new RegExp(`desktop-dir-refused:${escapeRegExp(dir)}`));
      assert.match(text, new RegExp(`ancestor ${escapeRegExp(parent)}`));
      assert.match(text, /can be replaced by another user/);
      assert.deepEqual(spawned, []);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("R24-2 a state directory under a 1777 sticky parent is accepted", async (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX mode bits");
      return;
    }
    const parent = ownDir("verax-r24-1777-");
    chmodSync(parent, 0o1777);
    const dir = join(parent, "state");
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(dir, 0o700);
    const spawned: string[] = [];
    try {
      const text = await refuseRun(dir, spawned);
      assert.equal(text.includes("desktop-dir-refused:"), false, text);
      assert.equal(spawned[0], "issuer");
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("R24-2 a state path whose parent is a symlink is refused", async (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX symlink");
      return;
    }
    const holder = ownDir("verax-r24-hold-");
    const target = ownDir("verax-r24-real-");
    const link = join(holder, "link");
    symlinkSync(target, link);
    const dir = join(link, "state");
    const spawned: string[] = [];
    try {
      const text = await refuseRun(dir, spawned);
      assert.match(text, new RegExp(`desktop-dir-refused:${escapeRegExp(dir)}`));
      assert.match(text, new RegExp(`ancestor ${escapeRegExp(link)}`));
      assert.match(text, /is a link/);
      assert.deepEqual(spawned, []);
    } finally {
      rmSync(holder, { recursive: true, force: true });
      rmSync(target, { recursive: true, force: true });
    }
  });

  // Add-subdirectory on an ancestor cannot move an existing child away. The
  // one use it has, creating a missing intermediate directory first, is the
  // re-check after mkdir below.
  it("R24-2 an ancestor granting only add-subdirectory (0x4) to another SID does not refuse an existing directory", async () => {
    const parent = ownDir("verax-r24-lc-");
    const dir = join(parent, "state");
    mkdirSync(dir, { mode: 0o700 });
    const spawned: string[] = [];
    try {
      const text = await runWithAncestors(dir, spawned, () => `O:SYD:(A;;FA;;;SY)(A;;0x4;;;${OTHER})`);
      assert.equal(text.includes("desktop-dir-refused:"), false, text);
      assert.equal(spawned[0], "issuer");
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("R24-2 an intermediate directory that turns replaceable while mkdir runs is refused after mkdir", async () => {
    const parent = ownDir("verax-r24-race-");
    const mid = join(parent, "mid");
    const dir = join(mid, "state");
    const spawned: string[] = [];
    try {
      const text = await runWithAncestors(dir, spawned, (ancestor) =>
        ancestor.toLowerCase() === mid.toLowerCase() && existsSync(mid)
          ? `O:${OTHER}D:(A;;FA;;;${OTHER})`
          : "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)",
      );
      assert.match(text, new RegExp(`desktop-dir-refused:${escapeRegExp(dir)}`));
      assert.match(text, /can be replaced by another user/);
      assert.deepEqual(spawned, []);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("R24-2 an elevated shell's directory (owner Administrators, the user's own full-control entry) is accepted", async () => {
    const parent = ownDir("verax-r24-ba-");
    const dir = join(parent, "state");
    mkdirSync(dir, { mode: 0o700 });
    const spawned: string[] = [];
    try {
      const text = await runWithAncestors(
        dir,
        spawned,
        () => "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)",
        {
          windowsDirectoryOwner: () => ({ ownerSid: "S-1-5-32-544", invokingSid: OWNER }),
          windowsDirectoryDacl: () => `O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;${OWNER})`,
        },
      );
      assert.equal(text.includes("desktop-dir-refused:"), false, text);
      assert.equal(spawned[0], "issuer");
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("R24-2 an ancestor granting DELETE_CHILD to another SID is refused", async () => {
    await refuseAncestorSddl(`O:SYD:(A;;0x40;;;${OTHER})`);
  });

  it("R24-2 the browser profile is refused when its ancestor can be replaced", async () => {
    const dir = ownDir("verax-r24-profile-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    const profile = join(dir, "browser-profile");
    const spawned: string[] = [];
    const err: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          ...dirHooks(),
          platform: "win32",
          windowsDirectoryOwner: () => ({ ownerSid: OWNER, invokingSid: OWNER }),
          windowsDirectoryDacl: () => `O:${OWNER}D:(A;;FA;;;${OWNER})`,
          windowsAncestorDacl: (ancestor) =>
            ancestor.includes("verax-r24-profile-")
              ? `O:SYD:(A;;0x40;;;${OTHER})`
              : "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)",
          readyMs: 2_000,
          kill: () => {},
          spawn: (name) => {
            spawned.push(name);
            const child = fakeChild(spawned.length);
            if (name === "issuer") {
              plantIssuer(dir);
              emitSoon(child, issuerReadyLine(issuerPort));
            }
            if (name === "body") emitSoon(child, bodyReadyLine(bodyPort));
            if (name === "panel") emitSoon(child, panelReadyLine(panelPort));
            return child;
          },
        },
      );
      const text = err.join("");
      assert.equal(code, 1, text);
      assert.match(text, new RegExp(`desktop-dir-refused:${escapeRegExp(profile)}`));
      assert.match(text, new RegExp(`ancestor ${escapeRegExp(dir)}`, process.platform === "win32" ? "i" : ""));
      assert.deepEqual(spawned, ["issuer", "body", "panel"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  for (const [state, prefix] of [
    ["\\\\host\\share\\verax", "\\\\"],
    ["//host/share/verax", "//"],
    ["\\\\?\\UNC\\host\\share\\verax", "\\\\?\\UNC\\"],
    ["\\\\?\\C:\\verax", "\\\\?\\"],
    ["\\\\.\\C:\\verax", "\\\\.\\"],
  ] as const) {
    it(`R24-3 refuses a Windows state path with prefix ${prefix}`, () => {
      const parsed = parseDesktopArgs(["desktop", "--state", state], "win32");
      assert.ok("error" in parsed, JSON.stringify(parsed));
      if ("error" in parsed) assert.equal(parsed.error, "desktop-state-unc");
    });
  }
});

function dirHooks(): {
  restrictOwner: () => void;
  windowsAncestorDacl?: (dir: string) => string;
  platform?: "win32";
  windowsDirectoryOwner?: () => { ownerSid: string; invokingSid: string };
  windowsDirectoryDacl?: () => string;
} {
  return {
    restrictOwner: () => {},
    ...desktopAncestorDaclHook(),
    ...(process.platform === "win32"
      ? {
          platform: "win32" as const,
          windowsDirectoryOwner: () => ({ ownerSid: OWNER, invokingSid: OWNER }),
          windowsDirectoryDacl: () => `O:${OWNER}D:(A;;FA;;;${OWNER})`,
        }
      : {}),
  };
}

async function refuseRun(dir: string, spawned: string[]): Promise<string> {
  const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
  const err: string[] = [];
  await runDesktop(
    { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
    (line) => err.push(line),
    {
      ...dirHooks(),
      readyMs: 500,
      spawn: (name) => {
        spawned.push(name);
        throw new Error("stop");
      },
    },
  );
  return err.join("");
}

async function runWithAncestors(
  dir: string,
  spawned: string[],
  ancestorDacl: (ancestor: string) => string,
  leaf?: {
    windowsDirectoryOwner: () => { ownerSid: string; invokingSid: string };
    windowsDirectoryDacl: () => string;
  },
): Promise<string> {
  const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
  const err: string[] = [];
  await runDesktop(
    { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
    (line) => err.push(line),
    {
      readyMs: 500,
      restrictOwner: () => {},
      platform: "win32",
      windowsDirectoryOwner: leaf?.windowsDirectoryOwner ?? (() => ({ ownerSid: OWNER, invokingSid: OWNER })),
      windowsDirectoryDacl: leaf?.windowsDirectoryDacl ?? (() => `O:${OWNER}D:(A;;FA;;;${OWNER})`),
      windowsAncestorDacl: ancestorDacl,
      spawn: (name) => {
        spawned.push(name);
        throw new Error("spawned");
      },
    },
  );
  return err.join("");
}

async function refuseAncestorSddl(sddl: string): Promise<void> {
  const parent = ownDir("verax-r24-sddl-");
  const dir = join(parent, "state");
  mkdirSync(dir, { mode: 0o700 });
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  const spawned: string[] = [];
  const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
  const err: string[] = [];
  try {
    const code = await runDesktop(
      { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
      (line) => err.push(line),
      {
        readyMs: 500,
        restrictOwner: () => {},
        platform: "win32",
        windowsDirectoryOwner: () => ({ ownerSid: OWNER, invokingSid: OWNER }),
        windowsDirectoryDacl: () => `O:${OWNER}D:(A;;FA;;;${OWNER})`,
        windowsAncestorDacl: () => sddl,
        spawn: (name) => {
          spawned.push(name);
          throw new Error("spawned");
        },
      },
    );
    const text = err.join("");
    assert.equal(code, 1, text);
    assert.match(text, new RegExp(`desktop-dir-refused:${escapeRegExp(dir)}`));
    assert.match(text, new RegExp(`ancestor ${escapeRegExp(parent)}`));
    assert.deepEqual(spawned, []);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
}

async function stopOnSignal(event: "SIGHUP" | "SIGBREAK" | "uncaughtException" | "exit", platform: "linux" | "win32"): Promise<void> {
  const dir = ownDir(`verax-r24-${event}-`);
  const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
  const killed: number[] = [];
  let exitCode: number | null = null;
  let browser: ChildProcess | undefined;
  const host = new EventEmitter() as EventEmitter & DesktopSignalHost;
  host.platform = platform;
  host.exit = (code: number) => {
    exitCode = code;
    setImmediate(() => browser?.emit("close"));
  };
  const pids: Record<DesktopSpawnName, number> = { issuer: 101, body: 102, panel: 103, browser: 104 };
  const err: string[] = [];
  try {
    await runDesktop(
      { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
      (line) => err.push(line),
      {
        ...dirHooks(),
        readyMs: 2_000,
        signals: host,
        kill: (pid) => {
          if (pid == null) return;
          killed.push(pid);
          if (event === "exit" && new Set(killed).size >= 4) setImmediate(() => browser?.emit("close"));
        },
          spawn: (name, _cmd, _args, env) => {
          if (name === "issuer" || name === "body") assert.equal(env[DESKTOP_PARENT_PID], String(process.pid));
          const child = fakeChild(pids[name]);
          if (name === "issuer") {
            plantIssuer(dir);
            emitSoon(child, issuerReadyLine(issuerPort));
          }
          if (name === "body") emitSoon(child, bodyReadyLine(bodyPort));
          if (name === "panel") emitSoon(child, panelReadyLine(panelPort));
          if (name === "browser") {
            browser = child;
            setImmediate(() => host.emit(event));
          }
          return child;
        },
      },
    );
    for (const pid of Object.values(pids)) {
      assert.ok(killed.includes(pid), `${event} ${err.join("")} killed ${killed.join(",")}`);
    }
    if (event === "exit") assert.equal(exitCode, null);
    else assert.equal(exitCode, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
