import { strict as assert } from "node:assert";
import { EventEmitter } from "node:events";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";

import {
  bodyReadyLine,
  bodyRpEnv,
  desktopChildEnv,
  desktopCodeRefusal,
  desktopMode,
  desktopPasskeyHint,
  forwardIpv6Loopback,
  issuerEnv,
  issuerJwksPinPath,
  issuerReadyLine,
  parseDesktopArgs,
  readIssuerJwksPin,
  runDesktop,
  type DesktopHooks,
} from "../src/desktop.ts";
import { CREDENTIALS_FILE } from "../src/operator-credentials.ts";

/** What the spawn hook hands back; named through the hook so this file does not import the process module. */
type SpawnedChild = ReturnType<NonNullable<DesktopHooks["spawn"]>>;

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close(() => reject(new Error("free-port")));
        return;
      }
      const port = addr.port;
      server.close(() => resolve(port));
    });
    server.once("error", reject);
  });
}

function stateWithLock(pid: number, port?: number): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-desktop-mode-"));
  const body: { pid: number; startedAt: number; token: string; port?: number } = {
    pid,
    startedAt: Date.now(),
    token: "t",
  };
  if (port !== undefined) body.port = port;
  writeFileSync(join(dir, "ledger.lock"), `${JSON.stringify(body)}\n`, "utf8");
  return dir;
}

/** A pid nothing is running under, found the way doctor.test.ts finds one. */
function deadPid(): number {
  let pid = 1_000_000;
  while (pid < 1_000_200) {
    try {
      process.kill(pid, 0);
      pid += 1;
    } catch {
      return pid;
    }
  }
  throw new Error("no-dead-pid");
}

/**
 * One ledger, one body. A live lock that names this port and whose pid is
 * the listener is `attach` from `desktopMode`. 0.4.0 refuses that result
 * before it claims a port or starts a child. A dead lock is still spawn.
 */
describe("verax desktop and a lock on the state directory", () => {
  it("refuses when the lock names the body port and the listener is that pid", async () => {
    const port = await freePort();
    const issuerPort = await freePort();
    const panelPort = await freePort();
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-mode-")));
    if (process.platform !== "win32") chmodSync(dir, 0o700);
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: Date.now(), token: "t", port })}\n`,
      "utf8",
    );
    const err: string[] = [];
    const spawned: string[] = [];
    const sid = "S-1-5-21-1";
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort: port, panelPort, browser: "fake-browser.mjs" },
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
      assert.match(text, new RegExp(`desktop-body-running:${port}`));
      assert.match(text, /verax unlock is for a dead lock only/);
      assert.deepEqual(spawned, []);
      for (const held of [port, issuerPort]) {
        const opened = await forwardIpv6Loopback(held);
        if (!opened.ok) {
          assert.equal(opened.reason, "unsupported");
          continue;
        }
        await new Promise<void>((resolve) => opened.server.close(() => resolve()));
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses when the lock is live but nothing answers on the body port", async () => {
    const dir = stateWithLock(process.pid);
    const port = await freePort();
    assert.deepEqual(await desktopMode(dir, port, () => null), {
      error: "desktop-body-locked",
      pid: process.pid,
      lockPort: null,
    });
  });

  it("spawns when there is no lock", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-desktop-mode-"));
    const port = await freePort();
    assert.deepEqual(await desktopMode(dir, port), { mode: "spawn" });
  });

  it("spawns when the lock belongs to a dead process", async () => {
    const dir = stateWithLock(deadPid());
    const port = await freePort();
    assert.deepEqual(await desktopMode(dir, port), { mode: "spawn" });
  });

  it("spawns when the lock file cannot be read", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-desktop-mode-"));
    writeFileSync(join(dir, "ledger.lock"), "not json", "utf8");
    const port = await freePort();
    assert.deepEqual(await desktopMode(dir, port), { mode: "spawn" });
  });
});

describe("verax desktop args", () => {
  it("parseDesktopArgs requires --state", () => {
    const parsed = parseDesktopArgs(["desktop"]);
    assert.deepEqual(parsed, { error: "usage" });
  });

  it("parseDesktopArgs accepts --inventory", () => {
    const parsed = parseDesktopArgs(["desktop", "--state", "s", "--inventory", "roster.json"]);
    assert.ok(!("error" in parsed));
    if (!("error" in parsed)) {
      assert.equal(parsed.stateDir, resolve("s"));
      assert.equal(parsed.inventoryFile, resolve("roster.json"));
    }
  });

  it("parseDesktopArgs resolves a relative state directory", () => {
    const parsed = parseDesktopArgs(["desktop", "--state", "st"]);
    assert.ok(!("error" in parsed));
    if (!("error" in parsed)) assert.equal(parsed.stateDir, resolve("st"));
  });
});

describe("verax desktop passkey hint", () => {
  it("prints one line when the state has no enrolled operator", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-desktop-passkey-"));
    const line = desktopPasskeyHint(dir);
    assert.equal(
      line,
      "the panel reads the ledger after a passkey sign-in; run verax operator enroll\n",
    );
    assert.equal(line?.split("\n").filter((part) => part !== "").length, 1);
  });

  it("prints nothing when an operator is enrolled", () => {
    // Presence of operator-credentials.json is the enrollment. The file is
    // not parsed here: a truncated file still counts as an operator.
    const dir = mkdtempSync(join(tmpdir(), "verax-desktop-passkey-"));
    writeFileSync(join(dir, CREDENTIALS_FILE), "{}\n");
    assert.equal(desktopPasskeyHint(dir), null);
  });
});

describe("verax desktop wiring", () => {
  it("tells the issuer which port this run put the panel on", () => {
    const env = issuerEnv(
      {},
      { stateDir: "/tmp/state", issuerPort: 8791, panelPort: 5200 },
      "http://localhost:8787",
      "http://localhost:8791",
    );
    // Without this the panel's own origin is not on the allow-list and the code
    // flow stops at `invalid_request` on any port but the default.
    // The browser origin is localhost: an IP address cannot be a WebAuthn RP ID.
    assert.equal(env.VERAX_DEV_REDIRECT_URIS, "http://localhost:5200/");
    assert.equal(env.VERAX_DEV_ISSUER_PORT, "8791");
    assert.equal(env.VERAX_RP_ID, "localhost");
    assert.equal(env.VERAX_RP_ORIGINS, "http://localhost:8791");
    assert.equal(env.VERAX_AUDIENCE, "http://localhost:8787");
    assert.equal(env.VERAX_ISSUER, "http://localhost:8791");
    const kept = issuerEnv(
      { VERAX_RP_ID: "login.example", VERAX_RP_ORIGINS: "https://login.example" },
      { stateDir: "/tmp/state", issuerPort: 8791, panelPort: 5200 },
      "http://localhost:8787",
      "http://localhost:8791",
    );
    assert.equal(kept.VERAX_RP_ID, "login.example");
    assert.equal(kept.VERAX_RP_ORIGINS, "https://login.example");
    assert.equal(kept.VERAX_DEV_REDIRECT_URIS, "http://localhost:5200/");
  });

  it("names the panel origin on the body, where the approval ceremony runs", () => {
    const env = bodyRpEnv({}, "http://localhost:5200");
    assert.equal(env.VERAX_RP_ID, "localhost");
    assert.equal(env.VERAX_RP_ORIGINS, "http://localhost:5200");
    const kept = bodyRpEnv(
      { VERAX_RP_ID: "login.example", VERAX_RP_ORIGINS: "https://panel.example" },
      "http://localhost:5200",
    );
    assert.equal(kept.VERAX_RP_ID, "login.example");
    assert.equal(kept.VERAX_RP_ORIGINS, "https://panel.example");
  });
});

function jwksState(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-desktop-jwks-"));
  mkdirSync(join(dir, "dev-issuer"));
  return dir;
}

const PUBLIC_JWKS = { keys: [{ kty: "EC", kid: "verax-dev", alg: "ES256" }] };

describe("verax desktop jwks pin", () => {
  it("refuses a jwks pin that contains a private field", () => {
    const dir = jwksState();
    try {
      writeFileSync(
        join(dir, "dev-issuer", "jwks.json"),
        `${JSON.stringify({ keys: [{ kty: "EC", kid: "verax-dev", d: "secret" }] })}\n`,
      );
      assert.throws(() => readIssuerJwksPin(dir), { message: "desktop-jwks-pin-failed" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a jwks pin that is a symbolic link", (t) => {
    const dir = jwksState();
    try {
      const target = join(dir, "elsewhere.json");
      const pin = join(dir, "dev-issuer", "jwks.json");
      writeFileSync(target, `${JSON.stringify(PUBLIC_JWKS)}\n`);
      try {
        symlinkSync(target, pin);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (process.platform === "win32" && (code === "EPERM" || code === "EACCES")) {
          t.skip("no symbolic-link privilege on this Windows account");
          return;
        }
        throw error;
      }
      assert.throws(() => readIssuerJwksPin(dir), { message: "desktop-jwks-pin-failed" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns the public key set from a regular pin file", () => {
    const dir = jwksState();
    try {
      writeFileSync(join(dir, "dev-issuer", "jwks.json"), `${JSON.stringify(PUBLIC_JWKS)}\n`);
      assert.equal(readIssuerJwksPin(dir), JSON.stringify(PUBLIC_JWKS));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("verax desktop child environment", () => {
  it("drops bootstrap variables and keeps PATH", () => {
    assert.deepEqual(
      desktopChildEnv({
        NODE_OPTIONS: "--require x",
        node_path: "y",
        PATH: "p",
        VERAX_DEV_TOKEN: "t",
      }),
      { PATH: "p", NO_COLOR: "1", FORCE_COLOR: "0" },
    );
    const dropped = [
      "NODE_REPL_EXTERNAL_MODULE",
      "LD_PRELOAD",
      "LD_LIBRARY_PATH",
      "LD_AUDIT",
      "DYLD_INSERT_LIBRARIES",
      "DYLD_LIBRARY_PATH",
      "ld_preload",
    ];
    const env = desktopChildEnv({
      PATH: "p",
      VERAX_AUDIENCE: "a",
      ...Object.fromEntries(dropped.map((key) => [key, "x"])),
    });
    assert.equal(env.PATH, "p");
    assert.equal(env.VERAX_AUDIENCE, "a");
    assert.equal(env.NO_COLOR, "1");
    assert.equal(env.FORCE_COLOR, "0");
    for (const key of dropped) assert.equal(env[key], undefined);
  });
});

describe("verax desktop code paths", () => {
  it("refuses a group-and-other-writable code file", (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX mode bits");
      return;
    }
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-code-")));
    const file = join(dir, "dev-issuer.mjs");
    writeFileSync(file, "");
    chmodSync(file, 0o666);
    try {
      const refused = desktopCodeRefusal([file], process.platform);
      assert.equal(refused?.path, file);
      assert.match(refused?.detail ?? "", /owner uid \d+; mode 666/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a parent directory others can write and keeps a sticky ancestor", (t) => {
    if (process.platform === "win32") {
      t.skip("POSIX mode bits");
      return;
    }
    const base = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-code-")));
    const sticky = join(base, "sticky");
    const parent = join(sticky, "parent");
    mkdirSync(parent, { recursive: true });
    const file = join(parent, "dev-issuer.mjs");
    writeFileSync(file, "");
    chmodSync(file, 0o644);
    chmodSync(parent, 0o755);
    chmodSync(sticky, 0o1777);
    try {
      assert.equal(desktopCodeRefusal([file], process.platform), null);
      chmodSync(parent, 0o777);
      const refused = desktopCodeRefusal([file], process.platform);
      assert.equal(refused?.path, parent);
      assert.match(refused?.detail ?? "", /owner uid \d+; mode 777/);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("refuses code Everyone can write and accepts owner, SYSTEM, and Administrators", (t) => {
    if (process.platform !== "win32") {
      t.skip("Windows ACL");
      return;
    }
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-code-")));
    const file = join(dir, "vite.js");
    writeFileSync(file, "");
    const owner = "S-1-5-21-1";
    const safe = `O:${owner}G:SYD:(A;;FA;;;${owner})(A;;FA;;;BA)(A;;FA;;;SY)`;
    const same = (p: string, q: string) => p.toLowerCase() === q.toLowerCase();
    try {
      let reads = 0;
      let asked: readonly string[] = [];
      const everyone = desktopCodeRefusal(
        [file],
        "win32",
        (paths) => {
          reads += 1;
          asked = paths;
          return new Map(paths.map((p) => [p, { sddl: "D:(A;;FA;;;WD)" }]));
        },
        owner,
      );
      assert.equal(reads, 1);
      assert.ok(asked.some((p) => same(p, file)));
      assert.ok(asked.some((p) => same(p, dir)));
      assert.ok(asked.some((p) => same(p, dirname(dir))));
      assert.equal(everyone?.path.toLowerCase(), file.toLowerCase());
      assert.match(everyone?.detail ?? "", /S-1-1-0|WD/);
      const accepted = desktopCodeRefusal(
        [file],
        "win32",
        (paths) => new Map(paths.map((p) => [p, { sddl: safe }])),
        owner,
      );
      assert.equal(accepted, null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses file-add by Users on the parent and ignores the same right on an ancestor", (t) => {
    if (process.platform !== "win32") {
      t.skip("Windows ACL");
      return;
    }
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-code-")));
    const file = join(dir, "vite.js");
    writeFileSync(file, "");
    const owner = "S-1-5-21-1";
    const safe = `O:${owner}G:SYD:(A;;FA;;;${owner})(A;;FA;;;BA)(A;;FA;;;SY)`;
    const bu = `O:${owner}G:SYD:(A;;FA;;;${owner})(A;;0x2;;;S-1-5-32-545)(A;;FA;;;BA)(A;;FA;;;SY)`;
    const same = (p: string, q: string) => p.toLowerCase() === q.toLowerCase();
    const withLoose = (loose: string | null) => (asked: readonly string[]) =>
      new Map(asked.map((p) => [p, { sddl: loose !== null && same(p, loose) ? bu : safe }]));
    try {
      assert.equal(desktopCodeRefusal([file], "win32", withLoose(null), owner), null);
      let reads = 0;
      const parent = desktopCodeRefusal(
        [file],
        "win32",
        (asked) => {
          reads += 1;
          return withLoose(dir)(asked);
        },
        owner,
      );
      assert.equal(reads, 1);
      assert.equal(parent?.path.toLowerCase(), dir.toLowerCase());
      assert.match(parent?.detail ?? "", /S-1-5-32-545/);
      assert.equal(desktopCodeRefusal([file], "win32", withLoose(dirname(dir)), owner), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("treats an existing node_modules on the walk as an object", (t) => {
    if (process.platform !== "win32") {
      t.skip("Windows ACL");
      return;
    }
    const root = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-code-")));
    const modules = join(root, "node_modules");
    const pkg = join(modules, "pkg");
    mkdirSync(pkg, { recursive: true });
    const file = join(pkg, "vite.js");
    writeFileSync(file, "");
    const owner = "S-1-5-21-1";
    const safe = `O:${owner}G:SYD:(A;;FA;;;${owner})(A;;FA;;;BA)(A;;FA;;;SY)`;
    const bu = `O:${owner}G:SYD:(A;;FA;;;${owner})(A;;0x2;;;S-1-5-32-545)(A;;FA;;;BA)(A;;FA;;;SY)`;
    const same = (p: string, q: string) => p.toLowerCase() === q.toLowerCase();
    try {
      const refused = desktopCodeRefusal(
        [file],
        "win32",
        (asked) => new Map(asked.map((p) => [p, { sddl: same(p, modules) ? bu : safe }])),
        owner,
      );
      assert.equal(refused?.path.toLowerCase(), modules.toLowerCase());
      assert.match(refused?.detail ?? "", /S-1-5-32-545/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("prints a fix line when launched code is writable by someone else", async () => {
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-fix-")));
    if (process.platform !== "win32") chmodSync(dir, 0o700);
    const issuerPort = await freePort();
    const bodyPort = await freePort();
    const panelPort = await freePort();
    const sid = "S-1-5-21-1";
    const err: string[] = [];
    let spawned = false;
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          platform: "win32",
          readyMs: 200,
          restrictOwner: () => {},
          windowsDirectoryOwner: () => ({ ownerSid: sid, invokingSid: sid }),
          windowsDirectoryDacl: () => `O:${sid}D:(A;;FA;;;${sid})`,
          windowsCodeAcl: (asked) => new Map([...asked].map((p) => [p, { sddl: "D:(A;;FA;;;WD)" }])),
          spawn: () => {
            spawned = true;
            throw new Error("spawned after a code refusal");
          },
        },
      );
      assert.equal(spawned, false);
      assert.equal(code, 1);
      const block = err.find((line) => line.startsWith("desktop-code-writable:"));
      const rows = block?.split("\n") ?? [];
      assert.match(rows[0] ?? "", /^desktop-code-writable:/);
      assert.match(rows[2] ?? "", /^fix:/);
      assert.match(rows[2] ?? "", /icacls/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Child the readiness wait can pass. It binds `port` and writes `readyLine`
 * once that bind has succeeded. `kill` only marks the child exited; the
 * caller closes every server it pushed onto `listeners`.
 */
function listeningChild(port: number, readyLine: string, listeners: Server[]): SpawnedChild {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const server = createHttpServer((_req, res) => {
    res.writeHead(204);
    res.end();
  });
  server.unref();
  listeners.push(server);
  const pid = 2_100_000 + listeners.length;
  let exitCode: number | null = null;
  const emitter = new EventEmitter();
  const child = Object.assign(emitter, {
    pid,
    signalCode: null as NodeJS.Signals | null,
    stdout,
    stderr,
    stdin: null,
    kill() {
      if (exitCode !== null) return true;
      exitCode = 0;
      emitter.emit("exit", 0, null);
      return true;
    },
  }) as unknown as SpawnedChild;
  // `Object.assign` would copy a getter as the value it returns once.
  Object.defineProperty(emitter, "exitCode", {
    enumerable: true,
    get() {
      return exitCode;
    },
  });
  server.once("error", () => {
    if (exitCode !== null) return;
    exitCode = 1;
    emitter.emit("exit", 1, null);
  });
  server.listen(port, "127.0.0.1", () => {
    stdout.write(`${readyLine}\n`);
  });
  return child;
}

function closeListeners(servers: readonly Server[]): Promise<void> {
  return Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolve) => {
          const finish = () => resolve();
          server.once("close", finish);
          try {
            server.close();
          } catch {
            finish();
            return;
          }
          if (!server.listening) finish();
        }),
    ),
  ).then(() => undefined);
}

/** Token and JWKS pin the desktop reads after the issuer prints its ready line. */
function writeIssuerDesk(dir: string): void {
  const pinDir = join(dir, "dev-issuer");
  mkdirSync(pinDir, { recursive: true });
  if (process.platform !== "win32") chmodSync(pinDir, 0o700);
  writeFileSync(issuerJwksPinPath(dir), `${JSON.stringify(PUBLIC_JWKS)}\n`, { mode: 0o600 });
  writeFileSync(join(dir, "dev-token"), "fresh-token\n", { mode: 0o600 });
}

describe("verax desktop body launch", () => {
  it("passes the panel RP into the body process it launches", async () => {
    // `bodyRpEnv` by itself stays green when launch stops spreading it.
    // This reads the environment the body spawn actually receives.
    // An operator value would be kept; this run sets neither, so the
    // launch site has to supply localhost and the panel origin.
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "verax-desktop-body-rp-")));
    if (process.platform !== "win32") chmodSync(dir, 0o700);
    const listeners: Server[] = [];
    const children = new Map<number, SpawnedChild>();
    const savedRpId = process.env.VERAX_RP_ID;
    const savedOrigins = process.env.VERAX_RP_ORIGINS;
    delete process.env.VERAX_RP_ID;
    delete process.env.VERAX_RP_ORIGINS;
    const err: string[] = [];
    let bodyEnv: NodeJS.ProcessEnv | undefined;
    const sid = "S-1-5-21-1";
    try {
      const [issuerPort, bodyPort, panelPort] = await Promise.all([freePort(), freePort(), freePort()]);
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 1_000,
          restrictOwner: () => {},
          ...(process.platform === "win32"
            ? {
                windowsDirectoryOwner: () => ({ ownerSid: sid, invokingSid: sid }),
                windowsDirectoryDacl: () => `O:${sid}D:(A;;FA;;;${sid})`,
              }
            : {}),
          kill: (pid) => {
            if (pid === undefined) return;
            children.get(pid)?.kill();
          },
          spawn: (name, _cmd, _args, env) => {
            if (name === "body") bodyEnv = { ...env };
            if (name === "panel" || name === "browser") throw new Error("stop-before-panel");
            const port = name === "issuer" ? issuerPort : bodyPort;
            const line = name === "issuer" ? issuerReadyLine(issuerPort) : bodyReadyLine(bodyPort);
            if (name === "issuer") writeIssuerDesk(dir);
            const child = listeningChild(port, line, listeners);
            if (child.pid !== undefined) children.set(child.pid, child);
            return child;
          },
        },
      );
      const text = err.join("");
      assert.equal(code, 1, text);
      assert.match(text, /desktop-failed:stop-before-panel/);
      assert.equal(bodyEnv?.VERAX_RP_ID, "localhost");
      assert.equal(bodyEnv?.VERAX_RP_ORIGINS, `http://localhost:${panelPort}`);
    } finally {
      for (const child of children.values()) child.kill();
      await closeListeners(listeners);
      if (savedRpId === undefined) delete process.env.VERAX_RP_ID;
      else process.env.VERAX_RP_ID = savedRpId;
      if (savedOrigins === undefined) delete process.env.VERAX_RP_ORIGINS;
      else process.env.VERAX_RP_ORIGINS = savedOrigins;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
