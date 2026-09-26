// R13: each `it` asserts the safe behaviour. On d50bcc5 the implementation
// does the unsafe thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createServer as createNetServer, type Server as NetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  bodyReadyLine,
  issuerJwksPinPath,
  issuerReadyLine,
  panelReadyLine,
  runDesktop,
  type DesktopSpawnName,
} from "../packages/body/src/desktop.ts";
import { EX_CONFIG } from "../packages/body/src/config.ts";
import { readInstallHealthNonce } from "../packages/body/src/health-extras.ts";
import {
  codeDirFor,
  healthzProvesService,
  planInstall,
  runInstall,
  serviceHealthIsNonce,
  stateDirFor,
  windowsSystemRoot,
} from "../packages/body/src/install.ts";

const root = dirname(fileURLToPath(import.meta.url));
const repo = join(root, "..");

function ownerDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function nodeEval(code: string): ChildProcess {
  return spawn(process.execPath, ["-e", code], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
}

function hold(line: string): ChildProcess {
  return nodeEval(`process.stderr.write(${JSON.stringify(`${line}\n`)}); setInterval(() => {}, 1e9);`);
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
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

function listen(server: Server | NetServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("listen"));
        return;
      }
      resolve(addr.port);
    });
  });
}

function close(server: Server | NetServer): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

const winLayout = {
  execPath: "C:\\Program Files\\nodejs\\node.exe",
  bodyVersion: "0.3.0",
  npmCli: "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
};

const adminSddl = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)\n";
const userSddl = "O:BAG:SYD:PAI(A;;FA;;;BU)\n";

describe("attack R13", () => {
  it("R13-1 refuses a taken port, waits on the child, pins the JWKS file, drops a stale token, and notices an early exit", async () => {
    const issuerSrc = readFileSync(join(repo, "scripts", "dev-issuer.mjs"), "utf8");
    assert.match(issuerSrc, /unlinkSync\(jwksPinPath\)/);
    assert.match(issuerSrc, /join\(dir, "jwks\.json"\)/);
    assert.match(issuerSrc, /mode: 0o600/);
    const desktopSrc = readFileSync(join(repo, "packages", "body", "src", "desktop.ts"), "utf8");
    assert.equal(desktopSrc.includes("fetchIssuerJwks"), false);

    const taken = createNetServer();
    const takenPort = await listen(taken);
    const busyDir = ownerDir("verax-r13-busy-");
    const busyErr: string[] = [];
    let spawned = 0;
    try {
      const [bodyPort, panelPort] = await Promise.all([freePort(), freePort()]);
      const code = await runDesktop(
        { stateDir: busyDir, issuerPort: takenPort, bodyPort, panelPort },
        (line) => busyErr.push(line),
        {
          readyMs: 300,
          spawn: () => {
            spawned += 1;
            return hold("should-not-run");
          },
        },
      );
      assert.equal(code, 1);
      assert.match(busyErr.join(""), new RegExp(`desktop-port-busy:issuer:${takenPort}`));
      assert.equal(spawned, 0);
    } finally {
      await close(taken);
      rmSync(busyDir, { recursive: true, force: true });
    }

    const earlyDir = ownerDir("verax-r13-early-");
    const earlyErr: string[] = [];
    let bodies = 0;
    try {
      const [issuerPort, bodyPort, panelPort] = await Promise.all([freePort(), freePort(), freePort()]);
      const code = await runDesktop(
        { stateDir: earlyDir, issuerPort, bodyPort, panelPort },
        (line) => earlyErr.push(line),
        {
          readyMs: 1_000,
          spawn: (name: DesktopSpawnName) => {
            if (name === "body") bodies += 1;
            if (name === "issuer") return nodeEval("process.exit(1)");
            return hold("idle");
          },
        },
      );
      assert.equal(code, 1);
      assert.match(earlyErr.join(""), /desktop-child-exited:issuer/);
      assert.equal(bodies, 0);
    } finally {
      rmSync(earlyDir, { recursive: true, force: true });
    }

    const squatDir = ownerDir("verax-r13-squat-");
    const squatErr: string[] = [];
    let squatBodies = 0;
    const squatPort = await freePort();
    try {
      const [bodyPort, panelPort] = await Promise.all([freePort(), freePort()]);
      const code = await runDesktop(
        { stateDir: squatDir, issuerPort: squatPort, bodyPort, panelPort },
        (line) => squatErr.push(line),
        {
          readyMs: 400,
          spawn: (name: DesktopSpawnName) => {
            if (name === "body") squatBodies += 1;
            if (name === "issuer") {
              return nodeEval(
                `const net = require("node:net"); const s = net.createServer(); s.listen(${squatPort}, "127.0.0.1"); setInterval(() => {}, 1e9);`,
              );
            }
            return hold("idle");
          },
        },
      );
      assert.equal(code, 1, squatErr.join(""));
      assert.match(squatErr.join(""), /desktop-issuer-timeout/);
      assert.equal(squatErr.join("").includes("desktop-ready"), false);
      assert.equal(squatBodies, 0);
    } finally {
      rmSync(squatDir, { recursive: true, force: true });
    }

    const stateDir = ownerDir("verax-r13-pin-");
    const tokenPath = join(stateDir, "dev-token");
    writeFileSync(tokenPath, "stale-token\n", { mode: 0o600 });
    const issuerPort = await freePort();
    const bodyPort = await freePort();
    const panelPort = await freePort();
    const jwks = JSON.stringify({ keys: [{ kty: "EC", kid: "verax-dev", alg: "ES256" }] });
    let tokenPresentAtSpawn: boolean | null = null;
    let pin = "";
    let decoy: Server | undefined;
    const pinErr: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => pinErr.push(line),
        {
          readyMs: 2_000,
          spawn: (name, _cmd, _args, env) => {
            if (name === "issuer") {
              tokenPresentAtSpawn = existsSync(tokenPath);
              const dir = join(stateDir, "dev-issuer");
              mkdirSync(dir, { recursive: true });
              if (process.platform !== "win32") chmodSync(dir, 0o700);
              writeFileSync(issuerJwksPinPath(stateDir), `${jwks}\n`, { mode: 0o600 });
              if (process.platform !== "win32") chmodSync(issuerJwksPinPath(stateDir), 0o600);
              writeFileSync(tokenPath, "fresh-token\n", { mode: 0o600 });
              decoy = createServer((_req, res) => {
                res.end(JSON.stringify({ keys: [{ kty: "EC", kid: "attacker" }] }));
              });
              decoy.listen(issuerPort, "127.0.0.1");
              return hold(issuerReadyLine(issuerPort));
            }
            if (name === "body") {
              pin = env.VERAX_JWKS_PIN ?? "";
              return hold(bodyReadyLine(bodyPort));
            }
            if (name === "panel") return hold(`  Local:   ${panelReadyLine(panelPort)}/`);
            return nodeEval("process.exit(0)");
          },
        },
      );
      assert.equal(tokenPresentAtSpawn, false);
      assert.equal(existsSync(tokenPath), true);
      assert.equal(readFileSync(tokenPath, "utf8").trim(), "fresh-token");
      assert.equal(pin.includes("verax-dev"), true, pin);
      assert.equal(pin.includes("attacker"), false, pin);
      assert.match(pinErr.join(""), /desktop-browser-exited-early/, pinErr.join(""));
    } finally {
      if (decoy) await close(decoy);
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("R13-2 refuses a SystemRoot that points elsewhere or contains .. without running a tool, and trust-checks System32", async () => {
    let calls = 0;
    const counting = () => {
      calls += 1;
      return { status: 0, stdout: "", stderr: "" };
    };
    assert.throws(() => windowsSystemRoot({ SystemRoot: "C:\\Users\\x\\fake" }, counting), /is not C:\\Windows/);
    // A data drive can hold a user-made \Windows\System32, and the trust check runs PowerShell from there.
    assert.throws(() => windowsSystemRoot({ SystemRoot: "D:\\Windows" }, counting), /is not C:\\Windows/);
    assert.throws(() => windowsSystemRoot({ SystemRoot: "C:\\Windows\\..\\Users\\x" }, counting), /contains \.\./);
    assert.equal(calls, 0);

    const seen: string[] = [];
    assert.throws(
      () =>
        windowsSystemRoot({ SystemRoot: "C:\\Windows" }, (argv) => {
          seen.push(argv.join(" "));
          return { status: 0, stdout: userSddl, stderr: "" };
        }),
      /System32/,
    );
    assert.ok(seen.some((line) => line.includes("System32")), seen.join("\n"));

    const trusted = windowsSystemRoot({ SystemRoot: "C:\\Windows" }, () => ({
      status: 0,
      stdout: adminSddl,
      stderr: "",
    }));
    assert.equal(trusted, "C:\\Windows");

    assert.throws(() => stateDirFor("win32", { ProgramData: "C:\\ProgramData\\..\\Users\\x" }), /contains \.\./);
    assert.throws(() => codeDirFor("win32", { ProgramFiles: "C:\\Program Files\\..\\Users\\x" }), /contains \.\./);

    const installPort = await freePort();
    const err: string[] = [];
    let sawFake = false;
    const code = await runInstall(["install", "--port", String(installPort)], {
      platform: "win32",
      env: {
        ProgramFiles: "C:\\Program Files",
        ProgramData: "C:\\Users\\x\\fake",
        USERPROFILE: "C:\\Users\\operator",
        USERNAME: "operator",
      },
      elevated: () => true,
      layout: winLayout,
      exec: (argv, stdin) => {
        if (stdin && stdin.startsWith("[")) {
          const paths = JSON.parse(stdin) as string[];
          const out: Record<string, string> = {};
          for (const file of paths) {
            if (file.toLowerCase().includes("\\users\\x\\fake")) {
              sawFake = true;
              out[file] = userSddl.trim();
            } else out[file] = adminSddl.trim();
          }
          return { status: 0, stdout: JSON.stringify(out), stderr: "" };
        }
        return { status: 0, stdout: "S-1-5-21-1\n", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: (line) => err.push(line) } },
    });
    assert.notEqual(code, 0, err.join(""));
    assert.equal(sawFake, true);
    assert.match(err.join(""), /Users\\x\\fake/);

    const badPort = await freePort();
    let ran = 0;
    const bad = await runInstall(["install", "--port", String(badPort)], {
      platform: "win32",
      env: {
        SystemRoot: "C:\\Users\\x\\fake",
        ProgramFiles: "C:\\Program Files",
        ProgramData: "C:\\ProgramData",
        USERPROFILE: "C:\\Users\\operator",
      },
      elevated: () => true,
      layout: winLayout,
      exec: () => {
        ran += 1;
        return { status: 0, stdout: "", stderr: "" };
      },
      io: { stdout: { write: () => undefined }, stderr: { write: () => undefined } },
    });
    assert.notEqual(bad, 0);
    assert.equal(ran, 0);
  });

  it("R13-3 refuses a busy install port and does not treat a foreign /healthz as the service", async () => {
    const nonce = "ab".repeat(32);
    assert.equal(healthzProvesService('{"ok":true}', nonce), false);
    assert.equal(healthzProvesService(JSON.stringify({ ok: true, nonce }), nonce), true);
    const nonceDir = ownerDir("verax-r13-nonce-");
    try {
      writeFileSync(join(nonceDir, "install-health-nonce"), `${nonce}\n`, { mode: 0o600 });
      assert.equal(readInstallHealthNonce(nonceDir), nonce);
    } finally {
      rmSync(nonceDir, { recursive: true, force: true });
    }

    const foreign = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
    });
    const foreignPort = await listen(foreign);
    try {
      assert.equal(await serviceHealthIsNonce(foreignPort, nonce, 400), false);
    } finally {
      await close(foreign);
    }

    const matched = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, nonce }));
    });
    const matchedPort = await listen(matched);
    try {
      assert.equal(await serviceHealthIsNonce(matchedPort, nonce, 1_000), true);
    } finally {
      await close(matched);
    }

    const held = createNetServer();
    const busyPort = await listen(held);
    const err: string[] = [];
    let ran = 0;
    try {
      const code = await runInstall(["install", "--port", String(busyPort)], {
        platform: "win32",
        env: {
          ProgramData: "C:\\ProgramData",
          ProgramFiles: "C:\\Program Files",
          USERPROFILE: "C:\\Users\\operator",
        },
        elevated: () => true,
        layout: winLayout,
        exec: () => {
          ran += 1;
          return { status: 0, stdout: "", stderr: "" };
        },
        io: { stdout: { write: () => undefined }, stderr: { write: (line) => err.push(line) } },
      });
      assert.equal(code, EX_CONFIG);
      assert.match(err.join(""), new RegExp(`port-busy:${busyPort}`));
      assert.equal(ran, 0);
    } finally {
      await close(held);
    }

    const plan = planInstall(
      "win32",
      { ProgramData: "C:\\ProgramData", ProgramFiles: "C:\\Program Files", USERPROFILE: "C:\\Users\\operator" },
      { ...winLayout, port: 8801, days: 30, force: false, stateExists: false },
    );
    assert.equal(plan.ok, true, plan.ok ? "" : plan.message);
    if (!plan.ok) return;
    const wait = plan.ops.find((op) => op.op === "wait-healthz");
    assert.ok(wait && wait.op === "wait-healthz");
    assert.match(wait.nonce, /^[0-9a-f]{64}$/);
    const writeAt = plan.ops.findIndex((op) => op.op === "write" && op.path.endsWith("install-health-nonce"));
    const startAt = plan.ops.findIndex((op) => op.op === "argv" && op.argv.join(" ").includes("Start-ScheduledTask"));
    assert.ok(writeAt >= 0 && startAt > writeAt, `write ${writeAt} start ${startAt}`);
  });
});
