import { strict as assert } from "node:assert";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { desktopCloneError, portOpen } from "../packages/body/src/desktop.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "..", "packages", "body", "src", "cli.ts");
const fakeBrowser = join(here, "..", "packages", "body", "tests", "fixtures", "fake-browser.mjs");
const fakeBrowserExit = join(here, "..", "packages", "body", "tests", "fixtures", "fake-browser-exit.mjs");
const policyFile = join(here, "..", "packages", "proxy", "policy", "default.json");

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
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

async function waitUntil(pred: () => Promise<boolean>, ms: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (await pred()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

function killTree(pid: number): void {
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/T", "/PID", String(pid), "/F"], { windowsHide: true, stdio: "ignore" });
    return;
  }
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // gone
    }
  }
}

function commandLines(): string {
  if (process.platform === "win32") {
    const r = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Process | ForEach-Object { $_.CommandLine }",
      ],
      { encoding: "utf8", windowsHide: true, maxBuffer: 20 * 1024 * 1024 },
    );
    return `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
  }
  return "";
}

describe("verax desktop CLI", () => {
  it("names a directory that is not a clone and accepts this repository", () => {
    const outside = mkdtempSync(join(tmpdir(), "verax-not-a-clone-"));
    try {
      assert.equal(
        desktopCloneError(outside),
        "verax desktop runs from a clone of github.com/verax-ai/verax; it is not in the npm package\n",
      );
      assert.equal(desktopCloneError(join(here, "..")), null);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it(
    "starts issuer, body and panel, then tears them down when the fake browser exits",
    { timeout: 180_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-desktop-"));
      const pidPath = join(stateDir, "fake-browser.pid");
      const [issuerPort, bodyPort, panelPort] = await Promise.all([
        freePort(),
        freePort(),
        freePort(),
      ]);
      const sink = { text: "" };
      let child: ChildProcess | undefined;
      try {
        child = spawn(
          process.execPath,
          [
            "--experimental-strip-types",
            cli,
            "desktop",
            "--state",
            stateDir,
            "--port",
            String(panelPort),
            "--issuer-port",
            String(issuerPort),
            "--body-port",
            String(bodyPort),
            "--browser",
            fakeBrowser,
          ],
          {
            env: {
              ...process.env,
              NO_COLOR: "1",
              FORCE_COLOR: "0",
              VERAX_FAKE_BROWSER_PID: pidPath,
            },
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
          },
        );
        const feed = (c: Buffer | string) => {
          sink.text += String(c);
        };
        child.stdout?.on("data", feed);
        child.stderr?.on("data", feed);

        const up = await waitUntil(async () => {
          const a = await portOpen(issuerPort);
          const b = await portOpen(bodyPort);
          const c = await portOpen(panelPort);
          return a && b && c && existsSync(pidPath);
        }, 150_000);
        assert.equal(up, true, `ports-not-ready\n${sink.text}`);

        const token = readFileSync(join(stateDir, "dev-token"), "utf8").trim();
        assert.ok(token.startsWith("eyJ"), "token-shape");
        assert.equal(sink.text.includes(token), false, "token-in-stdout");
        const argv = child.spawnargs.join(" ");
        assert.equal(argv.includes(token), false, "token-in-parent-argv");
        const lines = commandLines();
        if (lines !== "") {
          assert.equal(lines.includes(token), false, "token-in-process-argv");
        }

        const fakePid = Number(readFileSync(pidPath, "utf8").trim());
        assert.ok(Number.isInteger(fakePid) && fakePid > 0, "fake-pid");
        killTree(fakePid);

        const t0 = Date.now();
        const empty = await waitUntil(async () => {
          const a = await portOpen(issuerPort);
          const b = await portOpen(bodyPort);
          const c = await portOpen(panelPort);
          return !a && !b && !c;
        }, 30_000);
        const emptiedMs = Date.now() - t0;
        // The claim is that the CLI lets its ports go when the browser exits.
        // How long that takes is a fact about the machine: across 23 green
        // runs on 11 Sep 2026 it was 677-3047 ms, and twice the same tree
        // ran past the five-second deadline that used to be asserted here
        // while 101 test files competed for the disk. The number is still
        // printed, so a real slowdown is visible to a reader; the build no
        // longer turns red on the runner's mood.
        assert.equal(empty, true, `ports-still-open after ${emptiedMs}ms\n${sink.text}`);
        process.stdout.write(`desktop-teardown-ms=${emptiedMs}\n`);
      } finally {
        if (child?.pid) killTree(child.pid);
        rmSync(stateDir, { recursive: true, force: true });
      }
    },
  );

  it(
    "joins a body that already holds the ledger instead of starting a second one",
    { timeout: 180_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-desktop-attach-"));
      const pidPath = join(stateDir, "fake-browser.pid");
      const audience = "http://127.0.0.1/verax-desktop-attach";
      // A body in this process: its Ledger takes <state>/ledger.lock with our pid.
      const issuer = await startDevIssuer(0, audience);
      const server = await listen({
        issuer: issuer.issuer,
        jwksUrl: issuer.jwksUrl,
        audience,
        stateDir,
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile,
        tlsTerminated: false,
      });
      const bodyPort = (server.address() as { port: number }).port;
      const [issuerPort, panelPort] = await Promise.all([freePort(), freePort()]);
      const sink = { text: "" };
      let child: ChildProcess | undefined;
      try {
        assert.equal(existsSync(join(stateDir, "ledger.lock")), true, "lock-not-taken");
        child = spawn(
          process.execPath,
          [
            "--experimental-strip-types",
            cli,
            "desktop",
            "--state",
            stateDir,
            "--port",
            String(panelPort),
            "--issuer-port",
            String(issuerPort),
            "--body-port",
            String(bodyPort),
            "--browser",
            fakeBrowser,
          ],
          {
            env: {
              ...process.env,
              NO_COLOR: "1",
              FORCE_COLOR: "0",
              VERAX_FAKE_BROWSER_PID: pidPath,
            },
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
          },
        );
        const feed = (c: Buffer | string) => {
          sink.text += String(c);
        };
        child.stdout?.on("data", feed);
        child.stderr?.on("data", feed);

        const up = await waitUntil(
          async () => (await portOpen(panelPort)) && existsSync(pidPath) && /desktop-ready/.test(sink.text),
          150_000,
        );
        assert.equal(up, true, `panel-not-ready\n${sink.text}`);
        assert.match(sink.text, /desktop-ready body=\d+ panel=\d+ attached=1 pid=\d+/, sink.text);
        // No second issuer, no second token: the running body's are not ours.
        assert.equal(await portOpen(issuerPort), false, "second-issuer-started");
        assert.equal(existsSync(join(stateDir, "dev-token")), false, "second-token-minted");
        // The panel is served against the body that holds the ledger.
        const health = await fetch(`http://127.0.0.1:${panelPort}/healthz`);
        assert.equal(health.status, 200, `panel-proxy-healthz ${health.status}`);

        const fakePid = Number(readFileSync(pidPath, "utf8").trim());
        assert.ok(Number.isInteger(fakePid) && fakePid > 0, "fake-pid");
        // A window that closes inside the first 3 s is the early-exit case,
        // tested below; this is the ordinary close of a window that stayed up.
        await new Promise((r) => setTimeout(r, 3_500));
        killTree(fakePid);
        const code = await new Promise<number>((resolve) => {
          child!.on("close", (exit) => resolve(exit ?? 1));
        });
        assert.equal(code, 0, `expected-exit-0\n${sink.text}`);
        const panelDown = await waitUntil(async () => !(await portOpen(panelPort)), 30_000);
        assert.equal(panelDown, true, `panel-still-open\n${sink.text}`);
        // Closing the window is not a shutdown of a body this run did not start.
        assert.equal(await portOpen(bodyPort), true, "joined-body-killed-on-close");
      } finally {
        if (child?.pid) killTree(child.pid);
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
        await issuer.close();
        rmSync(stateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
      }
    },
  );

  it(
    "refuses a live lock whose body does not answer on the port it was given",
    { timeout: 60_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-desktop-locked-"));
      const audience = "http://127.0.0.1/verax-desktop-locked";
      const issuer = await startDevIssuer(0, audience);
      const server = await listen({
        issuer: issuer.issuer,
        jwksUrl: issuer.jwksUrl,
        audience,
        stateDir,
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile,
        tlsTerminated: false,
      });
      const [issuerPort, wrongBodyPort, panelPort] = await Promise.all([
        freePort(),
        freePort(),
        freePort(),
      ]);
      const sink = { text: "" };
      let child: ChildProcess | undefined;
      try {
        child = spawn(
          process.execPath,
          [
            "--experimental-strip-types",
            cli,
            "desktop",
            "--state",
            stateDir,
            "--port",
            String(panelPort),
            "--issuer-port",
            String(issuerPort),
            "--body-port",
            String(wrongBodyPort),
            "--browser",
            fakeBrowser,
          ],
          { env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
        );
        const feed = (c: Buffer | string) => {
          sink.text += String(c);
        };
        child.stdout?.on("data", feed);
        child.stderr?.on("data", feed);
        const code = await new Promise<number>((resolve) => {
          child!.on("close", (exit) => resolve(exit ?? 1));
        });
        assert.equal(code, 1, `expected-exit-1\n${sink.text}`);
        assert.match(sink.text, new RegExp(`desktop-body-locked:${process.pid}\\b`), sink.text);
        // Nothing was started over the lock: no issuer, no panel, no token.
        assert.equal(await portOpen(issuerPort), false, "issuer-started-over-lock");
        assert.equal(await portOpen(panelPort), false, "panel-started-over-lock");
        assert.equal(existsSync(join(stateDir, "dev-token")), false, "token-minted-over-lock");
      } finally {
        if (child?.pid) killTree(child.pid);
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
        await issuer.close();
        rmSync(stateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
      }
    },
  );

  it(
    "treats a browser that exits within 3s as desktop-browser-exited-early",
    { timeout: 180_000 },
    async () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-desktop-early-"));
      const [issuerPort, bodyPort, panelPort] = await Promise.all([
        freePort(),
        freePort(),
        freePort(),
      ]);
      const sink = { text: "" };
      let child: ChildProcess | undefined;
      try {
        child = spawn(
          process.execPath,
          [
            "--experimental-strip-types",
            cli,
            "desktop",
            "--state",
            stateDir,
            "--port",
            String(panelPort),
            "--issuer-port",
            String(issuerPort),
            "--body-port",
            String(bodyPort),
            "--browser",
            fakeBrowserExit,
          ],
          {
            env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" },
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
          },
        );
        const feed = (c: Buffer | string) => {
          sink.text += String(c);
        };
        child.stdout?.on("data", feed);
        child.stderr?.on("data", feed);

        const code = await new Promise<number>((resolve) => {
          child!.on("close", (exit) => resolve(exit ?? 1));
        });
        assert.equal(code, 1, `expected-exit-1\n${sink.text}`);
        assert.match(sink.text, /desktop-browser-exited-early/);
        const empty = await waitUntil(async () => {
          const a = await portOpen(issuerPort);
          const b = await portOpen(bodyPort);
          const c = await portOpen(panelPort);
          return !a && !b && !c;
        }, 30_000);
        assert.equal(empty, true, `ports-still-open\n${sink.text}`);
      } finally {
        if (child?.pid) killTree(child.pid);
        rmSync(stateDir, { recursive: true, force: true });
      }
    },
  );
});
