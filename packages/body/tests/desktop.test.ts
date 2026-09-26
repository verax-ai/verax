import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { desktopMode, desktopPasskeyHint, issuerEnv, parseDesktopArgs } from "../src/desktop.ts";
import { CREDENTIALS_FILE } from "../src/operator-credentials.ts";

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

function healthzServer(): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const server: Server = createHttpServer((req, res) => {
      if (req.url === "/healthz") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"ok":true}');
        return;
      }
      res.writeHead(404);
      res.end();
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("healthz-port"));
        return;
      }
      resolve({
        port: addr.port,
        close: () => new Promise<void>((done) => server.close(() => done())),
      });
    });
  });
}

function stateWithLock(pid: number): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-desktop-mode-"));
  writeFileSync(
    join(dir, "ledger.lock"),
    `${JSON.stringify({ pid, startedAt: Date.now(), token: "t" })}\n`,
    "utf8",
  );
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
 * One ledger, one body. The desktop used to build its own issuer and body
 * every time, so on a machine whose body starts at logon the window opened
 * on a second, empty ledger - the panel looked broken while the real
 * decisions sat in another directory. When the lock is held by a live
 * process and that body answers where this run was told to look, the panel
 * joins it instead.
 */
describe("verax desktop joins a running body", () => {
  it("attaches when the lock is live and /healthz answers on the body port", async () => {
    const body = await healthzServer();
    try {
      const dir = stateWithLock(process.pid);
      assert.deepEqual(await desktopMode(dir, body.port), { mode: "attach", pid: process.pid });
    } finally {
      await body.close();
    }
  });

  it("refuses when the lock is live but nothing answers on the body port", async () => {
    const dir = stateWithLock(process.pid);
    const port = await freePort();
    assert.deepEqual(await desktopMode(dir, port), { error: "desktop-body-locked", pid: process.pid });
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
    if (!("error" in parsed)) assert.equal(parsed.inventoryFile, "roster.json");
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
      "http://127.0.0.1:8787",
      "http://127.0.0.1:8791",
    );
    // Without this the panel's own origin is not on the allow-list and the code
    // flow stops at `invalid_request` on any port but the default.
    assert.equal(env.VERAX_DEV_REDIRECT_URIS, "http://127.0.0.1:5200/");
    assert.equal(env.VERAX_DEV_ISSUER_PORT, "8791");
  });
});
