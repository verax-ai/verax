import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { desktopMode, desktopPasskeyHint, forwardIpv6Loopback, issuerEnv, parseDesktopArgs, runDesktop } from "../src/desktop.ts";
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
});
