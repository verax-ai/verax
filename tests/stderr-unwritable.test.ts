import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const main = join(root, "packages", "body", "src", "main.ts");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

/** The port the body recorded in its ledger lock, or null while there is none. */
function recordedPort(stateDir: string): number | null {
  for (const entry of readdirSync(stateDir, { recursive: true, encoding: "utf8" })) {
    if (!entry.endsWith("ledger.lock")) continue;
    try {
      const row = JSON.parse(readFileSync(join(stateDir, entry), "utf8")) as { port?: unknown };
      if (typeof row.port === "number") return row.port;
    } catch {
      // Mid-write; the next look reads it whole.
    }
  }
  return null;
}

describe("a stderr that cannot be written", () => {
  it("does not stop the body: the line is lost and /healthz still answers", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-stderr-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const errFile = join(stateDir, "stderr.log");
    writeFileSync(errFile, "");
    // Opened for reading, so every write to it fails: what a log file does
    // once its disk has gone read-only.
    const fd = openSync(errFile, "r");
    const child = spawn(process.execPath, ["--experimental-strip-types", main], {
      cwd: root,
      env: {
        ...process.env,
        VERAX_ISSUER: issuer.issuer,
        VERAX_JWKS_URL: issuer.jwksUrl,
        VERAX_AUDIENCE: audience,
        VERAX_STATE_DIR: stateDir,
        VERAX_POLICY_FILE: policyFile,
        VERAX_BIND: "127.0.0.1:0",
      },
      stdio: ["ignore", "ignore", fd],
    });
    closeSync(fd);
    let exited: string | null = null;
    child.once("exit", (code, signal) => {
      exited = `exit ${code ?? signal}`;
    });
    try {
      let port: number | null = null;
      for (let i = 0; i < 300 && port === null && exited === null; i += 1) {
        await sleep(100);
        port = recordedPort(stateDir);
      }
      assert.ok(port, `the body never recorded a port (${exited ?? "still starting"})`);
      // main writes "listening ..." once the port is recorded. That write
      // returns and fails afterwards, so the body is given time to fall.
      await sleep(1000);
      assert.equal(exited, null, "the body stopped on a stderr it could not write");
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(res.status, 200);
      assert.equal(readFileSync(errFile, "utf8"), "", "the line was not supposed to arrive");
    } finally {
      // The body holds its ledger lock until it is gone; the directory goes after it.
      if (child.exitCode === null && child.signalCode === null) {
        const gone = new Promise<void>((resolve) => child.once("exit", () => resolve()));
        child.kill();
        await gone;
      }
      await issuer.close();
      rmSync(stateDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });
});
