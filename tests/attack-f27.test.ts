// F27: R19-2 and R18-2. Each assertion fails on 0e7eab0 and passes after the fix.
// R15-3 is covered by the desktop spawn capture and operator-passkey hostname rule.

import { strict as assert } from "node:assert";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  bodyReadyLine,
  issuerJwksPinPath,
  issuerReadyLine,
  panelReadyLine,
  runDesktop,
  type DesktopSpawnName,
} from "../packages/body/src/desktop.ts";
import { trustTargets, windowsUserCanWrite } from "../packages/body/src/install.ts";
import { startedWithoutEnd } from "../packages/proxy/src/in-flight-log.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";

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

function hostMatchesRp(origin: string, rpID: string): boolean {
  const host = new URL(origin).hostname;
  return host === rpID || host.endsWith(`.${rpID}`);
}

const GET_POLICY = {
  version: 1,
  default: "deny",
  rules: [{ id: "get", tool: "memory.get", requires: ["verax:read"], text: "read" }],
};

const reader = { brain: "brain-1", scopes: new Set(["verax:read"]) };

/** Stock ACL captured for C:\\Program Files\\nodejs. Add-file is not in it. */
const STOCK_NODEJS =
  "O:SYG:SYD:P(A;OICI;0x1200a9;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

describe("attack F27", () => {
  it("R19-2 a successful tool whose effect row cannot be written is effect-unrecorded, not :threw", async () => {
    const dir = ownerDir("verax-f27-effect-");
    const ledger = new FileLedger(dir);
    let runs = 0;
    let effectAppends = 0;
    const realAppend = ledger.appendEffect.bind(ledger);
    ledger.appendEffect = async (row, witness, hash) => {
      effectAppends += 1;
      if (effectAppends === 1) throw new Error("effect-append-failed");
      return realAppend(row, witness, hash);
    };
    const call = { name: "memory.get", arguments: { id: "a", _ref: "job-1" } };
    try {
      const proxy = createProxy({
        policy: loadPolicy(GET_POLICY),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: () => 1_700_000_000_000,
        nonce: () => "n-1",
        inner: async () => {
          runs += 1;
          return { content: [{ type: "text", text: "paid" }], isError: false };
        },
      });
      const first = await proxy.call(call, reader);
      assert.equal(runs, 1);
      assert.equal(first.isError, true);
      assert.equal(first.content.map((part) => part.text).join(""), "effect-unrecorded:job-1");
      const effects = await ledger.effects();
      assert.equal(
        effects.some((effect) => effect.row.effectClass.endsWith(":threw")),
        false,
        effects.map((effect) => effect.row.effectClass).join(","),
      );
      assert.equal(startedWithoutEnd(dir, "job-1"), true);
    } finally {
      ledger.close();
    }

    const again = new FileLedger(dir);
    let runsAgain = 0;
    try {
      const proxy = createProxy({
        policy: loadPolicy(GET_POLICY),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger: again,
        now: () => 1_700_000_000_000,
        nonce: () => "n-2",
        inner: async () => {
          runsAgain += 1;
          return { content: [{ type: "text", text: "paid" }], isError: false };
        },
      });
      const second = await proxy.call(call, reader);
      assert.equal(runsAgain, 0);
      assert.match(second.content.map((part) => part.text).join(""), /^denied:outcome-unknown:/);
      const effects = await again.effects();
      assert.equal(
        effects.some((effect) => effect.row.effectClass.endsWith(":threw")),
        false,
      );
    } finally {
      again.close();
    }
  });

  it("R18-2 add-file on the directory that holds an executable makes it untrusted; the stock nodejs ACL does not", () => {
    const userSid = "S-1-5-21-1001";
    const nodeExe = "C:\\Program Files\\nodejs\\node.exe";
    const targets = trustTargets(nodeExe, "win32");
    const parent = targets[1];
    assert.ok(parent);
    assert.equal(parent.path.replace(/[\\/]+$/, "").toLowerCase(), "c:\\program files\\nodejs");
    assert.equal(parent.ancestor, false);
    const planted = `O:SYG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x2;;;${userSid})`;
    assert.equal(
      windowsUserCanWrite(planted, { path: parent.path, userSid, ancestor: parent.ancestor }),
      true,
    );
    assert.equal(
      windowsUserCanWrite(STOCK_NODEJS, { path: parent.path, userSid, ancestor: parent.ancestor }),
      false,
    );
    const programFiles = targets.find(
      (entry) => entry.path.replace(/[\\/]+$/, "").toLowerCase() === "c:\\program files",
    );
    assert.ok(programFiles);
    assert.equal(programFiles.ancestor, true);
    assert.equal(
      windowsUserCanWrite(planted, { path: programFiles.path, userSid, ancestor: programFiles.ancestor }),
      false,
    );

    const tool = trustTargets("C:\\Windows\\System32\\whoami.exe", "win32");
    assert.equal(tool[1]?.path.replace(/[\\/]+$/, "").toLowerCase(), "c:\\windows\\system32");
    assert.equal(tool[1]?.ancestor, false);
    assert.equal(tool[2]?.ancestor, true);

    const codeDir = trustTargets("C:\\Program Files\\verax-cli", "win32");
    assert.equal(codeDir[0]?.ancestor, false);
    assert.equal(codeDir[1]?.ancestor, true);
  });

  it("R15-3 desktop children use localhost for the browser and 127.0.0.1 for sockets", async () => {
    const dir = ownerDir("verax-f27-desk-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    const saved = {
      allowed: process.env.VERAX_ALLOWED_ORIGINS,
      rp: process.env.VERAX_RP_ID,
      origins: process.env.VERAX_RP_ORIGINS,
    };
    delete process.env.VERAX_RP_ID;
    delete process.env.VERAX_RP_ORIGINS;
    process.env.VERAX_ALLOWED_ORIGINS = "http://localhost:9";
    const seen: { name: DesktopSpawnName; args: string[]; env: NodeJS.ProcessEnv }[] = [];
    const jwks = JSON.stringify({ keys: [{ kty: "EC", kid: "verax-dev", alg: "ES256" }] });
    try {
      await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        () => {},
        {
          readyMs: 2_000,
          restrictOwner: () => {},
          spawn: (name, _cmd, args, env) => {
            seen.push({ name, args: [...args], env: { ...env } });
            if (name === "issuer") {
              const pinDir = join(dir, "dev-issuer");
              mkdirSync(pinDir, { recursive: true });
              if (process.platform !== "win32") chmodSync(pinDir, 0o700);
              writeFileSync(issuerJwksPinPath(dir), `${jwks}\n`, { mode: 0o600 });
              writeFileSync(join(dir, "dev-token"), "fresh-token\n", { mode: 0o600 });
              return hold(issuerReadyLine(issuerPort));
            }
            if (name === "body") return hold(bodyReadyLine(bodyPort));
            if (name === "panel") return hold(`  Local:   ${panelReadyLine(panelPort)}/`);
            return nodeEval("process.exit(0)");
          },
        },
      );
      const issuer = seen.find((row) => row.name === "issuer");
      const body = seen.find((row) => row.name === "body");
      const panel = seen.find((row) => row.name === "panel");
      const browser = seen.find((row) => row.name === "browser");
      assert.ok(issuer && body && panel && browser);
      assert.equal(issuer.env.VERAX_ISSUER, `http://localhost:${issuerPort}`);
      assert.equal(issuer.env.VERAX_AUDIENCE, `http://localhost:${bodyPort}`);
      assert.equal(issuer.env.VERAX_DEV_REDIRECT_URIS, `http://localhost:${panelPort}/`);
      assert.equal(issuer.env.VERAX_RP_ID, "localhost");
      assert.equal(issuer.env.VERAX_RP_ORIGINS, `http://localhost:${issuerPort}`);
      for (const origin of [
        issuer.env.VERAX_ISSUER,
        issuer.env.VERAX_RP_ORIGINS,
        issuer.env.VERAX_DEV_REDIRECT_URIS,
        issuer.env.VERAX_AUDIENCE,
      ]) {
        assert.equal(hostMatchesRp(String(origin), "localhost"), true, String(origin));
      }
      assert.equal(hostMatchesRp("http://127.0.0.1:1", "localhost"), false);
      assert.equal(body.env.VERAX_ISSUER, `http://localhost:${issuerPort}`);
      assert.equal(body.env.VERAX_AUDIENCE, `http://localhost:${bodyPort}`);
      assert.equal(body.env.VERAX_BIND, `127.0.0.1:${bodyPort}`);
      assert.equal(body.env.VERAX_JWKS_URL, `http://127.0.0.1:${issuerPort}/.well-known/jwks.json`);
      assert.equal(
        body.env.VERAX_ALLOWED_ORIGINS,
        `http://localhost:9,http://localhost:${panelPort}`,
      );
      assert.ok(panel.args.includes("--host"));
      assert.ok(panel.args.includes("127.0.0.1"));
      assert.equal(panel.env.VERAX_BODY_URL, `http://127.0.0.1:${bodyPort}`);
      assert.ok(browser.args.includes(`http://localhost:${panelPort}`));
    } finally {
      if (saved.allowed === undefined) delete process.env.VERAX_ALLOWED_ORIGINS;
      else process.env.VERAX_ALLOWED_ORIGINS = saved.allowed;
      if (saved.rp === undefined) delete process.env.VERAX_RP_ID;
      else process.env.VERAX_RP_ID = saved.rp;
      if (saved.origins === undefined) delete process.env.VERAX_RP_ORIGINS;
      else process.env.VERAX_RP_ORIGINS = saved.origins;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
