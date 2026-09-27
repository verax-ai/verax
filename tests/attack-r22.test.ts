// R22: each `it` asserts the behaviour after the fix. On 811ea1a the
// implementation does the other thing, so the assertion fails.

import { strict as assert } from "node:assert";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { forwardIpv6Loopback, runDesktop } from "../packages/body/src/desktop.ts";
import { runDoctor } from "../packages/body/src/doctor.ts";

function ownerDir(prefix: string): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}

function ownerDirectoryHooks(): {
  restrictOwner: () => void;
  windowsDirectoryOwner?: () => { ownerSid: string; invokingSid: string };
  windowsDirectoryDacl?: () => string;
} {
  const restrictOwner = () => {};
  if (process.platform !== "win32") return { restrictOwner };
  const sid = "S-1-5-21-1";
  return {
    restrictOwner,
    windowsDirectoryOwner: () => ({ ownerSid: sid, invokingSid: sid }),
    windowsDirectoryDacl: () => `O:${sid}D:(A;;FA;;;${sid})`,
  };
}

async function ipv6LeftFree(port: number): Promise<void> {
  const opened = await forwardIpv6Loopback(port);
  if (!opened.ok) {
    assert.equal(opened.reason, "unsupported");
    return;
  }
  await new Promise<void>((resolve) => opened.server.close(() => resolve()));
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

function doctorEnv(dir: string): NodeJS.ProcessEnv {
  return {
    VERAX_ISSUER: "http://127.0.0.1:8790",
    VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
    VERAX_AUDIENCE: "http://127.0.0.1:8787",
    VERAX_STATE_DIR: dir,
    VERAX_POLICY_FILE: "x",
  };
}

function writeLegacy(
  dir: string,
  files: { decisions: string; effects: string; copyDecisions: string; copyEffects: string },
): void {
  const copyDir = join(dir, "evidence-copy");
  mkdirSync(copyDir, { recursive: true });
  if (process.platform !== "win32") chmodSync(copyDir, 0o700);
  writeFileSync(join(dir, "decisions.jsonl"), files.decisions, "utf8");
  writeFileSync(join(dir, "effects.jsonl"), files.effects, "utf8");
  writeFileSync(join(copyDir, "decisions.jsonl"), files.copyDecisions, "utf8");
  writeFileSync(join(copyDir, "effects.jsonl"), files.copyEffects, "utf8");
}

function evidenceCopy(dir: string): { level?: string; detail?: string } | undefined {
  return runDoctor(doctorEnv(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "evidence-copy");
}

describe("attack R22", () => {
  it("R22-1 a live body is refused before a metadata issuer port is claimed", async () => {
    const dir = ownerDir("verax-r22-attach-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1, token: "t", port: bodyPort })}\n`,
      "utf8",
    );
    const err: string[] = [];
    const spawned: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          ...ownerDirectoryHooks(),
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
      assert.equal(text.includes("desktop-port-busy:"), false, text);
      assert.deepEqual(spawned, []);
      await ipv6LeftFree(bodyPort);
      await ipv6LeftFree(issuerPort);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-1 a live body is refused without reading an issuer listener", async () => {
    const dir = ownerDir("verax-r22-down-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1, token: "t", port: bodyPort })}\n`,
      "utf8",
    );
    const err: string[] = [];
    const spawned: string[] = [];
    const heard: number[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          ...ownerDirectoryHooks(),
          listenerPid: (port) => {
            heard.push(port);
            return port === bodyPort ? process.pid : null;
          },
          spawn: (name) => {
            spawned.push(name);
            throw new Error("spawned while a body was already running");
          },
        },
      );
      const text = err.join("");
      assert.equal(code, 1, text);
      assert.match(text, new RegExp(`desktop-body-running:${bodyPort}`));
      assert.equal(text.includes("desktop-attach-issuer-down"), false, text);
      assert.deepEqual(heard, [bodyPort]);
      assert.deepEqual(spawned, []);
      await ipv6LeftFree(issuerPort);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-1 a live body is refused without reading resource metadata", async () => {
    const dir = ownerDir("verax-r22-meta-");
    const [issuerPort, bodyPort, panelPort] = await Promise.all([takePort(), takePort(), takePort()]);
    writeFileSync(
      join(dir, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1, token: "t", port: bodyPort })}\n`,
      "utf8",
    );
    const err: string[] = [];
    const spawned: string[] = [];
    try {
      const code = await runDesktop(
        { stateDir: dir, issuerPort, bodyPort, panelPort, browser: "fake-browser.mjs" },
        (line) => err.push(line),
        {
          readyMs: 500,
          ...ownerDirectoryHooks(),
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
      assert.equal(text.includes("desktop-attach-issuer-unknown"), false, text);
      assert.deepEqual(spawned, []);
      await ipv6LeftFree(bodyPort);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-2 a corrupt source decisions file fails evidence-copy", () => {
    const dir = ownerDir("verax-r22-src-dec-");
    try {
      writeLegacy(dir, {
        decisions: "{not-json\n",
        effects: '{"e":1}\n',
        copyDecisions: '{"n":1}\n',
        copyEffects: '{"e":1}\n',
      });
      const copy = evidenceCopy(dir);
      assert.equal(copy?.level, "fail", JSON.stringify(copy));
      assert.match(copy?.detail ?? "", /source decisions\.jsonl on piece legacy is corrupt/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-2 a corrupt source effects file fails evidence-copy", () => {
    const dir = ownerDir("verax-r22-src-eff-");
    try {
      const row = '{"n":1}\n';
      writeLegacy(dir, {
        decisions: row,
        effects: "{not-json\n",
        copyDecisions: row,
        copyEffects: '{"e":1}\n',
      });
      const copy = evidenceCopy(dir);
      assert.equal(copy?.level, "fail", JSON.stringify(copy));
      assert.match(copy?.detail ?? "", /source effects\.jsonl on piece legacy is corrupt/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-2 a decisions copy longer than its source fails evidence-copy", () => {
    const dir = ownerDir("verax-r22-short-dec-");
    try {
      writeLegacy(dir, {
        decisions: '{"n":1}\n',
        effects: '{"e":1}\n',
        copyDecisions: '{"n":1}\n{"n":2}\n',
        copyEffects: '{"e":1}\n',
      });
      const copy = evidenceCopy(dir);
      assert.equal(copy?.level, "fail", JSON.stringify(copy));
      assert.match(copy?.detail ?? "", /source is shorter than its evidence copy on piece legacy/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-2 an effects copy longer than its source fails evidence-copy", () => {
    const dir = ownerDir("verax-r22-short-eff-");
    try {
      const row = '{"n":1}\n';
      writeLegacy(dir, {
        decisions: row,
        effects: '{"e":1}\n',
        copyDecisions: row,
        copyEffects: '{"e":1}\n{"e":2}\n',
      });
      const copy = evidenceCopy(dir);
      assert.equal(copy?.level, "fail", JSON.stringify(copy));
      assert.match(copy?.detail ?? "", /source is shorter than its evidence copy on piece legacy/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-2 a closed piece whose decision lines disagree with the manifest fails ledger-index", () => {
    const dir = ownerDir("verax-r22-closed-");
    try {
      const pieceDir = join(dir, "pieces", "p-closed");
      const copyDir = join(dir, "evidence-copy", "pieces", "p-closed");
      mkdirSync(pieceDir, { recursive: true });
      mkdirSync(copyDir, { recursive: true });
      if (process.platform !== "win32") {
        chmodSync(join(dir, "pieces"), 0o700);
        chmodSync(pieceDir, 0o700);
        chmodSync(join(dir, "evidence-copy"), 0o700);
        chmodSync(join(dir, "evidence-copy", "pieces"), 0o700);
        chmodSync(copyDir, 0o700);
      }
      const row = '{"n":1}\n';
      writeFileSync(join(pieceDir, "decisions.jsonl"), row, "utf8");
      writeFileSync(join(pieceDir, "effects.jsonl"), "", "utf8");
      writeFileSync(join(copyDir, "decisions.jsonl"), row, "utf8");
      writeFileSync(join(copyDir, "effects.jsonl"), "", "utf8");
      writeFileSync(
        join(dir, "ledger-manifest.json"),
        `${JSON.stringify({
          version: 1,
          countedAtMs: [],
          pieces: [
            {
              id: "p-closed",
              decisions: "pieces/p-closed/decisions.jsonl",
              effects: "pieces/p-closed/effects.jsonl",
              inputs: "pieces/p-closed/inputs.jsonl",
              n: 2,
              effectN: 0,
              firstMs: 1,
              lastMs: 1,
              lastHash: "h",
              closed: true,
            },
          ],
        })}\n`,
        "utf8",
      );
      const allow = (ref: string) =>
        JSON.stringify({
          ref,
          piece: "p-closed",
          kind: "allow",
          tenantRef: "",
          ts: 1,
          requestHash: "",
          resolves: null,
          hasEffect: false,
          reasonCode: "",
          subject: "",
          policyHash: "",
        });
      writeFileSync(join(dir, "index.jsonl"), `${allow("a")}\n${allow("b")}\n`, "utf8");
      writeFileSync(
        join(dir, "heartbeat.json"),
        `${JSON.stringify({ atMs: Date.now(), lastDecisionN: 2 })}\n`,
        "utf8",
      );
      const idx = runDoctor(doctorEnv(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "ledger-index");
      assert.equal(idx?.level, "fail", JSON.stringify(idx));
      assert.match(idx?.detail ?? "", /piece p-closed has 1 decision line\(s\), the manifest says 2/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("R22-3 a heartbeat time in the future fails heartbeat", () => {
    const dir = ownerDir("verax-r22-hb-");
    try {
      writeFileSync(
        join(dir, "heartbeat.json"),
        `${JSON.stringify({ atMs: Date.now() + 120_000, lastDecisionN: 0 })}\n`,
        "utf8",
      );
      const pulse = runDoctor(doctorEnv(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "heartbeat");
      assert.equal(pulse?.level, "fail", JSON.stringify(pulse));
      assert.match(pulse?.detail ?? "", /heartbeat time is in the future/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
