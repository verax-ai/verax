import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { doctorExit, runDoctor } from "../src/doctor.ts";

describe("doctor", () => {
  it("fails when argv carries sk-test-not-a-key", () => {
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
      },
      ["node", "cli.ts", "doctor", "sk-test-not-a-key"],
    );
    assert.equal(doctorExit(checks), 1);
    assert.ok(checks.some((c) => c.id === "secrets-on-argv" && c.level === "fail"));
  });

  it("2: ledger-lock is ok/warn/fail by pid liveness", () => {
    const env = {
      VERAX_ISSUER: "http://127.0.0.1:8790",
      VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
      VERAX_AUDIENCE: "http://127.0.0.1:8787",
      VERAX_POLICY_FILE: "x",
    };
    const ours = mkdtempSync(join(tmpdir(), "verax-doc-ours-"));
    writeFileSync(
      join(ours, "ledger.lock"),
      `${JSON.stringify({ pid: process.pid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const oursCheck = runDoctor({ ...env, VERAX_STATE_DIR: ours }, ["node", "cli.ts", "doctor"]).find(
      (c) => c.id === "ledger-lock",
    );
    assert.equal(oursCheck?.level, "ok");

    const live = mkdtempSync(join(tmpdir(), "verax-doc-live-"));
    writeFileSync(
      join(live, "ledger.lock"),
      `${JSON.stringify({ pid: process.ppid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const liveCheck = runDoctor({ ...env, VERAX_STATE_DIR: live }, ["node", "cli.ts", "doctor"]).find(
      (c) => c.id === "ledger-lock",
    );
    assert.equal(liveCheck?.level, "warn");

    let deadPid = 1_000_000;
    while (deadPid < 1_000_200) {
      try {
        process.kill(deadPid, 0);
        deadPid += 1;
      } catch {
        break;
      }
    }
    const dead = mkdtempSync(join(tmpdir(), "verax-doc-dead-"));
    writeFileSync(
      join(dead, "ledger.lock"),
      `${JSON.stringify({ pid: deadPid, startedAt: 1 })}\n`,
      { encoding: "utf8" },
    );
    const deadCheck = runDoctor({ ...env, VERAX_STATE_DIR: dead }, ["node", "cli.ts", "doctor"]).find(
      (c) => c.id === "ledger-lock",
    );
    assert.equal(deadCheck?.level, "fail");
    assert.match(deadCheck?.detail ?? "", /verax unlock/);
  });
});
