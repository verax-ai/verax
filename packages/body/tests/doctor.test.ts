import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { doctorBodyLog, doctorExit, runDoctor } from "../src/doctor.ts";

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

  it("warns when the panel port is outside the issuer redirect allow-list", () => {
    const env = {
      VERAX_ISSUER: "http://127.0.0.1:8790",
      VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
      VERAX_AUDIENCE: "http://127.0.0.1:8787",
      VERAX_STATE_DIR: ".",
      VERAX_POLICY_FILE: "x",
      VERAX_PANEL_PORT: "5200",
    };
    const miss = runDoctor(env, ["node", "cli.ts", "doctor"]).find((c) => c.id === "panel-redirect-uri");
    assert.equal(miss?.level, "warn");
    assert.match(miss?.detail ?? "", /5200/);
    assert.match(miss?.detail ?? "", /VERAX_DEV_REDIRECT_URIS/);

    const listed = runDoctor(
      { ...env, VERAX_DEV_REDIRECT_URIS: "http://127.0.0.1:5200/" },
      ["node", "cli.ts", "doctor"],
    ).find((c) => c.id === "panel-redirect-uri");
    assert.equal(listed?.level, "ok");

    const def = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
      },
      ["node", "cli.ts", "doctor"],
    ).find((c) => c.id === "panel-redirect-uri");
    assert.equal(def?.level, "ok");
  });

  it("says where the panel port came from, so an ok line is not read as a live check", () => {
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
      },
      ["node", "cli.ts", "doctor"],
    );
    const check = checks.find((c) => c.id === "panel-redirect-uri");
    assert.equal(check?.level, "ok");
    // The doctor never opens the port; it reads an environment variable or falls
    // back to 5173. The line has to say so, or a green reads as "I looked".
    assert.match(check?.detail ?? "", /VERAX_PANEL_PORT/);
  });

  it("warns when the panel last-resort issuer differs from VERAX_ISSUER", () => {
    const base = {
      VERAX_JWKS_URL: "http://127.0.0.1:8791/.well-known/jwks.json",
      VERAX_AUDIENCE: "http://127.0.0.1:8787",
      VERAX_STATE_DIR: ".",
      VERAX_POLICY_FILE: "x",
    };
    const miss = runDoctor({ ...base, VERAX_ISSUER: "http://127.0.0.1:8791" }, ["node", "cli.ts", "doctor"]).find(
      (c) => c.id === "panel-issuer",
    );
    assert.equal(miss?.level, "warn");
    assert.match(miss?.detail ?? "", /8791/);
    assert.match(miss?.detail ?? "", /authorization_servers|resource metadata/);

    const same = runDoctor({ ...base, VERAX_ISSUER: "http://127.0.0.1:8790" }, ["node", "cli.ts", "doctor"]).find(
      (c) => c.id === "panel-issuer",
    );
    assert.equal(same?.level, "ok");
  });

  it("warns when a development token carries verax:audit and does not print the token", () => {
    const base = {
      VERAX_ISSUER: "http://127.0.0.1:8790",
      VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
      VERAX_AUDIENCE: "http://127.0.0.1:8787",
      VERAX_STATE_DIR: ".",
      VERAX_POLICY_FILE: "x",
    };
    // The scope string is not the agent token. Asking for audit does not grant it.
    const asked = runDoctor(
      { ...base, VERAX_DEV_SCOPE: "verax:read verax:memory verax:audit" },
      ["node", "cli.ts", "doctor"],
    ).find((c) => c.id === "dev-token-audit");
    assert.equal(asked?.level, "ok");
    assert.match(asked?.detail ?? "", /passkey/);

    const bare = runDoctor({ ...base, VERAX_DEV_SCOPE: "verax:read" }, ["node", "cli.ts", "doctor"]).find(
      (c) => c.id === "dev-token-audit",
    );
    assert.equal(bare?.level, "ok");

    const safePayload = Buffer.from(JSON.stringify({ scope: "verax:read" })).toString("base64url");
    const safeToken = `eyJhbGciOiJub25lIn0.${safePayload}.x`;
    const fromSafe = runDoctor({ ...base, VERAX_DEV_TOKEN: safeToken }, ["node", "cli.ts", "doctor"]);
    const dumped = JSON.stringify(fromSafe);
    assert.equal(dumped.includes(safeToken), false, dumped);
    assert.equal(dumped.includes(safePayload), false, dumped);
    assert.equal(fromSafe.find((c) => c.id === "dev-token-audit")?.level, "ok");

    const auditPayload = Buffer.from(JSON.stringify({ scope: "verax:read verax:audit" })).toString("base64url");
    const auditToken = `eyJhbGciOiJub25lIn0.${auditPayload}.x`;
    const fromTok = runDoctor({ ...base, VERAX_DEV_TOKEN: auditToken }, ["node", "cli.ts", "doctor"]);
    const dumpedAudit = JSON.stringify(fromTok);
    assert.equal(dumpedAudit.includes(auditToken), false, dumpedAudit);
    assert.equal(dumpedAudit.includes(auditPayload), false, dumpedAudit);
    const tokCheck = fromTok.find((c) => c.id === "dev-token-audit");
    assert.equal(tokCheck?.level, "warn");
    assert.match(tokCheck?.detail ?? "", /verax:audit/);
  });

  it("adds no downstream check when VERAX_DOWNSTREAM is unset", () => {
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
      },
      ["node", "cli.ts", "doctor"],
    );
    assert.equal(
      checks.some((c) => c.id.startsWith("downstream")),
      false,
    );
  });

  it("names a trusted stdio child as warn and does not fail the exit", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-doc-down-ok-"));
    const command = "NEVER-IN-DOCTOR-OUTPUT";
    writeFileSync(
      join(dir, "downstream.json"),
      `${JSON.stringify({ prefix: "kb", command, trust: "same-user" })}\n`,
      "utf8",
    );
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: dir,
        VERAX_POLICY_FILE: "x",
        VERAX_DOWNSTREAM: join(dir, "downstream.json"),
      },
      ["node", "cli.ts", "doctor"],
    );
    const document = checks.find((c) => c.id === "downstream-document");
    assert.equal(document?.level, "ok");
    const stdio = checks.find((c) => c.id === "downstream-stdio:kb");
    assert.equal(stdio?.level, "warn");
    assert.match(stdio?.detail ?? "", /kb/);
    assert.equal((stdio?.detail ?? "").includes(command), false);
    assert.equal(doctorExit(checks), 0);
  });

  it("fails the document when a stdio child has no trust ack", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-doc-down-ack-"));
    writeFileSync(
      join(dir, "downstream.json"),
      `${JSON.stringify({ prefix: "kb", command: "node" })}\n`,
      "utf8",
    );
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
        VERAX_DOWNSTREAM: join(dir, "downstream.json"),
      },
      ["node", "cli.ts", "doctor"],
    );
    const document = checks.find((c) => c.id === "downstream-document");
    assert.equal(document?.level, "fail");
    assert.equal(doctorExit(checks), 1);
  });

  it("does not name a downstream-stdio check for an HTTP child and does not print its url", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-doc-down-http-"));
    writeFileSync(
      join(dir, "downstream.json"),
      `${JSON.stringify({ prefix: "kb", url: "http://127.0.0.1:9/secret-token/mcp" })}\n`,
      "utf8",
    );
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
        VERAX_DOWNSTREAM: join(dir, "downstream.json"),
      },
      ["node", "cli.ts", "doctor"],
    );
    assert.equal(
      checks.some((c) => c.id.startsWith("downstream-stdio:")),
      false,
    );
    assert.equal(JSON.stringify(checks).includes("http://"), false);
  });

  it("fails the document when VERAX_DOWNSTREAM names a missing file", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-doc-down-miss-"));
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: ".",
        VERAX_POLICY_FILE: "x",
        VERAX_DOWNSTREAM: join(dir, "no-such-downstream.json"),
      },
      ["node", "cli.ts", "doctor"],
    );
    const document = checks.find((c) => c.id === "downstream-document");
    assert.equal(document?.level, "fail");
  });

  it("prints the last 20 lines of body.log", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-doc-body-log-"));
    const lines = Array.from({ length: 25 }, (_, i) => `line-${i + 1}`);
    writeFileSync(join(dir, "body.log"), `${lines.join("\n")}\n`, { encoding: "utf8" });
    assert.equal(doctorBodyLog(dir), `${lines.slice(-20).join("\n")}\n`);
    assert.match(doctorBodyLog(join(dir, "absent")), /body\.log missing:/);
  });
});
