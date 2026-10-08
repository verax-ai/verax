import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { setTimeout as delay } from "node:timers/promises";

import { verifyLedger } from "@verax-ai/proxy";
import { runCli } from "../packages/body/src/cli.ts";
import { runDoctor } from "../packages/body/src/doctor.ts";
import { readHalt } from "../packages/body/src/halt.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

function temp(): string { return mkdtempSync(join(tmpdir(), "verax-heartbeat-watch-")); }
function rows(dir: string, name: string): any[] {
  const file = join(dir, name);
  return existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((s) => JSON.parse(s)) : [];
}
function beat(dir: string): any { return JSON.parse(readFileSync(join(dir, "heartbeat.json"), "utf8")); }
function capture() {
  let stdout = "", stderr = "";
  return { hooks: { elevated: () => false, stdout: { write: (s: string) => { stdout += s; } }, stderr: { write: (s: string) => { stderr += s; } } }, out: () => stdout, err: () => stderr };
}
async function body(dir = temp()) {
  const issuer = await startDevIssuer(0, "http://127.0.0.1/watch-test");
  const policyFile = join(dir, "policy.json");
  writeFileSync(policyFile, JSON.stringify({ version: 1, default: "deny", rules: [{ id: "read", tool: "memory.get", requires: ["verax:read"], text: "Read." }] }));
  const config = { issuer: issuer.issuer, jwksUrl: issuer.jwksUrl, audience: issuer.audience, stateDir: dir, bindHost: "127.0.0.1", bindPort: 0, policyFile, tlsTerminated: false };
  const server = await listen(config);
  return { dir, config, server, issuer, base: `http://127.0.0.1:${(server.address() as { port: number }).port}`, close: async () => { await new Promise<void>((resolve) => server.close(() => resolve())); await issuer.close(); } };
}

describe("periodic body heartbeat and start gaps", () => {
  it("advances while idle without growing ledger rows and stops on close", async () => {
    const old = process.env.VERAX_HEARTBEAT_EVERY_MS;
    process.env.VERAX_HEARTBEAT_EVERY_MS = "1000";
    const b = await body();
    try {
      const first = beat(b.dir);
      await delay(1250);
      const second = beat(b.dir);
      assert.ok(second.atMs > first.atMs);
      assert.equal(second.beat, "timer");
      assert.equal(second.startedAtMs, first.startedAtMs);
      assert.ok(Number.isFinite(first.startedAtMs));
      assert.equal(second.pid, process.pid);
      assert.equal(second.lastDecisionN, 0);
      assert.equal(second.lastEffectN, 0);
      assert.deepEqual(rows(b.dir, "decisions.jsonl"), []);
      assert.deepEqual(rows(b.dir, "effects.jsonl"), []);
      await new Promise<void>((resolve) => b.server.close(() => resolve()));
      const stopped = readFileSync(join(b.dir, "heartbeat.json"), "utf8");
      await delay(1250);
      assert.equal(readFileSync(join(b.dir, "heartbeat.json"), "utf8"), stopped);
    } finally { await b.close(); if (old === undefined) delete process.env.VERAX_HEARTBEAT_EVERY_MS; else process.env.VERAX_HEARTBEAT_EVERY_MS = old; }
  });

  it("records the previous beat before startup control rows overwrite it", async () => {
    const b = await body();
    try {
      await new Promise<void>((resolve) => b.server.close(() => resolve()));
      const prev = beat(b.dir).atMs;
      await delay(120);
      const c = capture();
      // A halt at rest is synchronized on start; it must not hide the old beat.
      assert.equal(await runCli(["watch", b.dir, "--once", "--max-silence", "1ms"], c.hooks), 3);
      const restarted = await listen(b.config);
      try {
        const starts = rows(b.dir, "starts.jsonl");
        assert.equal(starts.length, 2);
        assert.equal(starts[0].prevBeatAtMs, null);
        assert.equal(starts[0].gapMs, null);
        assert.equal(starts[1].action, "start");
        assert.equal(starts[1].prevBeatAtMs, prev);
        assert.ok(starts[1].gapMs >= 120);
        assert.equal(beat(b.dir).beat, "timer");
      } finally { await new Promise<void>((resolve) => restarted.close(() => resolve())); }
      const summary = capture();
      assert.equal(await runCli(["verify", b.dir, "--json"], summary.hooks), 0, summary.out());
      const report = JSON.parse(summary.out()).starts;
      assert.equal(report.count, 2);
      assert.ok(report.largestGapMs >= 120);
      assert.equal(report.missingPreviousBeat.length, 1);
      const text = capture();
      assert.equal(await runCli(["verify", b.dir], text.hooks), 0);
      assert.match(text.out(), /starts\s+2.*largest gap.*unsigned/);
    } finally { await b.close(); }
  });
});

describe("verax watch once", () => {
  it("accepts a fresh beat; stale heartbeat halts and a later call is a signed deny", async () => {
    const b = await body();
    try {
      const c = capture();
      assert.equal(await runCli(["watch", b.dir, "--once"], c.hooks), 0, c.err());
      writeFileSync(join(b.dir, "heartbeat.json"), JSON.stringify({ atMs: 1 }));
      const silent = capture();
      assert.equal(await runCli(["watch", b.dir, "--once"], silent.hooks), 3);
      assert.equal(readHalt(b.dir).since?.by, "verax-watch");
      assert.equal(readHalt(b.dir).since?.via, "cli");
      assert.equal(JSON.parse(silent.out()).event, "silence");
      const token = await b.issuer.sign();
      const reply = await fetch(`${b.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "memory.get", arguments: { id: "missing" } } }) });
      assert.match(await reply.text(), /halted/);
      const decision = rows(b.dir, "decisions.jsonl").at(-1);
      assert.equal(decision.claims.decision, "deny");
      assert.equal(decision.claims.reasonCode, "halted");
      assert.equal(beat(b.dir).beat, "row");
      assert.equal(readHalt(b.dir).halted, true);
      const verified = await verifyLedger(b.dir);
      assert.equal(verified.ok, true, verified.problems.join("\n"));
      assert.ok(verified.signaturesValid > 0);
    } finally { await b.close(); }
  });

  for (const [label, value] of [["missing", undefined], ["broken", "{"], ["null", "null"], ["future", JSON.stringify({ atMs: Date.now() + 120_000 })], ["string time", JSON.stringify({ atMs: "12" })]] as const) {
    it(`fails closed on ${label}`, async () => {
      const dir = temp();
      if (value !== undefined) writeFileSync(join(dir, "heartbeat.json"), value);
      const c = capture();
      assert.equal(await runCli(["watch", dir, "--once"], c.hooks), 3, c.err());
      assert.equal(readHalt(dir).halted, true);
      assert.equal(JSON.parse(c.out()).event, "silence");
    });
  }
  it("doctor names a stopped timer and a corrupt idle beat", async () => {
    const dir = temp();
    const env = { VERAX_STATE_DIR: dir };
    for (const text of [JSON.stringify({ atMs: 1, beat: "timer" }), "{"]) {
      writeFileSync(join(dir, "heartbeat.json"), text);
      const check = runDoctor(env, []).find((c) => c.id === "heartbeat");
      assert.equal(check?.level, "fail");
      assert.match(check?.detail ?? "", /stopped|silent/);
    }
  });
  for (const args of [[], ["--max-silence", "no"], ["--max-silence", "0s"], ["--unknown"], ["--on-silence", "exec"], ["--exec", "node"], ["--url", "https://example.com/healthz"], ["--url", "https://example.com/healthz", "--token", "secret"]]) {
    it(`usage error for ${JSON.stringify(args)}`, async () => {
      const c = capture();
      const target = args.length === 0 || args.includes("--url") ? [] : [temp()];
      assert.equal(await runCli(["watch", ...target, ...args, "--once"], c.hooks), 2);
    });
  }
  it("remote audit heartbeat is live; a stopped body is silent without local halt", async () => {
    const b = await body();
    try {
      const tokenFile = join(b.dir, "audit.token");
      const token = await b.issuer.sign({ scope: "verax:audit" });
      writeFileSync(tokenFile, token);
      const argv = ["watch", "--url", `${b.base}/healthz`, "--token-file", tokenFile, "--once"];
      assert.ok(!argv.includes(token));
      const live = capture();
      assert.equal(await runCli(argv, live.hooks), 0, live.err());
      writeFileSync(tokenFile, await b.issuer.sign({ scope: "verax:read" }));
      assert.equal(await runCli(argv, capture().hooks), 3);
      writeFileSync(tokenFile, token);
      await new Promise<void>((resolve) => b.server.close(() => resolve()));
      const stopped = capture();
      assert.equal(await runCli(argv, stopped.hooks), 3);
      assert.match(stopped.out(), /remote halt is out of scope/);
      assert.equal(existsSync(join(b.dir, "halted")), false);
      assert.ok(!stopped.out().includes(token));
      assert.ok(!stopped.err().includes(token));
    } finally { await b.close(); }
  });
});
