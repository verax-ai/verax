import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { loadConfig } from "../packages/body/src/config.ts";
import { parseDownstreamDocument } from "../packages/body/src/downstream.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests", "fixtures", "downstream-echo.mjs");
const defaultPolicy = join(root, "packages", "proxy", "policy", "default.json");

const ECHO_POLICY = JSON.stringify({
  version: 1,
  default: "deny",
  rules: [
    {
      id: "echo-ping",
      tool: "echo.ping",
      requires: ["verax:read"],
      text: "Calling the echo downstream needs the read scope.",
    },
  ],
});

async function rpc(
  url: string,
  token: string | null,
  method: string,
  params: Record<string, unknown>,
): Promise<{ status: number; json: Record<string, unknown> | null }> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  let json: Record<string, unknown> | null = null;
  try {
    json = (await res.json()) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

type TraceEvent = { event: string; pid?: number };

type ServedCtx = {
  mcp: string;
  stateDir: string;
  token: (scope?: string) => Promise<string>;
  /** What the fixture child recorded, when `trace` was asked for. */
  trace: () => TraceEvent[];
};

/** Waits for a pid to disappear; the close is asynchronous on both platforms. */
async function waitForExit(pid: number, ms = 5000): Promise<void> {
  const until = Date.now() + ms;
  for (;;) {
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
    if (Date.now() > until) return;
    await sleep(25);
  }
}

/** Starts a body whose config names a downstream document, and tears both down. */
async function withServedBody(
  opts: { policyText: string; downstream: unknown; trace?: boolean },
  fn: (ctx: ServedCtx) => Promise<void>,
): Promise<void> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-served-"));
  const policyFile = join(stateDir, "policy.json");
  writeFileSync(policyFile, `${opts.policyText}\n`, "utf8");
  const traceFile = join(stateDir, "child-trace.jsonl");
  const downstreamFile = join(stateDir, "downstream.json");
  const document =
    opts.trace === true && !Array.isArray(opts.downstream)
      ? { ...(opts.downstream as Record<string, unknown>), env: { VERAX_ECHO_TRACE: traceFile } }
      : opts.downstream;
  writeFileSync(downstreamFile, `${JSON.stringify(document)}\n`, "utf8");
  const readTrace = (): TraceEvent[] =>
    existsSync(traceFile)
      ? readFileSync(traceFile, "utf8")
          .split("\n")
          .filter((line) => line.trim() !== "")
          .map((line) => JSON.parse(line) as TraceEvent)
      : [];
  const audience = "http://127.0.0.1/verax-test";
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
    downstreamFile,
  });
  const port = (server.address() as { port: number }).port;
  try {
    await fn({
      mcp: `http://127.0.0.1:${port}/mcp`,
      stateDir,
      token: (scope = "verax:read") => issuer.sign({ scope }),
      trace: readTrace,
    });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await issuer.close();
  }
}

describe("downstream on the served path", { timeout: 60_000 }, () => {
  it("publishes the child's prefixed tool on tools/list with its description and schema", async () => {
    await withServedBody(
      {
        policyText: ECHO_POLICY,
        downstream: { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
      },
      async ({ mcp, token }) => {
        const listed = await rpc(mcp, await token(), "tools/list", {});
        assert.equal(listed.status, 200);
        const tools =
          (listed.json?.result as { tools?: { name: string; description?: string; inputSchema?: unknown }[] })
            ?.tools ?? [];
        const names = tools.map((t) => t.name).sort();
        assert.deepEqual(names, [
          "audit.explain",
          "echo.ping",
          "memory.get",
          "memory.put",
          "message.read",
          "message.send",
          "spend",
        ]);
        const ping = tools.find((t) => t.name === "echo.ping");
        assert.ok(ping, "echo.ping missing from tools/list");
        assert.match(ping?.description ?? "", /pong/i);
        const schema = ping?.inputSchema as { properties?: Record<string, unknown> } | undefined;
        assert.ok(schema?.properties?.n, "the child's own parameter is not published");
      },
    );
  });

  it("forwards an allowed call through the gate and writes one decision and one effect", async () => {
    await withServedBody(
      {
        policyText: ECHO_POLICY,
        downstream: { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
      },
      async ({ mcp, stateDir, token }) => {
        const called = await rpc(mcp, await token(), "tools/call", {
          name: "echo.ping",
          arguments: { n: 7 },
        });
        assert.equal(called.status, 200);
        const result = called.json?.result as { isError?: boolean; content?: { text?: string }[] };
        assert.equal(result?.isError, false, JSON.stringify(called.json));
        const text = (result?.content ?? []).map((c) => c.text ?? "").join("");
        assert.match(text, /"pong":true/);
        assert.match(text, /"n":7/);

        const { readFileSync } = await import("node:fs");
        const decisions = readFileSync(join(stateDir, "decisions.jsonl"), "utf8");
        assert.match(decisions, /"subject":"echo\.ping"/);
        assert.match(decisions, /"decision":"allow"/);
        const effects = readFileSync(join(stateDir, "effects.jsonl"), "utf8");
        assert.match(effects, /"effectClass":"echo\.ping"/);
      },
    );
  });

  it("denies a forwarded tool the policy does not name, and the child is never called", async () => {
    await withServedBody(
      {
        policyText: readFileSync(defaultPolicy, "utf8"),
        downstream: { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
        trace: true,
      },
      async ({ mcp, stateDir, token, trace }) => {
        const called = await rpc(mcp, await token(), "tools/call", {
          name: "echo.ping",
          arguments: { n: 1 },
        });
        assert.equal(called.status, 200);
        const result = called.json?.result as { isError?: boolean; content?: { text?: string }[] };
        assert.equal(result?.isError, true);
        const text = (result?.content ?? []).map((c) => c.text ?? "").join("");
        assert.match(text, /^denied:no-rule:/);
        assert.equal(existsSync(join(stateDir, "effects.jsonl")), false);
        // The child started (the door lists its tool) but the gate refused
        // before `inner`, so it was never asked to do anything.
        assert.equal(trace().filter((e) => e.event === "start").length, 1);
        assert.equal(trace().filter((e) => e.event === "call").length, 0);
      },
    );
  });

  it("stops the body when the document names a child that cannot attach", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-served-bad-"));
    const policyFile = join(stateDir, "policy.json");
    writeFileSync(policyFile, `${ECHO_POLICY}\n`, "utf8");
    const downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(
      downstreamFile,
      `${JSON.stringify({ prefix: "echo", command: process.execPath, args: [join(root, "tests", "fixtures", "no-such-child.mjs")], trust: "same-user" })}\n`,
      "utf8",
    );
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    // A body that came up anyway is the failure this test is about, so it is
    // closed here rather than left to hold the runner open.
    let started: Awaited<ReturnType<typeof listen>> | null = null;
    try {
      await assert.rejects(async () => {
        started = await listen({
          issuer: issuer.issuer,
          jwksUrl: issuer.jwksUrl,
          audience,
          stateDir,
          bindHost: "127.0.0.1",
          bindPort: 0,
          policyFile,
          tlsTerminated: false,
          downstreamFile,
        });
      }, /downstream-attach-failed:echo:/);
    } finally {
      if (started !== null) {
        await new Promise<void>((resolve) => {
          (started as unknown as { close: (cb: () => void) => void }).close(() => resolve());
        });
      }
      await issuer.close();
    }
  });

  it("closes the child process when the body stops", async () => {
    let pid = 0;
    await withServedBody(
      {
        policyText: ECHO_POLICY,
        downstream: { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
        trace: true,
      },
      async ({ trace }) => {
        const start = trace().find((e) => e.event === "start");
        assert.ok(typeof start?.pid === "number" && start.pid > 0, "the child did not report a pid");
        pid = start.pid;
        assert.doesNotThrow(() => process.kill(pid, 0), "the child is not running while the body is up");
      },
    );
    // withServedBody has closed the server; the child must have gone with it.
    await waitForExit(pid);
    assert.throws(() => process.kill(pid, 0), /ESRCH/, `child ${pid} outlived the body`);
  });

  it("attaches every child an array document names and refuses a repeated prefix", async () => {
    await withServedBody(
      {
        policyText: ECHO_POLICY,
        downstream: [
          { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
          { prefix: "second", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
        ],
      },
      async ({ mcp, token }) => {
        const listed = await rpc(mcp, await token(), "tools/list", {});
        const names = ((listed.json?.result as { tools?: { name: string }[] })?.tools ?? []).map((t) => t.name);
        assert.ok(names.includes("echo.ping"), names.join(","));
        assert.ok(names.includes("second.ping"), names.join(","));
      },
    );
    assert.throws(
      () =>
        parseDownstreamDocument(
          JSON.stringify([
            { prefix: "echo", command: "node", trust: "same-user" },
            { prefix: "echo", command: "node", trust: "same-user" },
          ]),
        ),
      /downstream-prefix-duplicate:echo/,
    );
  });

  it("attaches what VERAX_DOWNSTREAM names, through the same loadConfig main uses", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-served-env-"));
    const policyFile = join(stateDir, "policy.json");
    writeFileSync(policyFile, `${ECHO_POLICY}\n`, "utf8");
    const downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(
      downstreamFile,
      `${JSON.stringify({ prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" })}\n`,
      "utf8",
    );
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const loaded = loadConfig({
      VERAX_ISSUER: issuer.issuer,
      VERAX_JWKS_URL: issuer.jwksUrl,
      VERAX_AUDIENCE: audience,
      VERAX_STATE_DIR: stateDir,
      VERAX_POLICY_FILE: policyFile,
      VERAX_BIND: "127.0.0.1:0",
      VERAX_DOWNSTREAM: downstreamFile,
    } as NodeJS.ProcessEnv);
    assert.equal(loaded.ok, true, loaded.ok === false ? loaded.reason : "");
    // main.ts hands this value straight to listen(); so does this test.
    const server = await listen(loaded.ok === true ? loaded.value : ({} as never));
    const port = (server.address() as { port: number }).port;
    try {
      const listed = await rpc(
        `http://127.0.0.1:${port}/mcp`,
        await issuer.sign({ scope: "verax:read" }),
        "tools/list",
        {},
      );
      const names = ((listed.json?.result as { tools?: { name: string }[] })?.tools ?? []).map((t) => t.name);
      assert.ok(names.includes("echo.ping"), `VERAX_DOWNSTREAM did not reach the door: ${names.join(",")}`);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("reads VERAX_DOWNSTREAM as a path to the document, never the document itself", () => {
    const base = {
      VERAX_ISSUER: "http://127.0.0.1:1",
      VERAX_JWKS_URL: "http://127.0.0.1:1/jwks",
      VERAX_AUDIENCE: "http://127.0.0.1/verax",
      VERAX_STATE_DIR: "/tmp/state",
      VERAX_POLICY_FILE: "/tmp/policy.json",
    };
    const unset = loadConfig(base as NodeJS.ProcessEnv);
    assert.equal(unset.ok, true);
    assert.equal(unset.ok === true ? unset.value.downstreamFile : "unset", null);
    const set = loadConfig({ ...base, VERAX_DOWNSTREAM: " /tmp/downstream.json " } as NodeJS.ProcessEnv);
    assert.equal(set.ok === true ? set.value.downstreamFile : "unset", "/tmp/downstream.json");
  });
});
