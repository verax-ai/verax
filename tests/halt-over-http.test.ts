import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { haltBody, resumeBody } from "../packages/body/src/halt.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

function allowPolicyFile(dir: string): string {
  const path = join(dir, "allow-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      rules: [
        {
          id: "put-allow",
          tool: "memory.put",
          requires: ["verax:memory"],
          mode: "allow",
          text: "Writes are allowed.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

async function put(base: string, token: string, id: string): Promise<string> {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "memory.put",
        arguments: {
          id,
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      },
    }),
  });
  return res.text();
}

type HaltState = { halted?: boolean; since?: { by?: string; via?: string } };

/**
 * The stop button is the panel's way to `verax halt`. Stopping is the safe
 * direction and any operator session may press it. Lifting the halt lets
 * everything through again, so it needs the approve scope, and the agent's own
 * token can press neither: an agent that could resume would make the halt a
 * suggestion.
 */
describe("halt and resume over HTTP", () => {
  it("an operator stops the body, the agent cannot undo it, and only approve resumes", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-halt-http-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile: allowPolicyFile(stateDir),
      tlsTerminated: false,
    });
    const port = (server.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    const call = (path: string, token: string | null, method = "POST") =>
      fetch(`${base}${path}`, {
        method,
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });

    try {
      const agent = await issuer.sign({ scope: "verax:read verax:memory" });
      const reader = await issuer.sign({ scope: "verax:audit", sub: "reader-3" });
      const operator = await issuer.sign({ scope: "verax:audit verax:approve", sub: "operator-7" });

      assert.doesNotMatch(await put(base, agent, "before"), /halted/);

      assert.equal((await call("/api/halt", null)).status, 401);
      assert.equal((await call("/api/halt", agent)).status, 403);

      const stopped = await call("/api/halt", reader);
      assert.equal(stopped.status, 200);
      const state = (await stopped.json()) as HaltState;
      assert.equal(state.halted, true);
      assert.equal(state.since?.by, "reader-3");
      assert.equal(state.since?.via, "http");

      assert.match(await put(base, agent, "while-halted"), /halted/);

      // Neither the agent nor a reader can lift it.
      assert.equal((await call("/api/resume", agent)).status, 403);
      assert.equal((await call("/api/resume", reader)).status, 403);
      const still = (await (await call("/api/halt", reader, "GET")).json()) as HaltState;
      assert.equal(still.halted, true);
      assert.equal(still.since?.by, "reader-3");

      // A second press does not rewrite who stopped it.
      const again = (await (await call("/api/halt", operator)).json()) as HaltState;
      assert.equal(again.since?.by, "reader-3");

      const resumed = await call("/api/resume", operator);
      assert.equal(resumed.status, 200);
      assert.equal(((await resumed.json()) as HaltState).halted, false);
      assert.doesNotMatch(await put(base, agent, "after"), /halted/);

      const history = readFileSync(join(stateDir, "halt-history.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { action: string; by: string });
      assert.deepEqual(
        history.map((row) => [row.action, row.by]),
        [
          ["halt", "reader-3"],
          ["resume", "operator-7"],
        ],
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await issuer.close();
    }
  });
});

describe("resume with a history it cannot write", () => {
  it("stays halted rather than resuming with no record", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-halt-history-"));
    haltBody(stateDir, "operator-7", "http");
    // A directory where the history file should be: every append fails.
    const history = join(stateDir, "halt-history.jsonl");
    rmSync(history);
    mkdirSync(history);
    assert.throws(() => resumeBody(stateDir, "operator-7", "http"));
    assert.equal(existsSync(join(stateDir, "halted")), true);
  });
});
