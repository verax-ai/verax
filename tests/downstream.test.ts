import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { extraToolNameOk, openDownstream, parseDownstreamJson } from "../packages/body/src/downstream.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";

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

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function textOf(result: { content: Array<{ text?: string }> }): string {
  return result.content.map((c) => c.text ?? "").join("");
}

async function withEchoBody(
  policyText: string,
  fn: (ctx: {
    services: ReturnType<typeof createBodyServices>;
    session: Awaited<ReturnType<typeof openDownstream>>;
  }) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "verax-down-"));
  const policyFile = join(dir, "policy.json");
  writeFileSync(policyFile, `${policyText}\n`, "utf8");
  const keys = testKeys();
  let n = 0;
  const session = await openDownstream({
    prefix: "echo",
    command: process.execPath,
    args: [fixture],
    cwd: root,
  });
  try {
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      now: () => Date.now(),
      nonce: () => `n${++n}`,
      extraTools: session.tools,
    });
    try {
      await fn({ services, session });
    } finally {
      services.ledger.close();
    }
  } finally {
    await session.close();
  }
}

describe("downstream spike", { timeout: 60_000 }, () => {
  it("lists the prefixed tool and an allow writes a decision plus an effect row", async () => {
    await withEchoBody(ECHO_POLICY, async ({ services }) => {
      assert.ok(services.listTools().includes("echo.ping"));
      const principal = { brain: "brain-1", scopes: new Set(["verax:read"]) };
      const result = await services.proxy.call(
        { name: "echo.ping", arguments: { n: 7 } },
        principal,
      );
      assert.equal(result.isError, false, textOf(result));
      assert.match(textOf(result), /"pong":true/);
      assert.match(textOf(result), /"n":7/);

      const decisions = await services.ledger.decisions();
      assert.equal(decisions.length, 1);
      assert.equal(decisions[0]?.claims.decision, "allow");
      assert.equal(decisions[0]?.claims.subject, "echo.ping");
      assert.equal(decisions[0]?.claims.reasonCode, "allow");

      const effects = await services.ledger.effects();
      assert.equal(effects.length, 1);
      assert.equal(effects[0]?.row.effectClass, "echo.ping");
      assert.equal(typeof effects[0]?.resultHash, "string");
      assert.equal(effects[0]?.resultHash?.length, 64);
    });
  });

  it("denies a prefixed tool when the policy has no rule, and writes no effect", async () => {
    await withEchoBody(readFileSync(defaultPolicy, "utf8"), async ({ services }) => {
      const result = await services.proxy.call(
        { name: "echo.ping", arguments: { n: 1 } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      assert.equal(result.isError, true);
      assert.match(textOf(result), /^denied:no-rule:/);
      assert.equal((await services.ledger.effects()).length, 0);
      const decisions = await services.ledger.decisions();
      assert.equal(decisions.length, 1);
      assert.equal(decisions[0]?.claims.decision, "deny");
      assert.equal(decisions[0]?.claims.reasonCode, "no-rule");
      assert.equal(decisions[0]?.claims.effectHash, null);
    });
  });

  it("records allow plus a threw effect when the child tool fails", async () => {
    await withEchoBody(ECHO_POLICY, async ({ services }) => {
      await assert.rejects(() =>
        services.proxy.call(
          { name: "echo.ping", arguments: { fail: true } },
          { brain: "brain-1", scopes: new Set(["verax:read"]) },
        ),
      );
      const decisions = await services.ledger.decisions();
      assert.equal(decisions.length, 1);
      assert.equal(decisions[0]?.claims.decision, "allow");
      const effects = await services.ledger.effects();
      assert.equal(effects.length, 1);
      assert.equal(effects[0]?.row.effectClass, "echo.ping:threw");
    });
  });

  it("parseDownstreamJson reads one stdio child and refuses a bad prefix", () => {
    const spec = parseDownstreamJson(
      JSON.stringify({ prefix: "echo", command: "node", args: ["x"], timeoutMs: 5, env: { K: "v" } }),
    );
    assert.equal(spec.prefix, "echo");
    assert.equal(spec.command, "node");
    assert.deepEqual(spec.args, ["x"]);
    assert.equal(spec.timeoutMs, 5);
    assert.deepEqual(spec.env, { K: "v" });
    assert.throws(() => parseDownstreamJson("{}"), /downstream-prefix-invalid/);
    assert.throws(() => parseDownstreamJson("["), /downstream-json-invalid/);
    assert.throws(() => parseDownstreamJson("[]"), /downstream-json-not-object/);
    assert.throws(() => parseDownstreamJson(JSON.stringify({ prefix: "echo", command: "node", env: { K: 1 } })), /downstream-env-invalid/);
    assert.throws(() => parseDownstreamJson(JSON.stringify({ prefix: "echo", command: "node", timeoutMs: 0 })), /downstream-timeout-invalid/);
  });

  it("refuses a bare extra name that is not prefix.childName", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-down-bare-"));
    const keys = testKeys();
    assert.equal(extraToolNameOk("ping"), false);
    assert.equal(extraToolNameOk("echo.ping"), true);
    assert.throws(
      () =>
        createBodyServices({
          stateDir: dir,
          policyFile: defaultPolicy,
          recordSigner: keys,
          effectSigner: keys,
          extraTools: [
            {
              name: "ping",
              fn: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
            },
          ],
        }),
      /downstream-name-invalid:ping/,
    );
  });

  it("refuses to register a prefixed name that collides with a body tool", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-down-col-"));
    const keys = testKeys();
    assert.throws(
      () =>
        createBodyServices({
          stateDir: dir,
          policyFile: defaultPolicy,
          recordSigner: keys,
          effectSigner: keys,
          extraTools: [
            {
              name: "memory.get",
              fn: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
            },
          ],
        }),
      /downstream-name-collision:memory\.get/,
    );
  });

  it("does not copy VERAX_* from the parent into the child unless the spec names them", async () => {
    await withEchoBody(ECHO_POLICY, async ({ services }) => {
      const result = await services.proxy.call(
        { name: "echo.ping", arguments: { n: 1, echoEnv: true } },
        { brain: "brain-1", scopes: new Set(["verax:read"]) },
      );
      assert.equal(result.isError, false, textOf(result));
      const body = JSON.parse(textOf(result)) as { veraxKeys?: string[] };
      assert.deepEqual(body.veraxKeys, []);
    });
  });

  it("listen() does not attach extras", () => {
    const server = readFileSync(join(root, "packages", "body", "src", "server.ts"), "utf8");
    assert.equal(server.includes("openDownstream"), false);
    assert.equal(server.includes("VERAX_DOWNSTREAM"), false);
    assert.equal(server.includes("extraTools"), false);
  });

  it("measures median extra latency of a forwarded call (proxy-perf pattern, not a budget)", async () => {
    await withEchoBody(ECHO_POLICY, async ({ services, session }) => {
      const principal = { brain: "brain-1", scopes: new Set(["verax:read"]) };
      const warmup = 6;
      const rounds = 12;
      const samples: number[] = [];
      for (let i = 0; i < warmup + rounds; i += 1) {
        const t0 = performance.now();
        const result = await services.proxy.call(
          { name: "echo.ping", arguments: { n: i } },
          principal,
        );
        samples.push(performance.now() - t0);
        assert.equal(result.isError, false, textOf(result));
      }
      const timed = samples.slice(warmup).sort((a, b) => a - b);
      const median = timed[Math.floor(timed.length / 2)] ?? Number.NaN;
      assert.ok(Number.isFinite(median), "forward median was not a number");
      // Printed for the spike report. Not compared to a baseline.
      process.stdout.write(`downstream-forward-median-ms ${median.toFixed(3)}\n`);
      assert.equal(session.prefix, "echo");
    });
  });
});
