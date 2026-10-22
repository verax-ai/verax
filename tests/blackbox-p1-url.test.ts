// URL rule for the P1 alarm webhook: https is accepted, loopback http is
// accepted, any other http is a start error. A 302 is not followed and is
// not delivery.
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { listen } from "../packages/body/src/server.ts";
import { ALARM_WEBHOOK_URL_ERROR } from "../packages/body/src/config.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const audience = "http://127.0.0.1/verax-test";
const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "policy", "default.json");
const UNTIL = Date.now() + 30 * 86_400_000;
const RETRY_MS = 150;

type Served = { isError: boolean; text: string };

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

async function until(cond: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return cond();
}

async function withIssuer(
  alarmWebhookUrl: string,
  run: (b: {
    state: string;
    get: (id: string) => Promise<Served>;
    put: (id: string, fact: string) => Promise<Served>;
    stop: () => Promise<void>;
    start: () => Promise<void>;
    fact: (id: string) => string;
  }) => Promise<void>,
): Promise<void> {
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1-url-"));
  const issuer = await startDevIssuer(0, audience);
  const token = await issuer.sign({ scope: "verax:read verax:memory", sub: "agent-a" });
  const opts = {
    issuer: issuer.issuer,
    jwksUrl: issuer.jwksUrl,
    audience,
    stateDir: state,
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile,
    tlsTerminated: false,
    alarmWebhookUrl,
    alarmRetryMs: RETRY_MS,
  };
  let server: Awaited<ReturnType<typeof listen>> | null = await listen(opts);
  let rpcId = 0;
  const call = async (name: string, args: Record<string, unknown>): Promise<Served> => {
    assert.ok(server, "body is stopped");
    const port = (server.address() as { port: number }).port;
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
    });
    const body = (await res.json()) as { result?: { isError?: boolean; content?: { text?: string }[] } };
    assert.ok(body.result, `no result for ${name}`);
    return { isError: body.result.isError === true, text: body.result.content?.[0]?.text ?? "" };
  };
  const tag = randomBytes(4).toString("hex");
  const b = {
    state,
    fact: (id: string) => `fact-${id}-${tag}`,
    put: (id: string, fact: string) =>
      call("memory.put", { id, body: { fact }, source: { uri: `file://src-${id}-${tag}`, retrievedAtMs: 1 }, validUntilMs: UNTIL }),
    get: (id: string) => call("memory.get", { id }),
    stop: async () => {
      if (!server) return;
      const srv = server;
      server = null;
      srv.closeAllConnections();
      await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    },
    start: async () => {
      server = await listen(opts);
    },
  };
  try {
    for (const id of ["n1", "n2"]) assert.equal((await b.put(id, b.fact(id))).isError, false);
    await run(b);
  } finally {
    await b.stop();
    await issuer.close?.();
    rmSync(state, { recursive: true, force: true });
  }
}

describe("black box P1: alarm webhook URL rule", () => {
  it("http://example.com is a start error and the alarm stays off", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1-url-deny-"));
    const issuer = await startDevIssuer(0, audience);
    try {
      await assert.rejects(
        () =>
          listen({
            issuer: issuer.issuer,
            jwksUrl: issuer.jwksUrl,
            audience,
            stateDir: state,
            bindHost: "127.0.0.1",
            bindPort: 0,
            policyFile,
            tlsTerminated: false,
            alarmWebhookUrl: "http://example.com/alarm",
          }),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, ALARM_WEBHOOK_URL_ERROR);
          return true;
        },
      );
      assert.equal(existsSync(join(state, "halted")), false);
      assert.equal(existsSync(join(state, "alarm-outbox")), false);
    } finally {
      await issuer.close?.();
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("https is accepted at start", async () => {
    await withIssuer("https://example.com/alarm", async (b) => {
      assert.equal((await b.get("n1")).isError, false);
      assert.equal(existsSync(join(b.state, "halted")), false);
    });
  });

  it("loopback http is accepted at start", async () => {
    await withIssuer("http://localhost:9/alarm", async (b) => {
      assert.equal((await b.get("n1")).isError, false);
    });
  });

  it("a 302 is not followed and is not delivery", async () => {
    const bounced: string[] = [];
    const bounce: Server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        bounced.push(body);
        res.writeHead(200).end();
      });
    });
    await new Promise<void>((r) => bounce.listen(0, "127.0.0.1", r));
    const bouncePort = (bounce.address() as { port: number }).port;

    let redirectAttempts = 0;
    const redirect: Server = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        redirectAttempts += 1;
        res.writeHead(302, { location: `http://127.0.0.1:${bouncePort}/caught` }).end();
      });
    });
    await new Promise<void>((r) => redirect.listen(0, "127.0.0.1", r));
    const redirectPort = (redirect.address() as { port: number }).port;

    try {
      await withIssuer(`http://127.0.0.1:${redirectPort}/alarm`, async (b) => {
        await b.stop();
        const hits = filesUnder(join(b.state, "tenants")).filter((f) => readFileSync(f, "utf8").includes(b.fact("n2")));
        assert.equal(hits.length, 1);
        writeFileSync(hits[0]!, readFileSync(hits[0]!, "utf8").replaceAll(b.fact("n2"), "attacker-fact"));
        await b.start();
        const r = await b.get("n2");
        assert.match(r.text, /memory-integrity-mismatch/);
        await until(() => redirectAttempts >= 2, 4000);
        assert.ok(redirectAttempts >= 1, "the 302 endpoint was never called");
        assert.equal(bounced.length, 0, "the 302 target received a body; the redirect was followed");
        assert.equal(existsSync(join(b.state, "alarm-history.jsonl")), false);
      });
    } finally {
      await new Promise<void>((r) => redirect.close(() => r()));
      await new Promise<void>((r) => bounce.close(() => r()));
    }
  });
});
