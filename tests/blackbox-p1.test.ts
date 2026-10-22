// Black box P1: a memory integrity failure halts the body and sends a signed alarm to the configured webhook,
// retried until accepted, across restarts. The alarm carries no memory content.
import { strict as assert } from "node:assert";
import { createPublicKey, randomBytes, verify } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { canonical } from "@cedulon/core";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const audience = "http://127.0.0.1/verax-test";
const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "policy", "default.json");
const UNTIL = Date.now() + 30 * 86_400_000;
const RETRY_MS = 150;

type Served = { isError: boolean; text: string };
type Alarm = { payload: Record<string, unknown>; sig: string };

/** A webhook receiver whose answers the test scripts: one status per request, then 200. */
async function receiver(statuses: number[] = []): Promise<{ url: string; got: Alarm[]; attempts: () => number; close: () => Promise<void> }> {
  const got: Alarm[] = [];
  let attempts = 0;
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      attempts += 1;
      const status = statuses.length > 0 ? statuses.shift()! : 200;
      if (status === 200) {
        try {
          got.push(JSON.parse(body) as Alarm);
        } catch {
          got.push({ payload: { unparsable: body.slice(0, 200) }, sig: "" });
        }
      }
      res.writeHead(status).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}/alarm`,
    got,
    attempts: () => attempts,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

async function until(cond: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return cond();
}

async function withBody(
  alarmWebhookUrl: string,
  run: (b: {
    state: string;
    put: (id: string, fact: string) => Promise<Served>;
    get: (id: string) => Promise<Served>;
    stop: () => Promise<void>;
    start: () => Promise<void>;
    fact: (id: string) => string;
  }) => Promise<void>,
): Promise<void> {
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1-"));
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
    for (const id of ["n1", "n2", "n3"]) assert.equal((await b.put(id, b.fact(id))).isError, false);
    await run(b);
  } finally {
    await b.stop();
    await issuer.close?.();
    rmSync(state, { recursive: true, force: true });
  }
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

function tamper(state: string, fact: string): void {
  const hits = filesUnder(join(state, "tenants")).filter((f) => readFileSync(f, "utf8").includes(fact));
  assert.equal(hits.length, 1, `one object holds ${fact}`);
  writeFileSync(hits[0]!, readFileSync(hits[0]!, "utf8").replaceAll(fact, "attacker-fact"));
}

/** The alarm is signed with the body's record key over canonical(payload) and names the trigger. */
function checkAlarm(state: string, a: Alarm, trigger: string, notInside: string[]): void {
  const pub = createPublicKey(readFileSync(join(state, "keys", "record.public.pem"), "utf8"));
  assert.ok(verify(null, Buffer.from(canonical(a.payload), "utf8"), pub, Buffer.from(a.sig, "base64")), "alarm signature does not verify");
  assert.equal(a.payload.purpose, "verax.incident.v1");
  assert.equal(a.payload.triggerCode, trigger);
  assert.equal(a.payload.enforcementState, "halted");
  assert.equal(typeof a.payload.eventId, "string");
  const text = JSON.stringify(a);
  for (const t of notInside) assert.ok(!text.includes(t), `alarm carries ${t}`);
}

describe("black box P1: integrity failure halts and alarms", () => {
  it("P1-C: no integrity failure, no halt and no alarm", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        assert.equal((await b.get("n1")).isError, false);
        await new Promise((r) => setTimeout(r, RETRY_MS * 4));
        assert.equal(rx.attempts(), 0, "an alarm was sent without a failure");
        assert.equal(existsSync(join(b.state, "halted")), false);
      });
    } finally {
      await rx.close();
    }
  });

  it("P1-1/2: a tampered item halts the body and a signed alarm without content reaches the webhook", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        await b.start();
        const r = await b.get("n3");
        assert.equal(r.isError, true);
        assert.match(r.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt");
        const next = await b.get("n2");
        assert.equal(next.isError, true);
        assert.match(next.text, /denied:halted/, `next call after the failure: ${next.text.slice(0, 120)}`);
        assert.ok(await until(() => rx.got.length >= 1, 5000), "no alarm reached the webhook");
        checkAlarm(b.state, rx.got[0]!, "memory-integrity-mismatch", [b.fact("n1"), b.fact("n2"), "attacker-fact", "file://src-"]);
      });
    } finally {
      await rx.close();
    }
  });

  it("P1-3: the alarm is retried until the webhook accepts it, with one event id", async () => {
    const rx = await receiver([503, 503]);
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        await b.start();
        await b.get("n3");
        assert.ok(await until(() => rx.got.length >= 1, 8000), `not delivered after ${rx.attempts()} attempts`);
        assert.ok(rx.attempts() >= 3, `attempts ${rx.attempts()}`);
        await new Promise((r) => setTimeout(r, RETRY_MS * 4));
        assert.equal(new Set(rx.got.map((a) => a.payload.eventId)).size, 1, "one incident, one event id");
      });
    } finally {
      await rx.close();
    }
  });

  it("P1-4: an undelivered alarm survives a restart and is delivered after it", async () => {
    const rx = await receiver();
    const deadUrl = rx.url;
    await rx.close();
    await withBody(deadUrl, async (b) => {
      await b.stop();
      tamper(b.state, b.fact("n3"));
      await b.start();
      await b.get("n3");
      await new Promise((r) => setTimeout(r, RETRY_MS * 3));
      await b.stop();
      const port = Number(new URL(deadUrl).port);
      const got: Alarm[] = [];
      const srv = createServer((req, res) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          got.push(JSON.parse(body) as Alarm);
          res.writeHead(200).end();
        });
      });
      await new Promise<void>((r) => srv.listen(port, "127.0.0.1", r));
      try {
        await b.start();
        assert.ok(await until(() => got.length >= 1, 8000), "the stored alarm was not delivered after restart");
        checkAlarm(b.state, got[0]!, "memory-integrity-mismatch", ["attacker-fact"]);
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });

  it("P1-5: an unverifiable commit history on open halts on first read and alarms", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        const commits = join(b.state, "memory-commits.jsonl");
        const lines = readFileSync(commits, "utf8").split("\n").filter((l) => l.trim() !== "");
        lines[0] = lines[0]!.replace(/"seq":1/, '"seq":7');
        writeFileSync(commits, lines.join("\n") + "\n");
        await b.start();
        const r = await b.get("n1");
        assert.match(r.text, /memory-integrity-history-unavailable/);
        assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt");
        assert.ok(await until(() => rx.got.length >= 1, 5000), "no alarm");
        checkAlarm(b.state, rx.got[0]!, "memory-integrity-history-unavailable", [b.fact("n1")]);
      });
    } finally {
      await rx.close();
    }
  });
});
