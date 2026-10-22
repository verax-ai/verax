// P1-h: a blocked halt switch still closes every tool in-process; the
// operator is not told "halted" unless the file is there; an incident
// always carries an event id.
import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runHalt } from "../packages/body/src/halt.ts";
import { incidentEventIdFrom, recordKeyId } from "../packages/body/src/incidents.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const audience = "http://127.0.0.1/verax-test";
const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "policy", "default.json");
const UNTIL = Date.now() + 30 * 86_400_000;
const RETRY_MS = 150;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Served = { isError: boolean; text: string };
type Alarm = { payload: Record<string, unknown>; sig: string };

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

async function withBody(
  alarmWebhookUrl: string,
  run: (b: {
    state: string;
    port: () => number;
    put: (id: string, fact: string) => Promise<Served>;
    get: (id: string) => Promise<Served>;
    call: (name: string, args: Record<string, unknown>) => Promise<Served>;
    haltHttp: () => Promise<{ status: number; text: string }>;
    stop: () => Promise<void>;
    start: () => Promise<void>;
    fact: (id: string) => string;
  }) => Promise<void>,
): Promise<void> {
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1h-"));
  const issuer = await startDevIssuer(0, audience);
  const token = await issuer.sign({ scope: "verax:read verax:memory", sub: "agent-a" });
  const operator = await issuer.sign({ scope: "verax:audit", sub: "operator-h" });
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
    port: () => {
      assert.ok(server, "body is stopped");
      return (server.address() as { port: number }).port;
    },
    fact: (id: string) => `fact-${id}-${tag}`,
    put: (id: string, fact: string) =>
      call("memory.put", { id, body: { fact }, source: { uri: `file://src-${id}-${tag}`, retrievedAtMs: 1 }, validUntilMs: UNTIL }),
    get: (id: string) => call("memory.get", { id }),
    call,
    haltHttp: async () => {
      assert.ok(server, "body is stopped");
      const port = (server.address() as { port: number }).port;
      const res = await fetch(`http://127.0.0.1:${port}/api/halt`, {
        method: "POST",
        headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
        body: "{}",
      });
      return { status: res.status, text: await res.text() };
    },
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
  if (!existsSync(dir)) return out;
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

function occupyAsFolder(path: string): void {
  rmSync(path, { recursive: true, force: true });
  mkdirSync(path, { recursive: true });
}

function failId(): never {
  throw new Error("uuid-unavailable");
}

function failBytes(_size: number): never {
  throw new Error("bytes-unavailable");
}

function uuidFromHex(hex: string): string {
  const h = hex.toLowerCase().replace(/[^0-9a-f]/g, "").padEnd(32, "0").slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

describe("black box P1-h: process halt, honest operator, identified alarm", { concurrency: 1 }, () => {
  it("H1: folder at halted plus an integrity error denies a non-memory.get tool", async () => {
    let rx: Awaited<ReturnType<typeof receiver>> | undefined;
    try {
      rx = await receiver();
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        occupyAsFolder(join(b.state, "halted"));
        await b.start();
        const first = await b.get("n3");
        assert.equal(first.isError, true);
        assert.match(first.text, /memory-integrity-mismatch/, `integrity path: ${first.text.slice(0, 160)}`);
        const other = await b.call("audit.explain", { ref: "n1" });
        assert.equal(other.isError, true, other.text);
        assert.match(other.text, /denied:halted/, `non-memory tool after blocked switch: ${other.text.slice(0, 160)}`);
      });
    } finally {
      await rx?.close();
    }
  });

  it("H2: the same blocked switch makes CLI and HTTP halt refuse to say halted", async () => {
    let rx: Awaited<ReturnType<typeof receiver>> | undefined;
    try {
      rx = await receiver();
      await withBody(rx.url, async (b) => {
        occupyAsFolder(join(b.state, "halted"));
        let err = "";
        const code = runHalt(b.state, (s) => {
          err += s;
        });
        assert.notEqual(code, 0, `CLI halt exit ${code}, stderr ${err.slice(0, 160)}`);
        assert.doesNotMatch(err, /(?:^|\n)halted(?:\n|$)/, `CLI claimed success: ${err.slice(0, 160)}`);
        const http = await b.haltHttp();
        assert.ok(http.status >= 500 && http.status <= 599, `HTTP halt status ${http.status}: ${http.text.slice(0, 160)}`);
        assert.doesNotMatch(http.text, /(?:^|\n)halted(?:\n|$)/);
        assert.doesNotMatch(http.text, /"halted"\s*:\s*true/);
      });
    } finally {
      await rx?.close();
    }
  });

  it("H3: identity failure still allocates a halt event id", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const opts = {
      observedAt: 1_700_000_000_000,
      triggerCode: "memory-integrity-mismatch",
      publicKeyPem,
    };
    try {
      const eventId = incidentEventIdFrom(opts, { randomUUID: failId, randomBytes: failBytes });
      assert.match(eventId, UUID_RE);
      const keyId = recordKeyId(publicKeyPem);
      const expected = uuidFromHex(
        createHash("sha256").update(`${opts.observedAt}\0${opts.triggerCode}\0${keyId}`, "utf8").digest("hex"),
      );
      assert.equal(eventId, expected);
      assert.equal(incidentEventIdFrom(opts, { randomUUID: failId, randomBytes: failBytes }), eventId);
      const lastResort = incidentEventIdFrom(
        { observedAt: 42, triggerCode: "memory-integrity-mismatch", publicKeyPem: "not-a-key" },
        { randomUUID: failId, randomBytes: failBytes },
      );
      assert.match(lastResort, UUID_RE);
      assert.equal(
        lastResort,
        uuidFromHex(createHash("sha256").update("42", "utf8").digest("hex")),
      );
    } finally {
      // No receiver, body, or timer is opened on this path.
    }
  });
});
