// P1-f: halt is unconditional; each pending event keeps its own record;
// resume uses the same verify/re-sign path and will not finish if the
// pending mark cannot be written.
import { strict as assert } from "node:assert";
import { createPublicKey, randomBytes, verify } from "node:crypto";
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
import { canonical } from "@cedulon/core";

import { ALARM_HISTORY, ALARM_OUTBOX_DIR, ALARM_OUTBOX_RECORD } from "../packages/body/src/alarm-outbox.ts";
import { resumeBody } from "../packages/body/src/halt.ts";
import { INCIDENTS_DIR, INCIDENT_RECORD } from "../packages/body/src/incidents.ts";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const audience = "http://127.0.0.1/verax-test";
const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "policy", "default.json");
const UNTIL = Date.now() + 30 * 86_400_000;
const RETRY_MS = 150;

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
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1f-"));
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

function lastHaltEventId(state: string): string {
  const raw = readFileSync(join(state, "halt-history.jsonl"), "utf8");
  const lines = raw.split("\n").filter((line) => line.trim() !== "");
  for (let i = lines.length - 1; i >= 0; i--) {
    const row = JSON.parse(lines[i] ?? "{}") as { action?: string; eventId?: string };
    if (row.action === "halt" && typeof row.eventId === "string") return row.eventId;
  }
  throw new Error("no halt eventId");
}

function occupyPendingMark(state: string, eventId: string): string {
  const path = join(state, INCIDENTS_DIR, `${eventId}.json`);
  rmSync(path, { force: true });
  mkdirSync(path, { recursive: true });
  return path;
}

function corruptStoredEnvelopes(state: string): string {
  const paths = [join(state, INCIDENT_RECORD)];
  const dir = join(state, INCIDENTS_DIR);
  if (existsSync(dir) && statSync(dir).isDirectory()) {
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".json")) continue;
      const p = join(dir, name);
      if (statSync(p).isFile()) paths.push(p);
    }
  }
  let eventId = "";
  for (const path of paths) {
    if (!existsSync(path) || !statSync(path).isFile()) continue;
    const rec = JSON.parse(readFileSync(path, "utf8")) as {
      eventId?: string;
      envelope?: { payload: Record<string, unknown>; sig: string };
    };
    if (typeof rec.eventId === "string") eventId = rec.eventId;
    assert.ok(rec.envelope && typeof rec.envelope.sig === "string", `no envelope in ${path}`);
    rec.envelope.sig = "AA==";
    writeFileSync(path, `${JSON.stringify(rec)}\n`, { encoding: "utf8", mode: 0o600 });
  }
  assert.equal(typeof eventId, "string");
  assert.notEqual(eventId, "");
  return eventId;
}

function checkAlarm(state: string, a: Alarm, eventId: string): void {
  const pub = createPublicKey(readFileSync(join(state, "keys", "record.public.pem"), "utf8"));
  assert.ok(verify(null, Buffer.from(canonical(a.payload), "utf8"), pub, Buffer.from(a.sig, "base64")), "alarm signature does not verify");
  assert.equal(a.payload.eventId, eventId);
  assert.equal(a.payload.purpose, "verax.incident.v1");
}

describe("black box P1-f: unconditional halt and per-event records", () => {
  it("F1: after resume, unreadable alarm-history plus a new integrity error still halt", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        mkdirSync(join(b.state, ALARM_OUTBOX_RECORD));
        await b.start();
        const first = await b.get("n3");
        assert.equal(first.isError, true);
        assert.match(first.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt");
        resumeBody(b.state, "test-operator", "cli");
        assert.equal(existsSync(join(b.state, "halted")), false, "resume did not clear the halt");
        rmSync(join(b.state, ALARM_HISTORY), { recursive: true, force: true });
        mkdirSync(join(b.state, ALARM_HISTORY));
        tamper(b.state, b.fact("n2"));
        const second = await b.get("n2");
        assert.equal(second.isError, true);
        assert.match(second.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "new integrity error did not halt after unreadable history");
        const next = await b.get("n1");
        assert.match(next.text, /denied:halted/, `next call after the failure: ${next.text.slice(0, 120)}`);
      });
    } finally {
      await rx.close();
    }
  });

  it("F2: two blocked events survive resume and both deliver with distinct ids", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        mkdirSync(join(b.state, ALARM_OUTBOX_RECORD));
        await b.start();
        const first = await b.get("n3");
        assert.equal(first.isError, true);
        assert.match(first.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt");
        const firstId = lastHaltEventId(b.state);
        resumeBody(b.state, "test-operator", "cli");
        assert.equal(existsSync(join(b.state, "halted")), false, "resume did not clear the halt");
        tamper(b.state, b.fact("n2"));
        const second = await b.get("n2");
        assert.equal(second.isError, true);
        assert.match(second.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "second failure did not halt");
        const secondId = lastHaltEventId(b.state);
        assert.notEqual(secondId, firstId, "second incident reused the first event id");
        await new Promise((res) => setTimeout(res, RETRY_MS * 3));
        assert.equal(rx.got.length, 0, "alarm was sent while the outbox write was blocked");
        rmSync(join(b.state, ALARM_OUTBOX_RECORD), { recursive: true, force: true });
        assert.ok(await until(() => rx.got.length >= 2, 8000), `both alarms were not delivered (got ${rx.got.length})`);
        const ids = new Set(rx.got.map((a) => a.payload.eventId));
        assert.ok(ids.has(firstId), "first event was not delivered");
        assert.ok(ids.has(secondId), "second event was not delivered");
        assert.equal(ids.size >= 2, true, "delivered alarms did not keep distinct ids");
      });
    } finally {
      await rx.close();
    }
  });

  it("F3: resume fails when the pending mark target is a folder; it succeeds after the folder is removed", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        mkdirSync(join(b.state, ALARM_OUTBOX_RECORD));
        await b.start();
        const r = await b.get("n3");
        assert.equal(r.isError, true);
        assert.match(r.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt");
        const eventId = lastHaltEventId(b.state);
        const blocked = occupyPendingMark(b.state, eventId);
        assert.throws(() => resumeBody(b.state, "test-operator", "cli"));
        assert.equal(existsSync(join(b.state, "halted")), true, "resume cleared the halt while the pending mark was blocked");
        rmSync(blocked, { recursive: true, force: true });
        resumeBody(b.state, "test-operator", "cli");
        assert.equal(existsSync(join(b.state, "halted")), false, "resume did not clear the halt after the folder was removed");
        rmSync(join(b.state, ALARM_OUTBOX_RECORD), { recursive: true, force: true });
        assert.ok(await until(() => rx.got.length >= 1, 8000), "alarm was not delivered after resume and unblock");
        assert.equal(rx.got[0]?.payload.eventId, eventId);
      });
    } finally {
      await rx.close();
    }
  });

  it("F4: a corrupted stored envelope is re-signed on resume; reopen delivers a verifiable alarm", async () => {
    const dead = await receiver();
    const url = dead.url;
    await dead.close();
    await withBody(url, async (b) => {
      await b.stop();
      tamper(b.state, b.fact("n3"));
      await b.start();
      await b.get("n3");
      assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt");
      await b.stop();
      const eventId = corruptStoredEnvelopes(b.state);
      rmSync(join(b.state, ALARM_OUTBOX_DIR), { recursive: true, force: true });
      rmSync(join(b.state, ALARM_OUTBOX_RECORD), { force: true });
      resumeBody(b.state, "test-operator", "cli");
      assert.equal(existsSync(join(b.state, "halted")), false, "resume did not clear the halt");
      const port = Number(new URL(url).port);
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
        assert.ok(await until(() => got.length >= 1, 8000), "re-signed alarm was not delivered after resume and reopen");
        checkAlarm(b.state, got[0]!, eventId);
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });
});
