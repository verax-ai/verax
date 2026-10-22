// P1-e: halt is fail-closed on incident write errors; open completes a
// leftover record; resume keeps an undelivered alarm; a bad stored envelope
// is rejected and re-signed.
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

import { ALARM_OUTBOX_DIR, ALARM_OUTBOX_RECORD } from "../packages/body/src/alarm-outbox.ts";
import { resumeBody } from "../packages/body/src/halt.ts";
import { INCIDENT_RECORD } from "../packages/body/src/incidents.ts";
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
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1e-"));
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

function checkAlarm(state: string, a: Alarm, eventId: string): void {
  const pub = createPublicKey(readFileSync(join(state, "keys", "record.public.pem"), "utf8"));
  assert.ok(verify(null, Buffer.from(canonical(a.payload), "utf8"), pub, Buffer.from(a.sig, "base64")), "alarm signature does not verify");
  assert.equal(a.payload.eventId, eventId);
  assert.equal(a.payload.purpose, "verax.incident.v1");
}

describe("black box P1-e: fail-closed halt and pending delivery", () => {
  it("E1: incident.json occupied by a folder still halts; later calls are denied; removing the folder delivers the alarm", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        mkdirSync(join(b.state, INCIDENT_RECORD));
        await b.start();
        const r = await b.get("n3");
        assert.equal(r.isError, true);
        assert.match(r.text, /memory-integrity-mismatch/);
        assert.equal(existsSync(join(b.state, "halted")), true, "body did not halt while incident.json was a folder");
        const next = await b.get("n2");
        assert.match(next.text, /denied:halted/, `next call after the failure: ${next.text.slice(0, 120)}`);
        rmSync(join(b.state, INCIDENT_RECORD), { recursive: true, force: true });
        assert.ok(await until(() => rx.got.length >= 1, 8000), "alarm was not delivered after the folder was removed");
        assert.equal(typeof rx.got[0]?.payload.eventId, "string");
      });
    } finally {
      await rx.close();
    }
  });

  it("E2: an open incident and outbox without halted is completed on open, same halt, alarm delivered", async () => {
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
      assert.equal(existsSync(join(b.state, INCIDENT_RECORD)), true, "incident record missing");
      const outbox = join(b.state, ALARM_OUTBOX_DIR);
      const pending = existsSync(outbox) ? readdirSync(outbox).filter((n) => n.endsWith(".json")) : [];
      assert.equal(pending.length, 1, `one pending alarm, found ${pending.join(",")}`);
      rmSync(join(b.state, "halted"), { force: true });
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
        const next = await b.get("n2");
        assert.match(next.text, /denied:halted/, `after open with leftover incident: ${next.text.slice(0, 120)}`);
        assert.equal(existsSync(join(b.state, "halted")), true, "open did not complete the halt");
        assert.ok(await until(() => got.length >= 1, 8000), "alarm was not delivered after the leftover halt was completed");
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });

  it("E3: resume while the outbox is blocked still delivers the alarm after the block lifts", async () => {
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
        await new Promise((res) => setTimeout(res, RETRY_MS * 3));
        assert.equal(rx.got.length, 0, "alarm was sent while the outbox write was blocked");
        resumeBody(b.state, "test-operator", "cli");
        assert.equal(existsSync(join(b.state, "halted")), false, "resume did not clear the halt");
        const ok = await b.get("n1");
        assert.equal(ok.isError, false, `body stayed halted after resume: ${ok.text.slice(0, 120)}`);
        rmSync(join(b.state, ALARM_OUTBOX_RECORD), { recursive: true, force: true });
        assert.ok(await until(() => rx.got.length >= 1, 8000), "alarm was not delivered after resume and unblock");
        assert.equal(existsSync(join(b.state, "halted")), false, "delivery re-halted a resumed body");
        assert.equal(typeof rx.got[0]?.payload.eventId, "string");
      });
    } finally {
      await rx.close();
    }
  });

  it("E4: a corrupted stored envelope is re-signed; the delivered alarm verifies under the record key", async () => {
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
      const incidentPath = join(b.state, INCIDENT_RECORD);
      const rec = JSON.parse(readFileSync(incidentPath, "utf8")) as {
        eventId: string;
        envelope?: { payload: Record<string, unknown>; sig: string };
      };
      assert.equal(typeof rec.eventId, "string");
      assert.ok(rec.envelope && typeof rec.envelope.sig === "string", "incident record has no envelope");
      rec.envelope.sig = "AA==";
      writeFileSync(incidentPath, `${JSON.stringify(rec)}\n`, { encoding: "utf8", mode: 0o600 });
      rmSync(join(b.state, ALARM_OUTBOX_DIR), { recursive: true, force: true });
      rmSync(join(b.state, ALARM_OUTBOX_RECORD), { force: true });
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
        assert.ok(await until(() => got.length >= 1, 8000), "re-signed alarm was not delivered");
        checkAlarm(b.state, got[0]!, rec.eventId);
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });
});
