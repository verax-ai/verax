// Durability of P1 halt/alarm: outbox write failure, sender errors, delivery
// record before delete, and via: "integrity" on the signed control line.
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
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

import { ALARM_HISTORY, ALARM_OUTBOX_DIR, ALARM_OUTBOX_RECORD, writeAlarmOutbox } from "../packages/body/src/alarm-outbox.ts";
import { startAlarmDelivery } from "../packages/body/src/alarm-webhook.ts";
import { resumeBody } from "../packages/body/src/halt.ts";
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
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1d-"));
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

function haltVia(state: string): string | undefined {
  const raw = readFileSync(join(state, "halt-history.jsonl"), "utf8");
  const lines = raw.split("\n").filter((line) => line.trim() !== "");
  const last = JSON.parse(lines[lines.length - 1] ?? "{}") as { via?: string };
  return last.via;
}

function controlVias(state: string): string[] {
  const inputs = new Map<string, { via?: string }>();
  for (const line of readFileSync(join(state, "inputs.jsonl"), "utf8").split("\n")) {
    if (line.trim() === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: { control?: { via?: string } } };
    if (typeof row.ref === "string" && row.inputs?.control) inputs.set(row.ref, row.inputs.control);
  }
  const vias: string[] = [];
  for (const line of readFileSync(join(state, "decisions.jsonl"), "utf8").split("\n")) {
    if (line.trim() === "") continue;
    const rec = JSON.parse(line) as { claims?: { subject?: string; ref?: string } };
    if (rec.claims?.subject !== "verax.halt") continue;
    const via = inputs.get(rec.claims.ref ?? "")?.via;
    if (via) vias.push(via);
  }
  return vias;
}

describe("black box P1 durability", () => {
  // Gate test: after an operator resume, a new integrity failure is a new incident and must reach the webhook.
  it("D6: a second integrity failure after resume sends a second alarm with a new event id", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        await b.start();
        await b.get("n3");
        assert.ok(await until(() => rx.got.length >= 1, 5000), "first alarm not delivered");
        const firstId = rx.got[0]!.payload.eventId;
        await b.stop();
        resumeBody(b.state, "test-operator", "cli");
        assert.equal(existsSync(join(b.state, "halted")), false, "resume did not clear the halt");
        tamper(b.state, b.fact("n2"));
        await b.start();
        const r = await b.get("n2");
        assert.equal(r.isError, true);
        assert.equal(existsSync(join(b.state, "halted")), true, "second failure did not halt");
        assert.ok(await until(() => rx.got.length >= 2, 5000), `second alarm not delivered (got ${rx.got.length})`);
        assert.notEqual(rx.got[1]!.payload.eventId, firstId, "second incident reused the first event id");
      });
    } finally {
      await rx.close();
    }
  });

  // Gate test: the halt is on disk but the outbox entry is gone (a crash between the two writes). The open must
  // rebuild the incident with the same event id and deliver it.
  it("D5: an integrity halt whose outbox entry was lost is completed on the next open, same event id", async () => {
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
      const outbox = join(b.state, ALARM_OUTBOX_DIR);
      const pending = readdirSync(outbox).filter((n) => n.endsWith(".json"));
      assert.equal(pending.length, 1, `one pending alarm, found ${pending.join(",")}`);
      const eventId = (JSON.parse(readFileSync(join(outbox, pending[0]!), "utf8")) as Alarm).payload.eventId;
      rmSync(outbox, { recursive: true, force: true });
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
        assert.ok(await until(() => got.length >= 1, 8000), "the lost alarm was not rebuilt and delivered");
        assert.equal(got[0]!.payload.eventId, eventId, "the rebuilt alarm must keep the halt's event id");
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });

  it("D1: outbox path occupied by a folder still halts; restart delivers the same event", async () => {
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
        await b.stop();
        rmSync(join(b.state, ALARM_OUTBOX_RECORD), { recursive: true, force: true });
        await b.start();
        assert.ok(await until(() => rx.got.length >= 1, 8000), "alarm was not delivered after the folder was removed");
        assert.equal(typeof rx.got[0]?.payload.eventId, "string");
      });
    } finally {
      await rx.close();
    }
  });

  it("D2: unreadable outbox list does not crash the sender; the next tick retries", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1d-d2-"));
    const rx = await receiver();
    const rejections: unknown[] = [];
    const onRej = (reason: unknown) => {
      rejections.push(reason);
    };
    process.on("unhandledRejection", onRej);
    try {
      writeFileSync(join(state, ALARM_OUTBOX_DIR), "not-a-directory");
      const stop = startAlarmDelivery({ stateDir: state, url: rx.url, retryMs: RETRY_MS });
      await new Promise((res) => setTimeout(res, RETRY_MS * 4));
      assert.equal(rejections.length, 0, `unhandled rejection: ${String(rejections[0])}`);
      assert.equal(rx.got.length, 0);
      await stop();
    } finally {
      process.off("unhandledRejection", onRej);
      await rx.close();
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("D3: a delivery record with the outbox file still present is not sent again", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1d-d3-"));
    const rx = await receiver();
    try {
      const envelope = {
        payload: { eventId: "already-delivered", purpose: "verax.incident.v1", triggerCode: "memory-integrity-mismatch" },
        sig: "test-sig",
      };
      writeAlarmOutbox(state, envelope);
      writeFileSync(
        join(state, ALARM_HISTORY),
        `${JSON.stringify({ eventId: "already-delivered", deliveredAtMs: 1, triggerCode: "memory-integrity-mismatch" })}\n`,
        { encoding: "utf8", mode: 0o600 },
      );
      const stop = startAlarmDelivery({ stateDir: state, url: rx.url, retryMs: RETRY_MS });
      await new Promise((res) => setTimeout(res, RETRY_MS * 4));
      assert.equal(rx.attempts(), 0, "a delivered eventId was posted again");
      assert.equal(rx.got.length, 0);
      await stop();
    } finally {
      await rx.close();
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("D4: automatic halt's signed control line keeps via: integrity", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        await b.start();
        await b.get("n3");
        const next = await b.get("n2");
        assert.match(next.text, /denied:halted/);
        assert.equal(haltVia(b.state), "integrity");
        assert.ok(controlVias(b.state).includes("integrity"), `control vias: ${controlVias(b.state).join(",")}`);
      });
    } finally {
      await rx.close();
    }
  });
});
