// P1-c: event identity before halt, pending outbox retry, torn history,
// ledger cleanup on open, integrity tag, and outbox path bounds.
import { strict as assert } from "node:assert";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
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
import { verifyControlSignatures } from "../packages/body/src/control-signature.ts";
import { INCIDENT_BY } from "../packages/body/src/incidents.ts";
import { listen } from "../packages/body/src/server.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";
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
  const state = mkdtempSync(join(tmpdir(), "verax-bbp1c-"));
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

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function openError(message: unknown): string {
  return message instanceof Error ? message.message : String(message);
}

describe("black box P1-c", () => {
  it("C1: halt switch without a history line still delivers the same alarm on reopen", async () => {
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
      writeFileSync(join(b.state, "halt-history.jsonl"), "", { encoding: "utf8", mode: 0o600 });
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
        assert.ok(await until(() => got.length >= 1, 8000), "alarm was not delivered after history was cut");
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });

  it("C2: a blocked outbox becomes a pending incident and delivers without a restart", async () => {
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
        rmSync(join(b.state, ALARM_OUTBOX_RECORD), { recursive: true, force: true });
        assert.ok(await until(() => rx.got.length >= 1, 8000), "alarm was not delivered after the folder was removed");
        assert.equal(typeof rx.got[0]?.payload.eventId, "string");
      });
    } finally {
      await rx.close();
    }
  });

  it("C3: a torn history tail does not swallow the delivery record", async () => {
    const dead = await receiver();
    const url = dead.url;
    await dead.close();
    await withBody(url, async (b) => {
      await b.stop();
      tamper(b.state, b.fact("n3"));
      await b.start();
      await b.get("n3");
      await b.stop();
      writeFileSync(join(b.state, ALARM_HISTORY), '{"eventId":"torn', { encoding: "utf8", mode: 0o600 });
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
        assert.ok(await until(() => got.length >= 1, 8000), "alarm was not delivered after the torn tail");
        const firstId = got[0]!.payload.eventId;
        await b.stop();
        await b.start();
        await new Promise((res) => setTimeout(res, RETRY_MS * 4));
        assert.equal(got.length, 1, "delivered event was sent again after reopen");
        assert.equal(got[0]!.payload.eventId, firstId);
      } finally {
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });

  it("C4: an unreadable alarm history on open does not leak ledger-locked", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1c-c4-"));
    const keys = testKeys();
    writeFileSync(join(state, "halted"), "", { encoding: "utf8", mode: 0o600 });
    writeFileSync(
      join(state, "halt-history.jsonl"),
      `${JSON.stringify({
        action: "halt",
        atMs: 1,
        by: INCIDENT_BY,
        via: "integrity",
        eventId: randomUUID(),
        triggerCode: "memory-integrity-mismatch",
      })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    mkdirSync(join(state, ALARM_HISTORY));
    const opts = {
      stateDir: state,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      alarmWebhookUrl: "http://127.0.0.1:9/alarm",
    };
    const first = ((): string | null => {
      try {
        const services = createBodyServices(opts);
        void services.stopAlarms();
        services.ledger.close();
        return null;
      } catch (err) {
        return openError(err);
      }
    })();
    const second = ((): string | null => {
      try {
        const services = createBodyServices(opts);
        void services.stopAlarms();
        services.ledger.close();
        return null;
      } catch (err) {
        return openError(err);
      }
    })();
    try {
      if (first !== null) assert.doesNotMatch(first, /ledger-locked/);
      if (second !== null) assert.doesNotMatch(second, /ledger-locked/);
    } finally {
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("C5: via:integrity is counted only for an automatic halt; a resume is failed", async () => {
    const rx = await receiver();
    try {
      await withBody(rx.url, async (b) => {
        await b.stop();
        tamper(b.state, b.fact("n3"));
        await b.start();
        await b.get("n3");
        const next = await b.get("n2");
        assert.match(next.text, /denied:halted/);
        writeFileSync(
          join(b.state, "halt-history.jsonl"),
          `${readFileSync(join(b.state, "halt-history.jsonl"), "utf8").trimEnd()}\n${JSON.stringify({
            action: "resume",
            atMs: Date.now(),
            by: "attacker",
            via: "integrity",
          })}\n`,
          { encoding: "utf8", mode: 0o600 },
        );
        await b.get("n1");
        const report = await verifyControlSignatures(b.state);
        assert.ok((report.integrity ?? 0) >= 1, `integrity counter missing: ${report.line}`);
        assert.ok(report.signedFailed >= 1, `forged integrity resume was not failed: ${report.line}`);
        assert.match(report.line, /integrity /);
      });
    } finally {
      await rx.close();
    }
  });

  it("C6: a history eventId that walks out of the outbox is not written", async () => {
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1c-c6-"));
    const keys = testKeys();
    const evilId = "../../evil";
    writeFileSync(join(state, "halted"), "", { encoding: "utf8", mode: 0o600 });
    writeFileSync(
      join(state, "halt-history.jsonl"),
      `${JSON.stringify({
        action: "halt",
        atMs: 1,
        by: INCIDENT_BY,
        via: "integrity",
        eventId: evilId,
        triggerCode: "memory-integrity-mismatch",
      })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    writeFileSync(join(state, "incident.json"), `${JSON.stringify({ eventId: evilId, triggerCode: "memory-integrity-mismatch", observedAt: 1 })}\n`);
    const outside = [join(state, "..", "evil"), join(state, "..", "evil.json"), join(state, "evil"), join(state, "evil.json")];
    try {
      assert.throws(() => writeAlarmOutbox(state, { payload: { eventId: evilId }, sig: "test" }), /alarm-event-id-invalid|alarm-outbox-path-escape/);
      for (const path of outside) assert.equal(existsSync(path), false, path);
      const services = createBodyServices({
        stateDir: state,
        policyFile,
        recordSigner: keys,
        effectSigner: keys,
        alarmWebhookUrl: "http://127.0.0.1:9/alarm",
      });
      try {
        await services.stopAlarms();
        services.ledger.close();
      } finally {
        for (const path of outside) assert.equal(existsSync(path), false, path);
      }
    } finally {
      rmSync(state, { recursive: true, force: true });
    }
  });
});
