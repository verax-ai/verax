import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const audience = "http://127.0.0.1/verax-test";

type RpcBody = {
  result?: { content?: { type: string; text?: string }[]; isError?: boolean };
};

function toolText(body: RpcBody): string {
  return body.result?.content?.[0]?.text ?? "";
}

function toolJson(body: RpcBody): Record<string, unknown> {
  const text = toolText(body);
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { raw: text };
  }
}

/** Outbox rows across tenants; zero when nothing was ever written (no tenant directory yet). */
function outboxCount(state: string): number {
  let tenants: string[];
  try {
    tenants = readdirSync(join(state, "tenants"));
  } catch {
    return 0;
  }
  let n = 0;
  for (const t of tenants) {
    try {
      n += readJsonl(join(state, "tenants", t, "outbox.jsonl")).length;
    } catch {
      // no outbox for this tenant
    }
  }
  return n;
}

function readJsonl(path: string): Record<string, unknown>[] {
  try {
    return readFileSync(path, "utf8")
      .trim()
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

function decisionRows(state: string): { claims: { decision: string; reasonCode: string; ref?: string; subject?: string } }[] {
  return readJsonl(join(state, "decisions.jsonl")) as {
    claims: { decision: string; reasonCode: string; ref?: string; subject?: string };
  }[];
}

async function withBody(
  doc: unknown,
  run: (ctx: {
    rpc: (tool: string, args: Record<string, unknown>, tok?: string) => Promise<{ status: number; body: RpcBody }>;
    url: string;
    token: string;
    state: string;
    issuer: Awaited<ReturnType<typeof startDevIssuer>>;
    restart: (nextDoc: unknown) => Promise<void>;
  }) => Promise<void>,
): Promise<void> {
  const state = mkdtempSync(join(tmpdir(), "verax-concurrency-"));
  const policyFile = join(state, "policy.json");
  writeFileSync(policyFile, JSON.stringify(doc));
  const issuer = await startDevIssuer(0, audience);
  let server = await listen({
    issuer: issuer.issuer,
    jwksUrl: issuer.jwksUrl,
    audience,
    stateDir: state,
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile,
    tlsTerminated: false,
  });
  const token = await issuer.sign({
    scope: "verax:read verax:memory verax:act verax:pay verax:approve verax:audit",
  });
  let id = 0;
  const rpc = async (tool: string, args: Record<string, unknown>, tok = token) => {
    const port = (server.address() as { port: number }).port;
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${tok}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: ++id,
        method: "tools/call",
        params: { name: tool, arguments: args },
      }),
    });
    return { status: res.status, body: (await res.json()) as RpcBody };
  };
  const restart = async (nextDoc: unknown) => {
    writeFileSync(policyFile, JSON.stringify(nextDoc));
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir: state,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      tlsTerminated: false,
    });
  };
  try {
    await fetch(`http://127.0.0.1:${(server.address() as { port: number }).port}/healthz`, {
      headers: { authorization: `Bearer ${token}` },
    });
    await run({
      rpc,
      get url() {
        return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      },
      token,
      state,
      issuer,
      restart,
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await issuer.close();
  }
}

const readRule = { id: "read", tool: "memory.get", requires: ["verax:read"], text: "read" };
const spendRule = (dailyMaxMinor: number) => ({
  id: "spend",
  tool: "spend",
  requires: ["verax:pay"],
  text: "approval",
  mode: "approve",
  spend: { maxAmountMinor: 100, currency: "USD", payees: ["test"], dailyMaxMinor },
});

describe("concurrency audit", () => {
  it("V-01 eight parallel reads under ratePerMinute 1 and dailyMax 1 write one allow", async () => {
    await withBody(
      { version: 1, default: "deny", limits: { ratePerMinute: 1, dailyMax: 1 }, rules: [readRule] },
      async ({ rpc, state }) => {
        await Promise.all(Array.from({ length: 8 }, (_, i) => rpc("memory.get", { id: `x${i}` })));
        const rows = decisionRows(state);
        const allow = rows.filter((r) => r.claims.decision === "allow");
        const denied = rows.filter(
          (r) => r.claims.reasonCode === "rate-limited" || r.claims.reasonCode === "daily-limited",
        );
        assert.equal(allow.length, 1);
        assert.equal(denied.length, 7);
        assert.equal(rows.length, 8);
      },
    );
  });

  it("V-02 eight parallel message.send calls with the same _ref write one outbox row", async () => {
    await withBody(
      {
        version: 1,
        default: "deny",
        egress: ["example.invalid"],
        rules: [{ id: "send", tool: "message.send", requires: ["verax:act"], text: "send", egress: true }],
      },
      async ({ rpc, state }) => {
        const args = { to: "audit@example.invalid", text: "LOCAL STUB ONLY", _ref: "same" };
        const results = await Promise.all(Array.from({ length: 8 }, () => rpc("message.send", args)));
        const texts = results.map((r) => toolText(r.body));
        const real = texts.filter((t) => t.includes("queued"));
        const replay = texts.filter((t) => t.startsWith("allowed:"));
        assert.equal(real.length, 1);
        assert.equal(replay.length, 7);
        const [tenant] = readdirSync(join(state, "tenants"));
        const outbox = readJsonl(join(state, "tenants", tenant!, "outbox.jsonl"));
        assert.equal(outbox.length, 1);
        const ninth = await rpc("message.send", args);
        assert.match(toolText(ninth.body), /^allowed:/);
        assert.equal(readJsonl(join(state, "tenants", tenant!, "outbox.jsonl")).length, 1);
      },
    );
  });

  it("V-03 spend budget is one pending at request time and one approval after the cap tightens", async () => {
    const open = {
      version: 1,
      default: "deny",
      rules: [spendRule(100)],
    };
    await withBody(open, async ({ rpc, state }) => {
      await Promise.all(
        Array.from({ length: 8 }, (_, i) =>
          rpc("spend", { amountMinor: 100, currency: "USD", payee: "test", reference: String(i) }),
        ),
      );
      const pending = readJsonl(join(state, "approvals.jsonl")).filter((row) => row.status === "pending");
      const denied = decisionRows(state).filter((r) => r.claims.reasonCode === "spend-daily");
      assert.equal(pending.length, 1, "request-time lock must keep one pending");
      assert.equal(denied.length, 7);
    });

    const wide = { version: 1, default: "deny", rules: [spendRule(200)] };
    const tight = { version: 1, default: "deny", rules: [spendRule(150)] };
    // `url` is read at call time: the restart below moves the body to a new port.
    await withBody(wide, async (ctx) => {
      const { rpc, state, token, restart } = ctx;
      await rpc("spend", { amountMinor: 100, currency: "USD", payee: "test", reference: "one" });
      await rpc("spend", { amountMinor: 100, currency: "USD", payee: "test", reference: "two" });
      const pending = readJsonl(join(state, "approvals.jsonl")).filter((row) => row.status === "pending");
      assert.equal(pending.length, 2);
      await restart(tight);
      const approve = async (row: Record<string, unknown>) => {
        const r = await fetch(`${ctx.url}/api/approve`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ ref: row.ref, requestHash: row.requestHash }),
        });
        return { status: r.status, body: (await r.json()) as { error?: string } };
      };
      const first = await approve(pending[0]!);
      const second = await approve(pending[1]!);
      assert.equal(first.status, 200);
      assert.equal(second.status, 409);
      assert.equal(second.body.error, "budget-exceeded");
      const after = readJsonl(join(state, "approvals.jsonl"));
      const lastByRef = new Map<string, Record<string, unknown>>();
      for (const row of after) lastByRef.set(String(row.ref), row);
      assert.equal(lastByRef.get(String(pending[0]!.ref))?.status, "approved");
      assert.equal(lastByRef.get(String(pending[1]!.ref))?.status, "pending");
    });
  });

  it("V-04 four parallel /api/approve calls leave one allow", async () => {
    await withBody({ version: 1, default: "deny", rules: [spendRule(100)] }, async ({ rpc, state, url, token }) => {
      await rpc("spend", { amountMinor: 100, currency: "USD", payee: "test", reference: "single" });
      const row = readJsonl(join(state, "approvals.jsonl"))[0]!;
      const statuses = await Promise.all(
        Array.from({ length: 4 }, async () => {
          const r = await fetch(`${url}/api/approve`, {
            method: "POST",
            headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
            body: JSON.stringify({ ref: row.ref, requestHash: row.requestHash }),
          });
          const body = (await r.json()) as { error?: string; allowRef?: string };
          return { status: r.status, body };
        }),
      );
      assert.equal(statuses.filter((s) => s.status === 200).length, 1);
      const lost = statuses.filter((s) => s.status === 409);
      assert.equal(lost.length, 3);
      assert.ok(lost.every((s) => s.body.error === "already-resolved" && typeof s.body.allowRef === "string"));
      const allows = decisionRows(state).filter((r) => r.claims.reasonCode === "approved-by-operator");
      assert.equal(allows.length, 1);
      const effects = readJsonl(join(state, "effects.jsonl"));
      assert.equal(
        effects.filter((e) => {
          const row = e.row as { effectClass?: string } | undefined;
          return row?.effectClass === "spend";
        }).length,
        1,
      );
    });
  });

  it("V-05 memory.get returns this tenant's own record before checking other tenants", async () => {
    await withBody(
      {
        version: 1,
        default: "deny",
        rules: [readRule, { id: "write", tool: "memory.put", requires: ["verax:memory"], text: "write" }],
      },
      async ({ rpc, issuer }) => {
        const tokenB = await issuer.sign({ sub: "brain-2", scope: "verax:read verax:memory" });
        const tokenC = await issuer.sign({ sub: "brain-3", scope: "verax:read verax:memory" });
        const until = Date.now() + 86_400_000;
        const putA = await rpc("memory.put", {
          id: "shared-name",
          body: "from-a",
          source: { system: "audit" },
          validFromMs: 0,
          validUntilMs: until,
        });
        const putB = await rpc(
          "memory.put",
          {
            id: "shared-name",
            body: "from-b",
            source: { system: "audit" },
            validFromMs: 0,
            validUntilMs: until,
          },
          tokenB,
        );
        const hashA = toolJson(putA.body).versionHash;
        const hashB = toolJson(putB.body).versionHash;
        assert.equal(typeof hashA, "string");
        assert.equal(typeof hashB, "string");
        assert.notEqual(hashA, hashB);
        const gotA = toolJson((await rpc("memory.get", { id: "shared-name" })).body);
        const gotB = toolJson((await rpc("memory.get", { id: "shared-name" }, tokenB)).body);
        const gotC = await rpc("memory.get", { id: "shared-name" }, tokenC);
        assert.equal(gotA.versionHash, hashA);
        assert.equal(gotA.body, "from-a");
        assert.equal(gotB.versionHash, hashB);
        assert.equal(gotB.body, "from-b");
        assert.equal(gotC.body.result?.isError, true);
        assert.equal(toolJson(gotC.body).error, "not-found");
      },
    );
  });

  it("V-06 retry of an approved send re-evaluates current scopes", async () => {
    await withBody(
      {
        version: 1,
        default: "deny",
        egress: ["example.invalid"],
        rules: [
          {
            id: "send",
            tool: "message.send",
            requires: ["verax:act"],
            text: "approve send",
            mode: "approve",
            egress: true,
          },
        ],
      },
      async ({ rpc, state, url, token, issuer }) => {
        const args = { to: "audit@example.invalid", text: "LOCAL STUB ONLY", _ref: "approved-send" };
        await rpc("message.send", args);
        const row = readJsonl(join(state, "approvals.jsonl"))[0]!;
        const approved = await fetch(`${url}/api/approve`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ ref: row.ref, requestHash: row.requestHash }),
        });
        assert.equal(approved.status, 200);
        const reduced = await issuer.sign({ scope: "", sub: "brain-1" });
        const retry = await rpc("message.send", args, reduced);
        assert.equal(retry.body.result?.isError, true);
        assert.match(toolText(retry.body), /denied:scope-missing:/);
        assert.equal(outboxCount(state), 0);
        const scoped = await rpc("message.send", args);
        assert.equal(scoped.body.result?.isError, false);
        assert.equal(toolJson(scoped.body).queued, true);
        assert.equal(outboxCount(state), 1);
      },
    );
  });
});
