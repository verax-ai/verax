// GET /api/agents answers one row per agent: what each did in the window
// (decisions, allowed, denied, deferred), what is waiting on an operator for
// it, when it last acted, and what the roster says about it. A company has
// hundreds of agents; the panel's status tab draws this list instead of
// asking an operator to read it off the records. The window is read from
// the end of the ledger like /api/ledger, so the answer costs the window.

import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import type { DecisionKind, SignedDecisionRecord } from "@cedulon/core";

import { listen } from "../packages/body/src/server.ts";
import { approvalsLogFor } from "../packages/proxy/src/approvals.ts";
import { sha256Canonical } from "../packages/proxy/src/hash.ts";
import { inputsLogFor } from "../packages/proxy/src/inputs.ts";
import { FileLedger, ledgerFs } from "../packages/proxy/src/ledger.ts";
import type { DecisionInputs } from "../packages/proxy/src/types.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function inputsOf(brain: string, i: number): DecisionInputs {
  return {
    principal: { brain, scopes: ["verax:read"] },
    inputs: [{ id: `k${i}`, versionHash: "00".repeat(32), validFromMs: 0, validUntilMs: 9_000_000_000_000 }],
  };
}

function record(i: number, brain: string, decision: DecisionKind, timestampMs: number, prev: string | null): SignedDecisionRecord {
  return {
    claims: {
      decider: "verax-proxy",
      subject: decision === "defer" ? "spend" : "memory.get",
      requestHash: "00".repeat(32),
      policyHash: "00".repeat(32),
      inputsHash: sha256Canonical(inputsOf(brain, i)),
      decision,
      reasonCode: decision === "allow" ? "allow" : decision === "deny" ? "scope-missing" : "approval-required",
      ref: `r-${i}`,
      effectClass: "memory.get",
      effectHash: "11".repeat(32),
      timestampMs,
      nonce: `n-${i}`,
      prevRecordHash: prev,
    },
    publicKeyPem: "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----\n",
    encoding: "cose",
    coseHex: i.toString(16).padStart(128, "0"),
  };
}

type Fixture = { brain: string; decision: DecisionKind; atMs: number }[];

/** The ledger, its inputs and one pending approval, written without fsync. */
async function buildLedger(dir: string, rows: Fixture, pendingFor: { brain: string; ref: string }): Promise<void> {
  const realOpen = ledgerFs.open;
  ledgerFs.open = (async (path: string, flags: string) => {
    const fh = await open(path, flags);
    return { write: (data: string) => fh.write(data), sync: async () => undefined, close: () => fh.close() };
  }) as unknown as typeof open;
  const ledger = new FileLedger(dir);
  const inputs = inputsLogFor(ledger);
  const approvals = approvalsLogFor(ledger);
  try {
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i]!;
      await inputs.append(`r-${i}`, inputsOf(row.brain, i));
      await ledger.appendDecisionChained((prev) => record(i, row.brain, row.decision, row.atMs, prev));
    }
    await approvals.append({
      ref: pendingFor.ref,
      requestHash: "cd".repeat(32),
      subject: "spend",
      args: { amountMinor: 1000, currency: "TRY", payee: "sample-merchant" },
      ruleId: "spend",
      ruleText: "A payment is held for an operator.",
      inputsSummary: { count: 0, ids: [] },
      expiresAtMs: Date.now() + DAY,
      status: "pending",
      brain: pendingFor.brain,
    });
  } finally {
    ledger.close();
    ledgerFs.open = realOpen;
  }
}

type AgentRow = {
  brain: string;
  decisions: number;
  allowed: number;
  denied: number;
  deferred: number;
  pending: number;
  lastMs: number | null;
  roster: { state: string; label: string; group: string | null } | null;
};
type AgentsAnswer = { fromMs: number; toMs: number; agents: AgentRow[]; unattributed: number };

describe("api/agents", () => {
  it("answers one row per agent for the last day, roster included, pending first", async () => {
    const now = Date.now();
    const stateDir = mkdtempSync(join(tmpdir(), "verax-agents-"));
    // Written in time order, as the proxy would: the oldest first.
    const rows: Fixture = [
      { brain: "agent-b", decision: "allow", atMs: now - 2 * DAY }, // outside the day
      { brain: "agent-a", decision: "allow", atMs: now - 60 * 60_000 },
      { brain: "agent-a", decision: "allow", atMs: now - 50 * 60_000 },
      { brain: "agent-a", decision: "deny", atMs: now - 40 * 60_000 },
      { brain: "agent-b", decision: "allow", atMs: now - 30 * 60_000 },
      { brain: "agent-b", decision: "allow", atMs: now - 20 * 60_000 },
      { brain: "agent-a", decision: "defer", atMs: now - 10 * 60_000 },
    ];
    await buildLedger(stateDir, rows, { brain: "agent-a", ref: "r-6" });
    const inventoryFile = join(stateDir, "inventory.json");
    writeFileSync(
      inventoryFile,
      JSON.stringify({
        takenAtMs: now,
        source: "fixture",
        groups: [{ id: "pc", label: "This PC" }],
        agents: [
          { id: "agent-a", label: "Agent A", groupId: "pc", kind: "worker", lastRunMs: now - 60_000, state: "live" },
          { id: "agent-c", label: "Agent C", groupId: null, kind: "cron", lastRunMs: null, state: "unmonitored" },
        ],
        orphans: [],
      }),
      "utf8",
    );
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      inventoryFile,
      tlsTerminated: false,
    });
    const bodyPort = (server.address() as { port: number }).port;
    const base = `http://127.0.0.1:${bodyPort}`;
    try {
      const anon = await fetch(`${base}/api/agents`);
      assert.equal(anon.status, 401);
      const brain = await issuer.sign({ scope: "verax:read" });
      const forbidden = await fetch(`${base}/api/agents`, { headers: { authorization: `Bearer ${brain}` } });
      assert.equal(forbidden.status, 403);

      const audit = await issuer.sign({ scope: "verax:read verax:audit" });
      const res = await fetch(`${base}/api/agents`, { headers: { authorization: `Bearer ${audit}` } });
      assert.equal(res.status, 200);
      const answer = (await res.json()) as AgentsAnswer;
      assert.equal(answer.toMs - answer.fromMs, DAY);
      assert.ok(answer.toMs >= now && answer.toMs <= Date.now());
      assert.equal(answer.unattributed, 0);
      assert.deepEqual(
        answer.agents.map((a) => a.brain),
        ["agent-a", "agent-b", "agent-c"],
      );
      const [a, b, c] = answer.agents as [AgentRow, AgentRow, AgentRow];
      assert.deepEqual(
        { ...a, lastMs: a.lastMs },
        {
          brain: "agent-a",
          decisions: 4,
          allowed: 2,
          denied: 1,
          deferred: 1,
          pending: 1,
          lastMs: now - 10 * 60_000,
          roster: { state: "live", label: "Agent A", group: "This PC" },
        },
      );
      assert.deepEqual(b, {
        brain: "agent-b",
        decisions: 2,
        allowed: 2,
        denied: 0,
        deferred: 0,
        pending: 0,
        lastMs: now - 20 * 60_000,
        roster: null,
      });
      assert.deepEqual(c, {
        brain: "agent-c",
        decisions: 0,
        allowed: 0,
        denied: 0,
        deferred: 0,
        pending: 0,
        lastMs: null,
        roster: { state: "unmonitored", label: "Agent C", group: null },
      });

      // A wider window counts the older row too.
      const wide = await fetch(`${base}/api/agents?from=${now - 3 * DAY}&to=${now + 1}`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      assert.equal(wide.status, 200);
      const wideAnswer = (await wide.json()) as AgentsAnswer;
      assert.equal(wideAnswer.agents.find((x) => x.brain === "agent-b")?.decisions, 3);

      const bad = await fetch(`${base}/api/agents?from=abc`, { headers: { authorization: `Bearer ${audit}` } });
      assert.equal(bad.status, 400);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
