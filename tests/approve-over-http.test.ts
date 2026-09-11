import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** A policy that defers the write, so there is something to approve. */
function approvePolicyFile(dir: string): string {
  const path = join(dir, "approve-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "put-approve",
          tool: "memory.put",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Writes need operator approval.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

async function rpc(url: string, token: string, params: Record<string, unknown>): Promise<void> {
  await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params }),
  });
}

type Pending = { ref: string; requestHash: string; status?: string };

/**
 * Approving is the one thing the panel could not do. It listed what was
 * waiting and left the operator to find a terminal, which is the wrong place
 * to be standing when an agent is asking to spend and the operator is not at a
 * desk.
 *
 * Two things this door has to get right, and they are why it is not a thin
 * wrapper over the CLI:
 *
 * Reading is not approving. The audit scope hands out the whole ledger; an
 * approval signs a new decision into it and lets money go. If the same scope
 * opened both, everyone who can read could spend.
 *
 * A phone screen goes stale. The list may have been open for ten minutes, so
 * the approval carries the requestHash the operator was looking at, and the
 * body refuses when that is not what is pending any more. "I approved what I
 * saw" is only true if something checks.
 */
describe("approving over HTTP", () => {
  it("needs its own scope, matches what the screen showed, and resolves once", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-approve-http-"));
    const audience = "http://127.0.0.1/verax-test";
    const issuer = await startDevIssuer(0, audience);
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile: approvePolicyFile(stateDir),
      tlsTerminated: false,
    });
    const port = (server.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    const post = (token: string | null, body: unknown) =>
      fetch(`${base}/api/approve`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });

    try {
      const brain = await issuer.sign({ scope: "verax:memory" });
      await rpc(`${base}/mcp`, brain, {
        name: "memory.put",
        arguments: {
          id: "n1",
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });

      const auditOnly = await issuer.sign({ scope: "verax:audit" });
      const listed = await fetch(`${base}/api/ledger?from=0&to=${Number.MAX_SAFE_INTEGER}`, {
        headers: { authorization: `Bearer ${auditOnly}` },
      });
      const body = (await listed.json()) as { approvals?: Pending[] };
      const waiting = (body.approvals ?? []).find((a) => a.status === "pending" || a.status === undefined);
      assert.ok(waiting, `nothing is waiting to be approved: ${JSON.stringify(body.approvals)}`);

      assert.equal((await post(null, { ref: waiting.ref, requestHash: waiting.requestHash })).status, 401);

      // Reading the ledger must not be enough to spend from it.
      const forbidden = await post(auditOnly, { ref: waiting.ref, requestHash: waiting.requestHash });
      assert.equal(forbidden.status, 403);

      const operator = await issuer.sign({ scope: "verax:audit verax:approve", sub: "operator-7" });

      // A screen that has gone stale approves nothing.
      const stale = await post(operator, { ref: waiting.ref, requestHash: "00".repeat(32) });
      assert.equal(stale.status, 409);
      assert.equal(((await stale.json()) as { error?: string }).error, "stale");

      const missing = await post(operator, { ref: "no-such-ref", requestHash: waiting.requestHash });
      assert.equal(missing.status, 404);

      const ok = await post(operator, { ref: waiting.ref, requestHash: waiting.requestHash });
      assert.equal(ok.status, 200);
      const first = (await ok.json()) as { allowRef?: string; approver?: string };
      assert.ok(first.allowRef, "no allowRef came back");
      // The record says who, and on a phone the machine's login name is not it.
      assert.equal(first.approver, "operator-7");

      // The same tap twice is one approval, not two.
      const again = await post(operator, { ref: waiting.ref, requestHash: waiting.requestHash });
      assert.equal(again.status, 409);
      assert.equal(((await again.json()) as { error?: string }).error, "already-resolved");

      const after = await fetch(`${base}/api/ledger?from=0&to=${Number.MAX_SAFE_INTEGER}`, {
        headers: { authorization: `Bearer ${auditOnly}` },
      });
      const seen = (await after.json()) as { decisions?: { claims: { decision: string; ref: string } }[] };
      const allows = (seen.decisions ?? []).filter((d) => d.claims.decision === "allow");
      assert.equal(allows.length, 1, `one approval must leave one allow, got ${allows.length}`);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await issuer.close();
    }
  });
});
