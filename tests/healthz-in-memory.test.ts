// /healthz with an audit token reports how many decisions and effects the
// ledger holds. Measured on 17 Sep 2026 with a 100k-decision ledger, that
// answer cost one second: the handler read both ledger files from disk and
// counted the lines, while the ledger already kept the same counts in memory.
// The panel asks /healthz every five seconds. This guard counts the file
// reads the way the append-cost suite does: a fact the filesystem hands us,
// not a timing that moves with the machine.

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
// The body reaches the proxy through its built package, so the seam has to
// be the built module: patching the source copy would count nothing.
import { ledgerFs } from "../packages/proxy/dist/ledger.js";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

async function rpc(url: string, token: string, method: string, params: Record<string, unknown>): Promise<number> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  await res.arrayBuffer();
  return res.status;
}

function lines(path: string): string[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l !== "");
}

describe("healthz counts from memory", () => {
  it("answers decisions, effects and lastDecisionMs without rereading the ledger files", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-healthz-mem-"));
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
      tlsTerminated: false,
    });
    const bodyPort = (server.address() as { port: number }).port;
    const mcp = `http://127.0.0.1:${bodyPort}/mcp`;
    const origRead = ledgerFs.readFile.bind(ledgerFs);
    const origReadSync = ledgerFs.readFileSync.bind(ledgerFs);
    try {
      const brain = await issuer.sign({ scope: "verax:read verax:memory" });
      const put = {
        body: { t: 1 },
        source: { uri: "file://t", retrievedAtMs: 1 },
        validUntilMs: Date.now() + 60_000,
      };
      assert.equal(await rpc(mcp, brain, "tools/call", { name: "memory.put", arguments: { id: "a", ...put } }), 200);
      assert.equal(await rpc(mcp, brain, "tools/call", { name: "memory.put", arguments: { id: "b", ...put } }), 200);
      assert.equal(await rpc(mcp, brain, "tools/call", { name: "memory.get", arguments: { id: "a" } }), 200);

      const decisionLines = lines(join(stateDir, "decisions.jsonl"));
      const effectLines = lines(join(stateDir, "effects.jsonl"));
      assert.equal(decisionLines.length, 3);
      assert.ok(effectLines.length >= 1, "the allowed calls left effects");
      const lastLine = JSON.parse(decisionLines[decisionLines.length - 1]!) as { claims: { timestampMs: number } };

      const reads: string[] = [];
      const note = (path: unknown) => {
        const name = String(path).split(/[\\/]/).pop() ?? "";
        if (name === "decisions.jsonl" || name === "effects.jsonl") reads.push(name);
      };
      ledgerFs.readFile = (async (path: Parameters<typeof origRead>[0], ...rest: unknown[]) => {
        note(path);
        return origRead(path, ...(rest as []));
      }) as typeof ledgerFs.readFile;
      ledgerFs.readFileSync = ((path: Parameters<typeof origReadSync>[0], ...rest: unknown[]) => {
        note(path);
        return origReadSync(path, ...(rest as []));
      }) as typeof ledgerFs.readFileSync;

      const audit = await issuer.sign({ scope: "verax:read verax:audit" });
      const res = await fetch(`http://127.0.0.1:${bodyPort}/healthz`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      assert.equal(res.status, 200);
      const health = (await res.json()) as { decisions?: number; effects?: number; lastDecisionMs?: number | null };

      assert.equal(health.decisions, decisionLines.length);
      assert.equal(health.effects, effectLines.length);
      assert.equal(health.lastDecisionMs, lastLine.claims.timestampMs);
      assert.deepEqual(reads, [], `healthz reread the ledger: ${reads.join(", ")}`);
    } finally {
      ledgerFs.readFile = origRead;
      ledgerFs.readFileSync = origReadSync;
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
