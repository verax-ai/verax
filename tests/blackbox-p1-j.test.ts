// P1-j: the process halt flag closes the approval door too; a normal halt
// lives in the file alone, so a resume from another process lifts it; the
// last-resort event id separates two incidents in the same millisecond.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { allocateIncidentEventId } from "../packages/body/src/incidents.ts";
import { listen } from "../packages/body/src/server.ts";
import { approvalsLogFor, approvePending } from "../packages/proxy/src/approvals.ts";
import { FileLedger } from "../packages/proxy/src/ledger.ts";
import { clearProcessHalted, isProcessHalted, markProcessHalted } from "../packages/proxy/src/process-halt.ts";
import type { RecordSigner } from "../packages/proxy/src/types.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const here = dirname(fileURLToPath(import.meta.url));
const audience = "http://127.0.0.1/verax-test";
const policyFile = join(here, "..", "packages", "proxy", "policy", "default.json");
const haltModule = pathToFileURL(join(here, "..", "packages", "body", "src", "halt.ts")).href;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Served = { isError: boolean; text: string };

async function receiver(): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    req.resume();
    req.on("end", () => res.writeHead(200).end());
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}/alarm`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

describe("black box P1-j: approval door, cross-process resume, last-resort id", { concurrency: 1 }, () => {
  it("J1: a process-only halt refuses approvePending before the queue can authorize anything", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-bbp1j-"));
    try {
      const ledger = new FileLedger(dir);
      markProcessHalted(dir);
      assert.equal(existsSync(join(dir, "halted")), false, "the flag stands alone before the gate runs");
      const outcome = await approvePending({
        ledger,
        recordSigner: {} as RecordSigner,
        now: () => Date.now(),
        nonce: () => randomBytes(8).toString("hex"),
        ref: "pending-ref-j1",
        approverId: "operator-j1",
        via: "cli",
        policyHash: "0".repeat(64),
        approvals: approvalsLogFor(ledger),
      });
      assert.deepEqual(outcome, { ok: false, reason: "halted" });
    } finally {
      clearProcessHalted(dir);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("J2: a resume from another process lifts a normal halt in the running body", async () => {
    const rx = await receiver();
    const state = mkdtempSync(join(tmpdir(), "verax-bbp1j-"));
    const issuer = await startDevIssuer(0, audience);
    let server: Awaited<ReturnType<typeof listen>> | null = null;
    try {
      const token = await issuer.sign({ scope: "verax:read verax:memory", sub: "agent-j" });
      const operator = await issuer.sign({ scope: "verax:audit", sub: "operator-j" });
      server = await listen({
        issuer: issuer.issuer,
        jwksUrl: issuer.jwksUrl,
        audience,
        stateDir: state,
        bindHost: "127.0.0.1",
        bindPort: 0,
        policyFile,
        tlsTerminated: false,
        alarmWebhookUrl: rx.url,
        alarmRetryMs: 150,
      });
      const port = (server.address() as { port: number }).port;
      let rpcId = 0;
      const call = async (): Promise<Served> => {
        const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
          body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name: "audit.explain", arguments: { ref: "none" } } }),
        });
        const body = (await res.json()) as { result?: { isError?: boolean; content?: { text?: string }[] } };
        assert.ok(body.result, "no result");
        return { isError: body.result.isError === true, text: body.result.content?.[0]?.text ?? "" };
      };

      const halt = await fetch(`http://127.0.0.1:${port}/api/halt`, {
        method: "POST",
        headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
        body: "{}",
      });
      assert.equal(halt.status, 200, await halt.text());
      assert.equal(existsSync(join(state, "halted")), true, "a normal halt writes the switch");
      // No tool call here: a call would read the file and drop a stray flag,
      // hiding a flag that a resume in another process cannot clear.

      const child = spawnSync(
        process.execPath,
        [
          "--experimental-strip-types",
          "--no-warnings",
          "--input-type=module",
          "-e",
          `const m = await import(${JSON.stringify(haltModule)}); process.exitCode = m.runResume(${JSON.stringify(state)});`,
        ],
        { encoding: "utf8", timeout: 60_000 },
      );
      assert.equal(child.status, 0, `resume child: ${child.stderr.slice(0, 300)}`);
      assert.equal(existsSync(join(state, "halted")), false, "the other process removed the switch");

      const after = await call();
      assert.doesNotMatch(after.text, /denied:halted/, `running body after resume: ${after.text.slice(0, 160)}`);
      assert.equal(existsSync(join(state, "halted")), false, "the running body did not write the switch back");
      assert.equal(isProcessHalted(state), false);
    } finally {
      if (server) {
        const srv = server;
        srv.closeAllConnections();
        await new Promise<void>((r) => srv.close(() => r()));
      }
      await issuer.close?.();
      await rx.close();
      clearProcessHalted(state);
      rmSync(state, { recursive: true, force: true });
    }
  });

  it("J3: with no randomness at all, two incidents in one millisecond get two ids", () => {
    const cjs = createRequire(import.meta.url)("node:crypto") as {
      randomUUID: () => string;
      randomBytes: (n: number) => Buffer;
    };
    const original = { randomUUID: cjs.randomUUID, randomBytes: cjs.randomBytes };
    const opts = { observedAt: 1_700_000_000_000, triggerCode: "memory-integrity-mismatch", publicKeyPem: "not-a-key" };
    let first = "";
    let second = "";
    try {
      cjs.randomUUID = () => {
        throw new Error("uuid-unavailable");
      };
      cjs.randomBytes = () => {
        throw new Error("bytes-unavailable");
      };
      syncBuiltinESMExports();
      first = allocateIncidentEventId(opts);
      second = allocateIncidentEventId(opts);
    } finally {
      cjs.randomUUID = original.randomUUID;
      cjs.randomBytes = original.randomBytes;
      syncBuiltinESMExports();
    }
    assert.match(first, UUID_RE);
    assert.match(second, UUID_RE);
    assert.notEqual(first, second);
  });
});
