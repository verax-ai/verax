import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

/**
 * A body can now stand in front of other products, and until this file
 * nothing said which ones. An operator reading the panel could see rows
 * named `conarium.list_tables` without anything telling them that a
 * Conarium is attached, by which transport, or which of its tools this
 * body will even accept.
 *
 * What must not appear is as important. A child's URL can carry its token
 * in the path — the live Conarium's does — and a command line can name a
 * path on the host. The door publishes the prefix, the transport and the
 * tool names, and nothing else.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests", "fixtures", "downstream-echo.mjs");
const defaultPolicy = join(root, "packages", "proxy", "policy", "default.json");

const SIR = "cok-gizli-jeton-123";

async function withBody(
  downstream: unknown | null,
  fn: (ctx: { base: string; audit: () => Promise<string>; brain: () => Promise<string> }) => Promise<void>,
): Promise<void> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-down-visible-"));
  const policyFile = join(stateDir, "policy.json");
  const { readFileSync } = await import("node:fs");
  writeFileSync(policyFile, readFileSync(defaultPolicy, "utf8"), "utf8");
  let downstreamFile: string | null = null;
  if (downstream !== null) {
    downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(downstreamFile, `${JSON.stringify(downstream)}\n`, "utf8");
  }
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
    ...(downstreamFile ? { downstreamFile } : {}),
  });
  const port = (server.address() as { port: number }).port;
  try {
    await fn({
      base: `http://127.0.0.1:${port}`,
      audit: () => issuer.sign({ scope: "verax:audit" }),
      brain: () => issuer.sign({ scope: "verax:read" }),
    });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await issuer.close();
  }
}

type Cocuk = { prefix: string; transport: string; tools: string[] };

async function healthz(base: string, token?: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${base}/healthz`, token ? { headers: { authorization: `Bearer ${token}` } } : undefined);
  return (await res.json()) as Record<string, unknown>;
}

describe("the body says which children it attached", { timeout: 60_000 }, () => {
  it("an operator sees the prefix, the transport and the tool names", async () => {
    await withBody(
      { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, env: { GIZLI: SIR }, trust: "same-user" },
      async ({ base, audit }) => {
        const body = await healthz(base, await audit());
        const kids = body.downstream as Cocuk[] | undefined;
        assert.ok(Array.isArray(kids), `downstream alanı yok: ${JSON.stringify(body).slice(0, 200)}`);
        assert.equal(kids.length, 1);
        assert.equal(kids[0]?.prefix, "echo");
        assert.equal(kids[0]?.transport, "stdio");
        assert.deepEqual(kids[0]?.tools, ["echo.ping"]);
      },
    );
  });

  it("never publishes the child's url, command, arguments, env or headers", async () => {
    await withBody(
      {
        prefix: "echo",
        command: process.execPath,
        args: [fixture],
        cwd: root,
        env: { GIZLI: SIR },
        trust: "same-user",
      },
      async ({ base, audit }) => {
        const metin = JSON.stringify(await healthz(base, await audit()));
        assert.equal(metin.includes(SIR), false, "çocuğun env sırrı sızdı");
        assert.equal(metin.includes(fixture), false, "çocuğun dosya yolu sızdı");
        assert.equal(metin.includes(process.execPath), false, "çocuğun komutu sızdı");
        assert.equal(metin.toLowerCase().includes("headers"), false, "başlık alanı sızdı");
      },
    );
  });

  it("an unauthenticated probe still sees liveness only", async () => {
    await withBody(
      { prefix: "echo", command: process.execPath, args: [fixture], cwd: root, trust: "same-user" },
      async ({ base, brain }) => {
        const acik = await healthz(base);
        assert.deepEqual(acik, { ok: true });
        // A brain token is not an operator session either.
        const beyin = await healthz(base, await brain());
        assert.deepEqual(beyin, { ok: true });
      },
    );
  });

  it("a body with no children says so with an empty list, not a missing field", async () => {
    await withBody(null, async ({ base, audit }) => {
      const body = await healthz(base, await audit());
      assert.deepEqual(body.downstream, []);
    });
  });
});
