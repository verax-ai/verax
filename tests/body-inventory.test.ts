import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const sample = join(root, "packages", "galaxy", "tests", "fixtures", "inventory-sample.json");

async function withBody(
  inventoryFile: string | null,
  fn: (base: string, sign: (scope: string) => Promise<string>) => Promise<void>,
): Promise<void> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-inv-http-"));
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
    inventoryFile,
  });
  const port = (server.address() as { port: number }).port;
  try {
    await fn(`http://127.0.0.1:${port}`, (scope) => issuer.sign({ scope }));
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await issuer.close();
  }
}

describe("GET /api/inventory", () => {
  it("is an audit door and does not write the ledger", async () => {
    await withBody(sample, async (base, sign) => {
      const anon = await fetch(`${base}/api/inventory`);
      assert.equal(anon.status, 401);

      const brain = await sign("verax:read");
      const forbidden = await fetch(`${base}/api/inventory`, {
        headers: { authorization: `Bearer ${brain}` },
      });
      assert.equal(forbidden.status, 403);

      const audit = await sign("verax:read verax:audit");
      const ok = await fetch(`${base}/api/inventory`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      assert.equal(ok.status, 200);
      const body = (await ok.json()) as { inventory?: { source?: string; agents?: unknown[] } | null };
      assert.equal(body.inventory?.source, "fixture-source");
      assert.equal(body.inventory?.agents?.length, 3);

      const posted = await fetch(`${base}/api/inventory`, {
        method: "POST",
        headers: { authorization: `Bearer ${audit}`, "content-type": "application/json" },
        body: "{}",
      });
      assert.equal(posted.status, 405);

      const ledger = await fetch(`${base}/api/ledger?from=0&to=99`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      const ledgerBody = (await ledger.json()) as { decisions: unknown[] };
      assert.equal(ledgerBody.decisions.length, 0);
    });
  });

  it("returns null when the file is absent, and null plus a reason when the document is broken", async () => {
    await withBody(join(tmpdir(), "verax-inventory-missing.json"), async (base, sign) => {
      const audit = await sign("verax:read verax:audit");
      const res = await fetch(`${base}/api/inventory`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), { inventory: null });
    });

    const dir = mkdtempSync(join(tmpdir(), "verax-inv-bad-"));
    const broken = join(dir, "broken.json");
    writeFileSync(broken, "{", "utf8");
    await withBody(broken, async (base, sign) => {
      const audit = await sign("verax:read verax:audit");
      const res = await fetch(`${base}/api/inventory`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), { inventory: null, reason: "invalid-json" });
    });
  });
});

describe("healthz inventory", () => {
  it("names inventory only under verax:audit", async () => {
    await withBody(sample, async (base, sign) => {
      const anon = await fetch(`${base}/healthz`);
      const anonBody = (await anon.json()) as Record<string, unknown>;
      assert.equal(anonBody.ok, true);
      assert.equal("inventory" in anonBody, false);

      const brain = await sign("verax:read");
      const brainRes = await fetch(`${base}/healthz`, {
        headers: { authorization: `Bearer ${brain}` },
      });
      assert.deepEqual(await brainRes.json(), { ok: true });

      const audit = await sign("verax:read verax:audit");
      const panel = await fetch(`${base}/healthz`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      const panelBody = (await panel.json()) as {
        inventory?: { source: string; takenAtMs: number; agents: number } | null;
      };
      assert.deepEqual(panelBody.inventory, {
        source: "fixture-source",
        takenAtMs: 1700000000000,
        agents: 3,
      });
    });
  });

  it("reports inventory null when no file is bound", async () => {
    await withBody(null, async (base, sign) => {
      const audit = await sign("verax:read verax:audit");
      const panel = await fetch(`${base}/healthz`, {
        headers: { authorization: `Bearer ${audit}` },
      });
      const panelBody = (await panel.json()) as { inventory?: unknown };
      assert.equal(panelBody.inventory, null);
    });
  });
});
