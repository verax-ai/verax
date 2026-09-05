import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

function unauthCount(stateDir: string): number {
  const path = join(stateDir, "metrics.json");
  if (!existsSync(path)) return 0;
  const raw = JSON.parse(readFileSync(path, "utf8")) as { unauthenticated_requests?: number };
  return Number(raw.unauthenticated_requests ?? 0);
}

describe("P2-12 contest error classes", () => {
  it("unknown ref is 404 and does not bump unauthenticated", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-contest-"));
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
    const port = (server.address() as { port: number }).port;
    try {
      const token = await issuer.sign({ scope: "verax:read" });
      const before = unauthCount(stateDir);
      const res = await fetch(`http://127.0.0.1:${port}/api/contest/yok`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(res.status, 404, `status ${res.status} body=${await res.clone().text()}`);
      assert.deepEqual(await res.json(), { error: "unknown-ref" });
      assert.equal(unauthCount(stateDir), before);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
