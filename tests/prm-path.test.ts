import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

describe("P2-9 RFC 9728 protected-resource metadata path", () => {
  it("serves /.well-known/oauth-protected-resource/<path> and the challenge names it", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-prm-"));
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
      const challenge = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST" });
      assert.equal(challenge.status, 401);
      const www = challenge.headers.get("www-authenticate") ?? "";
      const quoted = /resource_metadata="([^"]+)"/.exec(www)?.[1];
      assert.ok(quoted, www);
      const meta = new URL(quoted);
      meta.port = String(port);
      const prm = await fetch(meta);
      assert.equal(prm.status, 200, `GET ${meta.pathname} -> ${prm.status}`);
      const body = (await prm.json()) as { resource?: string };
      assert.equal(body.resource, audience);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });
});
