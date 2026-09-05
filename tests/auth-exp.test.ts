import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listen } from "../packages/body/src/server.ts";
import { startDevIssuer } from "./issuer-helper.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

async function toolsList(url: string, token: string): Promise<number> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
  return res.status;
}

describe("P1-1 jwtVerify requires exp, iat, sub", () => {
  it("rejects a signed token with no exp, a future iat beyond 60s skew, and a future nbf", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-exp-"));
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
    const mcp = `http://127.0.0.1:${port}/mcp`;
    try {
      const noExp = await issuer.sign({ omitExp: true });
      assert.equal(await toolsList(mcp, noExp), 401, "signed token without exp must be 401");

      const futureIat = await issuer.sign({ iatSkewSec: 120 });
      assert.equal(await toolsList(mcp, futureIat), 401, "iat more than 60s in the future must be 401");

      const futureNbf = await issuer.sign({ nbfSkewSec: 120 });
      assert.equal(await toolsList(mcp, futureNbf), 401, "nbf in the future must be 401");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("F: a token with iat two hours ago and exp in ten minutes is accepted", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-iat-age-"));
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
    const mcp = `http://127.0.0.1:${port}/mcp`;
    try {
      const aged = await issuer.sign({ iatSkewSec: -7200 });
      assert.equal(await toolsList(mcp, aged), 200, "valid exp must not be refused for iat age");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await issuer.close();
    }
  });

  it("F: auth.ts keeps requiredClaims and clockTolerance, drops maxTokenAge", () => {
    const src = readFileSync(join(root, "packages", "body", "src", "auth.ts"), "utf8");
    assert.equal(src.includes("maxTokenAge"), false);
    assert.equal(src.includes("clockTolerance: 60"), true);
    assert.equal(src.includes('requiredClaims: ["exp", "iat", "sub"]'), true);
  });
});
