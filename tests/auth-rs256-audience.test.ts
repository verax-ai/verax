import { strict as assert } from "node:assert";
import { constants, generateKeyPairSync, randomUUID, sign as nodeSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

import { AGENT_TOKEN_ALGS, createVerifier, resourceMetadataUrl, wwwAuthenticate } from "../packages/body/src/auth.ts";
import { runDoctor } from "../packages/body/src/doctor.ts";
import { listen } from "../packages/body/src/server.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const ISS = "https://issuer.example";
const AUD = "https://verax.example.com/mcp";

const b64url = (v: unknown) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");
const claims = (over: Record<string, unknown> = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return { scope: "verax:read", iss: ISS, aud: AUD, sub: "agent", iat: now, exp: now + 600, jti: randomUUID(), ...over };
};

/** A JWT signed with node:crypto directly, so key sizes jose refuses to sign with can still be presented. */
function rawJwt(header: Record<string, unknown>, body: Record<string, unknown>, sign: (data: Buffer) => Buffer): string {
  const head = `${b64url(header)}.${b64url(body)}`;
  return `${head}.${sign(Buffer.from(head)).toString("base64url")}`;
}

async function rsaJwk(bits: number, kid: string) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  const jwk = { ...(publicKey.export({ format: "jwk" }) as JWK), kid, alg: "RS256", use: "sig" };
  return { jwk, privateKey, publicKey };
}

describe("agent tokens signed with RS256", () => {
  it("lists exactly ES256, EdDSA and RS256", () => {
    assert.deepEqual([...AGENT_TOKEN_ALGS], ["ES256", "EdDSA", "RS256"]);
  });

  it("accepts an RS256 token from a 2048-bit key in the JWKS", async () => {
    const rsa = await rsaJwk(2048, "rsa-2048");
    const verify = createVerifier("https://unused.example/jwks", ISS, AUD, null, { keys: [rsa.jwk] });
    const token = await new SignJWT({ scope: "verax:read verax:memory" })
      .setProtectedHeader({ alg: "RS256", kid: "rsa-2048" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject("agent-rs")
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(rsa.privateKey);
    const out = await verify(token);
    assert.equal(out.principal.brain, "agent-rs");
    assert.ok(out.principal.scopes.has("verax:memory"));
  });

  it("refuses RS256 under a 1024-bit key, HS256 keyed with the RSA public key, PS256, RS256 against an EC key, and alg none", async () => {
    const small = await rsaJwk(1024, "rsa-1024");
    const big = await rsaJwk(2048, "rsa-2048");
    const ec = await generateKeyPair("ES256");
    const ecJwk = { ...(await exportJWK(ec.publicKey)), kid: "ec-1", alg: "ES256", use: "sig" };
    const verify = createVerifier("https://unused.example/jwks", ISS, AUD, null, { keys: [small.jwk, big.jwk, ecJwk] });

    const rs1024 = rawJwt({ alg: "RS256", kid: "rsa-1024", typ: "JWT" }, claims(), (d) => nodeSign("sha256", d, small.privateKey));
    const publicPem = big.publicKey.export({ format: "pem", type: "spki" });
    const hsConfused = await new SignJWT({ scope: "verax:read" })
      .setProtectedHeader({ alg: "HS256", kid: "rsa-2048" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject("agent")
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(Buffer.from(String(publicPem)));
    const ps256 = rawJwt({ alg: "PS256", kid: "rsa-2048", typ: "JWT" }, claims(), (d) =>
      nodeSign("sha256", d, { key: big.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }),
    );
    const rsOnEc = rawJwt({ alg: "RS256", kid: "ec-1", typ: "JWT" }, claims(), (d) => nodeSign("sha256", d, big.privateKey));
    const none = `${b64url({ alg: "none", kid: "rsa-2048", typ: "JWT" })}.${b64url(claims())}.`;

    for (const [name, token] of Object.entries({ rs1024, hsConfused, ps256, rsOnEc, none })) {
      await assert.rejects(verify(token), `${name} must be refused`);
    }
  });
});

describe("an audience that is not a URL", () => {
  it("has no resource metadata and a plain Bearer challenge", () => {
    assert.equal(resourceMetadataUrl("verax-ecs-test"), null);
    assert.equal(resourceMetadataUrl("api://default"), null);
    assert.equal(wwwAuthenticate("verax-ecs-test"), "Bearer");
    assert.equal(
      resourceMetadataUrl("https://verax.example.com/mcp"),
      "https://verax.example.com/.well-known/oauth-protected-resource/mcp",
    );
    assert.equal(
      wwwAuthenticate("https://verax.example.com/mcp"),
      'Bearer resource_metadata="https://verax.example.com/.well-known/oauth-protected-resource/mcp"',
    );
  });

  it("answers an unauthenticated call with 401, not 400, and doctor warns about it", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-aud-"));
    const { publicKey } = await generateKeyPair("ES256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "k", alg: "ES256", use: "sig" };
    const jwksServer: Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [jwk] }));
    });
    await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", () => r()));
    const jwksPort = (jwksServer.address() as { port: number }).port;
    const audience = "verax-ecs-test";
    const server = await listen({
      issuer: ISS,
      jwksUrl: `http://127.0.0.1:${jwksPort}/jwks.json`,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      tlsTerminated: false,
    });
    const port = (server.address() as { port: number }).port;
    try {
      const noToken = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      assert.equal(noToken.status, 401);
      assert.equal(noToken.headers.get("www-authenticate"), "Bearer");

      const badToken = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer not.a.token" },
        body: "{}",
      });
      assert.equal(badToken.status, 401);

      const metadata = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource`);
      assert.equal(metadata.status, 404, "no metadata document is served for a non-URL audience");

      const doctor = runDoctor({ VERAX_ISSUER: ISS, VERAX_JWKS_URL: "https://issuer.example/jwks", VERAX_AUDIENCE: audience }, []);
      const check = doctor.find((c) => c.id === "audience-url");
      assert.equal(check?.level, "warn");
      const doctorUrl = runDoctor({ VERAX_ISSUER: ISS, VERAX_JWKS_URL: "https://issuer.example/jwks", VERAX_AUDIENCE: AUD }, []);
      assert.equal(doctorUrl.find((c) => c.id === "audience-url")?.level, "ok");
    } finally {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
      await new Promise<void>((r) => jwksServer.close(() => r()));
    }
  });
});

describe("an RS256 agent token over HTTP", () => {
  it("opens an MCP session but cannot approve, read the ledger, list agents or see health counts", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-rs-http-"));
    const rsa = await rsaJwk(2048, "rsa-http");
    const jwksServer: Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [rsa.jwk] }));
    });
    await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", () => r()));
    const jwksPort = (jwksServer.address() as { port: number }).port;
    const server = await listen({
      issuer: ISS,
      jwksUrl: `http://127.0.0.1:${jwksPort}/jwks.json`,
      audience: AUD,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      tlsTerminated: false,
    });
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const token = await new SignJWT({ scope: "verax:read verax:memory" })
      .setProtectedHeader({ alg: "RS256", kid: "rsa-http" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject("agent-rs")
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(rsa.privateKey);
    const auth = { authorization: `Bearer ${token}` };
    try {
      const init = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "rs256-test", version: "1" } },
        }),
      });
      assert.equal(init.status, 200, await init.text());

      const approve = await fetch(`${base}/api/approve`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({ ref: "r1", requestHash: "deadbeef" }),
      });
      assert.equal(approve.status, 403, await approve.text());
      const ledger = await fetch(`${base}/api/ledger`, { headers: auth });
      assert.equal(ledger.status, 403, await ledger.text());
      const agents = await fetch(`${base}/api/agents`, { headers: auth });
      assert.ok(agents.status === 403 || agents.status === 401, String(agents.status));
      const health = await fetch(`${base}/healthz`, { headers: auth });
      assert.equal(health.status, 200);
      assert.deepEqual(await health.json(), { ok: true });
    } finally {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
      await new Promise<void>((r) => jwksServer.close(() => r()));
    }
  });
});
