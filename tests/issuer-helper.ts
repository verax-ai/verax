import { createServer, type Server } from "node:http";
import { generateKeyPair, SignJWT, exportJWK } from "jose";

export type DevIssuer = {
  issuer: string;
  jwksUrl: string;
  audience: string;
  port: number;
  sign: (over?: {
    aud?: string;
    exp?: string;
    alg?: string;
    scope?: string;
    omitExp?: boolean;
    iatSkewSec?: number;
    nbfSkewSec?: number;
  }) => Promise<string>;
  close: () => Promise<void>;
};

export async function startDevIssuer(bindPort: number, audience: string): Promise<DevIssuer> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), alg: "ES256", use: "sig", kid: "test" };
  const server: Server = createServer((req, res) => {
    if (req.url === "/.well-known/jwks.json") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(bindPort, "127.0.0.1", () => resolve());
  });
  const port = (server.address() as { port: number }).port;
  const issuerUrl = `http://127.0.0.1:${port}`;
  return {
    issuer: issuerUrl,
    jwksUrl: `${issuerUrl}/.well-known/jwks.json`,
    audience,
    port,
    async sign(over = {}) {
      const nowSec = Math.floor(Date.now() / 1000);
      const jwt = new SignJWT({ scope: over.scope ?? "verax:read verax:memory" })
        .setProtectedHeader({ alg: "ES256", kid: "test" })
        .setSubject("brain-1")
        .setIssuer(issuerUrl)
        .setAudience(over.aud ?? audience)
        .setIssuedAt(nowSec + (over.iatSkewSec ?? 0));
      if (typeof over.nbfSkewSec === "number") {
        jwt.setNotBefore(nowSec + over.nbfSkewSec);
      }
      if (over.omitExp === true) {
        // Intentionally unsigned exp: the verifier must reject this.
      } else if (over.exp === "past") {
        jwt.setExpirationTime(nowSec - 60);
      } else {
        jwt.setExpirationTime("10m");
      }
      return jwt.sign(privateKey);
    },
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
