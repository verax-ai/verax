#!/usr/bin/env node
// Development only; not an authorization server; no authorize endpoint.

import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPair, exportJWK, exportPKCS8, exportSPKI, SignJWT, importPKCS8 } from "jose";

if (process.env.NODE_ENV === "production") {
  process.stderr.write("dev-issuer refuses NODE_ENV=production\n");
  process.exit(1);
}

const stateDir = process.env.VERAX_STATE_DIR;
if (!stateDir) {
  process.stderr.write("dev-issuer requires VERAX_STATE_DIR\n");
  process.exit(78);
}

const outIdx = process.argv.indexOf("--out");
const outPath = outIdx >= 0 ? process.argv[outIdx + 1] : null;
if (!outPath) {
  process.stderr.write("dev-issuer requires --out <file>\n");
  process.exit(78);
}

const dir = join(stateDir, "dev-issuer");
mkdirSync(dir, { recursive: true, mode: 0o700 });
const privPath = join(dir, "key.pkcs8");
const pubPath = join(dir, "key.spki");
const jwkPath = join(dir, "jwk.json");

let privatePem;
let jwk;
if (existsSync(privPath) && existsSync(jwkPath)) {
  privatePem = readFileSync(privPath, "utf8");
  jwk = JSON.parse(readFileSync(jwkPath, "utf8"));
} else {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  privatePem = await exportPKCS8(privateKey);
  const publicPem = await exportSPKI(publicKey);
  jwk = { ...(await exportJWK(publicKey)), alg: "ES256", use: "sig", kid: "verax-dev" };
  writeFileSync(privPath, privatePem, { encoding: "utf8", mode: 0o600 });
  writeFileSync(pubPath, publicPem, { encoding: "utf8", mode: 0o600 });
  writeFileSync(jwkPath, `${JSON.stringify(jwk)}\n`, { encoding: "utf8", mode: 0o600 });
}

const key = await importPKCS8(privatePem, "ES256");
const port = Number(process.env.VERAX_DEV_ISSUER_PORT ?? "8790");
const audience = process.env.VERAX_AUDIENCE ?? "http://127.0.0.1:8787";
const issuer = process.env.VERAX_ISSUER ?? "http://127.0.0.1:8790";
const sub = process.env.VERAX_DEV_SUB ?? "dev-brain";
const scope = process.env.VERAX_DEV_SCOPE ?? "verax:read verax:memory";

const token = await new SignJWT({ scope })
  .setProtectedHeader({ alg: "ES256", kid: "verax-dev" })
  .setSubject(sub)
  .setIssuer(issuer)
  .setAudience(audience)
  .setIssuedAt()
  .setExpirationTime("10m")
  .sign(key);

writeFileSync(outPath, token, { encoding: "utf8", mode: 0o600 });
chmodSync(outPath, 0o600);

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  if (url.pathname === "/.well-known/jwks.json") {
    const body = JSON.stringify({ keys: [jwk] });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
    return;
  }
  res.writeHead(404);
  res.end();
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(port, "127.0.0.1", resolve);
});

process.stderr.write(`dev-issuer listening on http://127.0.0.1:${port}/.well-known/jwks.json\n`);
