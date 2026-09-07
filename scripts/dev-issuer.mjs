#!/usr/bin/env node
// Development only. PKCE S256 authorize/token for local panel sessions.
// NODE_ENV=production still exits. Not a production authorization server.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
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
// Development only: one token stands in for both a brain and the operator panel, so
// it carries `verax:audit` as well. A real issuer grants that scope to an operator
// session, never to a brain.
const scope = process.env.VERAX_DEV_SCOPE ?? "verax:read verax:memory verax:audit";

async function mintAccessToken() {
  return new SignJWT({ scope })
    .setProtectedHeader({ alg: "ES256", kid: "verax-dev" })
    .setSubject(sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("10m")
    .setJti(randomUUID())
    .sign(key);
}

const token = await mintAccessToken();
writeFileSync(outPath, token, { encoding: "utf8", mode: 0o600 });
chmodSync(outPath, 0o600);

const CODE_TTL_MS = 60_000;
const CODE_LIMIT = 100;
const DEFAULT_REDIRECTS = ["http://127.0.0.1:5173/", "http://127.0.0.1:4173/"];
/** @type {Map<string, { challenge: string; redirectUri: string; expiresAtMs: number }>} */
const codes = new Map();

function redirectAllowList() {
  const raw = process.env.VERAX_DEV_REDIRECT_URIS ?? "";
  const listed = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  return listed.length > 0 ? listed : DEFAULT_REDIRECTS;
}

function normalizeRedirect(uri) {
  const u = new URL(uri);
  const path = u.pathname === "" ? "/" : u.pathname;
  return `${u.origin}${path}`;
}

function redirectAllowed(uri) {
  let normalized;
  try {
    normalized = normalizeRedirect(uri);
  } catch {
    return false;
  }
  return redirectAllowList().some((allowed) => {
    try {
      return normalizeRedirect(allowed) === normalized;
    } catch {
      return false;
    }
  });
}

function pruneCodes(now = Date.now()) {
  for (const [code, row] of codes) {
    if (now > row.expiresAtMs) codes.delete(code);
  }
  while (codes.size >= CODE_LIMIT) {
    const oldest = codes.keys().next().value;
    if (typeof oldest !== "string") break;
    codes.delete(oldest);
  }
}

function s256(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}

function sendJson(res, status, obj) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

function redirectWith(res, redirectUri, params) {
  let loc;
  try {
    loc = new URL(redirectUri);
  } catch {
    sendJson(res, 400, { error: "invalid_request" });
    return;
  }
  for (const [k, v] of Object.entries(params)) {
    if (typeof v === "string") loc.searchParams.set(k, v);
  }
  res.writeHead(302, { location: loc.toString() });
  res.end();
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function readJson(req) {
  const text = await readBody(req);
  if (text === "") return {};
  return JSON.parse(text);
}

function parseForm(text) {
  const params = new URLSearchParams(text);
  /** @type {Record<string, string>} */
  const out = {};
  for (const [k, v] of params) out[k] = v;
  return out;
}

const server = createServer((req, res) => {
  void (async () => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/.well-known/jwks.json") {
      const body = JSON.stringify({ keys: [jwk] });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }
    if (req.method === "GET" && url.pathname === "/authorize") {
      const responseType = url.searchParams.get("response_type");
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const challenge = url.searchParams.get("code_challenge");
      const method = url.searchParams.get("code_challenge_method");
      const state = url.searchParams.get("state");
      if (responseType !== "code" || !clientId || !redirectUri) {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      if (!challenge) {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      if (method !== "S256") {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      if (!redirectAllowed(redirectUri)) {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      pruneCodes();
      const code = randomBytes(32).toString("base64url");
      codes.set(code, {
        challenge,
        redirectUri,
        expiresAtMs: Date.now() + CODE_TTL_MS,
      });
      redirectWith(res, redirectUri, { code, ...(state ? { state } : {}) });
      return;
    }
    if (req.method === "POST" && url.pathname === "/token") {
      let parsed;
      try {
        const text = await readBody(req);
        const ctype = String(req.headers["content-type"] ?? "");
        parsed = ctype.includes("application/json") ? JSON.parse(text || "{}") : parseForm(text);
      } catch {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const grant = parsed.grant_type;
      const code = parsed.code;
      const redirectUri = parsed.redirect_uri;
      const verifier = parsed.code_verifier;
      if (grant !== "authorization_code" || typeof code !== "string" || typeof redirectUri !== "string" || typeof verifier !== "string") {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const row = codes.get(code);
      codes.delete(code);
      if (!row || Date.now() > row.expiresAtMs) {
        sendJson(res, 400, { error: "invalid_grant" });
        return;
      }
      if (redirectUri !== row.redirectUri) {
        sendJson(res, 400, { error: "invalid_grant" });
        return;
      }
      if (s256(verifier) !== row.challenge) {
        sendJson(res, 400, { error: "invalid_grant" });
        return;
      }
      const accessToken = await mintAccessToken();
      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 600,
      });
      return;
    }
    if (req.method === "POST" && url.pathname === "/revoke") {
      let parsed;
      try {
        parsed = await readJson(req);
      } catch {
        sendJson(res, 400, { error: "bad-request" });
        return;
      }
      const jti = typeof parsed.jti === "string" ? parsed.jti : "";
      if (jti === "") {
        sendJson(res, 400, { error: "jti-missing" });
        return;
      }
      appendFileSync(join(stateDir, "revoked-jti.jsonl"), `${JSON.stringify({ jti })}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
      sendJson(res, 200, { revoked: true });
      return;
    }
    res.writeHead(404);
    res.end();
  })();
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(port, "127.0.0.1", resolve);
});

const bound = server.address();
const listenPort = bound && typeof bound === "object" ? bound.port : port;
process.stderr.write(`dev-issuer listening on http://127.0.0.1:${listenPort}/.well-known/jwks.json\n`);
