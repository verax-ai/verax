#!/usr/bin/env node
// Development only. PKCE S256 authorize/token for local panel sessions.
// NODE_ENV=production still exits. Not a production authorization server.

import { createHash, createPublicKey, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, exportJWK, exportPKCS8, exportSPKI, SignJWT, importPKCS8, jwtVerify } from "jose";
import { checkPairing, consumePairing } from "../packages/body/src/operator-pairing.ts";
import {
  DEFAULT_OPERATOR_SUB,
  findCredential,
  hasRegisteredOperator,
  saveCredential,
  updateCounter,
} from "../packages/body/src/operator-credentials.ts";
import { readRpConfig } from "../packages/body/src/rp-config.ts";

// Off by default. With VERAX_DEV_ISSUER_TRACE=1 the issuer names each phase and
// the time since it started, on stderr. It exists because a gate run twice saw
// this process print its first line and never reach `listening`, and "no port"
// cannot say which phase stalled. Three suites read this stderr for the
// `listening` line, so the default output must not change.
const TRACE_T0 = performance.now();
function trace(phase) {
  if (process.env.VERAX_DEV_ISSUER_TRACE !== "1") return;
  process.stderr.write(`dev-issuer: trace ${phase} +${Math.round(performance.now() - TRACE_T0)}ms
`);
}

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

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const rp = readRpConfig(process.env);
if (!rp.ok) {
  process.stderr.write(`dev-issuer: passkey enroll and sign-in are closed: ${rp.reason}\n`);
}

// Importing @simplewebauthn/server takes about 320 ms, more than this issuer
// needed to start before passkeys (about 110 ms; about 450 ms with the import).
// Paid up front, every start carried it, including the desktop and test runs
// that never touch a passkey, and in one of three full unit runs two issuers
// did not start inside their 8 s budget. Only the passkey routes load it now.
let webauthnLoad;
function webauthn() {
  webauthnLoad ??= Promise.all([
    import("@simplewebauthn/server"),
    import("@simplewebauthn/server/helpers"),
  ]).then(([server, helpers]) => ({ ...server, isoBase64URL: helpers.isoBase64URL }));
  return webauthnLoad;
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
// jwtVerify rejects a private key. The public half is the same PEM the JWKS serves.
const verifyKey = createPublicKey(privatePem);
trace("keys-ready");
const port = Number(process.env.VERAX_DEV_ISSUER_PORT ?? "8790");
const audience = process.env.VERAX_AUDIENCE ?? "http://127.0.0.1:8787";
const issuer = process.env.VERAX_ISSUER ?? "http://127.0.0.1:8790";
const agentSub = process.env.VERAX_DEV_SUB ?? "dev-brain";
const operatorSub = process.env.VERAX_DEV_OPERATOR_SUB ?? "operator-1";
const requestedScope = process.env.VERAX_DEV_SCOPE ?? "verax:read verax:memory verax:audit";

/** The file written for the agent never carries approve, even when the env asks. */
function agentScope(raw) {
  return raw
    .split(/\s+/)
    .filter((part) => part !== "" && part !== "verax:approve")
    .join(" ");
}

async function mintAccessToken(kind, extra = {}) {
  // A session without a passkey is read-only, even when VERAX_DEV_SCOPE asks
  // for approve. Approve is minted only after a registered operator signs in.
  let tokenScope = kind === "agent" ? agentScope(requestedScope) : requestedScope;
  if (kind === "session" && extra.grantApprove !== true) {
    tokenScope = agentScope(tokenScope);
  }
  if (kind === "session" && extra.grantApprove === true) {
    tokenScope = "verax:audit verax:approve";
  }
  const tokenSub = kind === "agent" ? agentSub : (extra.sub ?? operatorSub);
  return new SignJWT({ scope: tokenScope })
    .setProtectedHeader({ alg: "ES256", kid: "verax-dev" })
    .setSubject(tokenSub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("10m")
    .setJti(randomUUID())
    .sign(key);
}

const token = await mintAccessToken("agent");
writeFileSync(outPath, token, { encoding: "utf8", mode: 0o600 });
chmodSync(outPath, 0o600);
trace("token-written");

const CODE_TTL_MS = 60_000;
const CODE_LIMIT = 100;
const DEFAULT_REDIRECTS = ["http://127.0.0.1:5173/", "http://127.0.0.1:4173/"];
/** @type {Map<string, { challenge: string; redirectUri: string; expiresAtMs: number; grantApprove?: boolean; sub?: string }>} */
const codes = new Map();
/** @type {Map<string, { challenge: string; expiresAtMs: number }>} */
const enrollChallenges = new Map();
/** @type {Map<string, { challenge: string; expiresAtMs: number }>} */
const signinChallenges = new Map();

function pruneWebauthn(now = Date.now()) {
  for (const store of [enrollChallenges, signinChallenges]) {
    for (const [id, row] of store) {
      if (now > row.expiresAtMs) store.delete(id);
    }
  }
}

function htmlPage(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
</head>
<body>
${body}
</body>
</html>
`;
}

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

/**
 * The panel is served from its own port, so the browser only hands it the token
 * response when that response says the panel's origin may read it. The set of
 * origins is exactly the registered redirect URIs - the same list `/authorize`
 * already trusts - so this opens nothing `/authorize` had not already opened.
 */
function corsOrigin(req) {
  const origin = req.headers.origin;
  if (typeof origin !== "string" || origin === "") return null;
  for (const allowed of redirectAllowList()) {
    try {
      if (new URL(allowed).origin === origin) return origin;
    } catch {
      // an unparsable entry in the list is not an invitation
    }
  }
  return null;
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

/** Same allow-list as the body's `loopbackHostDecision`: 127.0.0.1, localhost, [::1], with the listen port. */
function issuerHostDecision(hostHeader, bindPort) {
  if (hostHeader === undefined || String(hostHeader).trim() === "") return "deny";
  const raw = String(hostHeader).trim();
  if (raw.startsWith("[") && !raw.includes("]")) return "malformed";
  let name = raw;
  let port;
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    name = raw.slice(1, end);
    const rest = raw.slice(end + 1);
    if (rest === "") port = undefined;
    else if (/^:[0-9]+$/.test(rest)) port = Number(rest.slice(1));
    else return "deny";
  } else {
    const colon = raw.lastIndexOf(":");
    if (colon > 0 && /^[0-9]+$/.test(raw.slice(colon + 1))) {
      name = raw.slice(0, colon);
      port = Number(raw.slice(colon + 1));
    }
  }
  const lowered = name.toLowerCase();
  if (lowered !== "127.0.0.1" && lowered !== "localhost" && lowered !== "::1") return "deny";
  if (port === undefined) return bindPort === 80 ? "allow" : "deny";
  return port === bindPort ? "allow" : "deny";
}

/** `operator` carries `verax:approve`. `agent` is a valid issuer token without it. `none` did not verify. */
async function bearerRevokeRole(req) {
  const raw = req.headers.authorization;
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return "none";
  try {
    const { payload } = await jwtVerify(header.slice("Bearer ".length), verifyKey, { issuer, audience });
    const scope = typeof payload.scope === "string" ? payload.scope : "";
    const parts = scope.split(/\s+/).filter((part) => part !== "");
    return parts.includes("verax:approve") ? "operator" : "agent";
  } catch {
    return "none";
  }
}

const server = createServer((req, res) => {
  void (async () => {
    const bound = server.address();
    const listenPort = bound && typeof bound === "object" ? bound.port : port;
    const hostHeader = Array.isArray(req.headers.host) ? req.headers.host[0] : req.headers.host;
    if (issuerHostDecision(hostHeader, listenPort) !== "allow") {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const allowOrigin = corsOrigin(req);
    if (allowOrigin) {
      res.setHeader("access-control-allow-origin", allowOrigin);
      res.setHeader("vary", "origin");
    }
    if (req.method === "OPTIONS") {
      if (!allowOrigin) {
        res.writeHead(403);
        res.end();
        return;
      }
      res.writeHead(204, {
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "600",
      });
      res.end();
      return;
    }
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
      if (hasRegisteredOperator(stateDir)) {
        if (!rp.ok) {
          sendJson(res, 503, { error: "passkey-closed", reason: rp.reason });
          return;
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(
          htmlPage(
            "Sign in",
            `<p>A registered operator must sign in with a passkey.</p>
<form id="signin" data-query="${String(url.search).replaceAll('"', "&quot;")}">
  <button type="submit">Sign in with passkey</button>
</form>
<p id="out"></p>
<script type="module">
  import { startAuthentication } from "/vendor/@simplewebauthn/browser/esm/index.js";
  const form = document.getElementById("signin");
  const out = document.getElementById("out");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    out.textContent = "";
    const opt = await fetch("/authorize/options", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const options = await opt.json();
    if (!opt.ok) { out.textContent = options.error ?? "options-failed"; return; }
    let assertion;
    try { assertion = await startAuthentication({ optionsJSON: options }); }
    catch (err) { out.textContent = "cancelled"; return; }
    const q = new URLSearchParams(form.dataset.query ?? "");
    const done = await fetch("/authorize/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        response: assertion,
        response_type: q.get("response_type"),
        client_id: q.get("client_id"),
        redirect_uri: q.get("redirect_uri"),
        code_challenge: q.get("code_challenge"),
        code_challenge_method: q.get("code_challenge_method"),
        state: q.get("state"),
      }),
    });
    const body = await done.json();
    if (!done.ok || typeof body.location !== "string") { out.textContent = body.error ?? "verify-failed"; return; }
    window.location.assign(body.location);
  });
</script>`,
          ),
        );
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
      const accessToken = await mintAccessToken("session", {
        grantApprove: row.grantApprove === true,
        sub: row.sub,
      });
      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 600,
      });
      return;
    }
    if (req.method === "GET" && url.pathname.startsWith("/vendor/@simplewebauthn/browser/")) {
      const rel = url.pathname.slice("/vendor/@simplewebauthn/browser/".length);
      if (rel.includes("..") || rel.includes("\\")) {
        res.writeHead(404);
        res.end();
        return;
      }
      const vendorRoot = resolve(repoRoot, "node_modules", "@simplewebauthn", "browser");
      const file = resolve(vendorRoot, rel);
      const relToRoot = relative(vendorRoot, file);
      if (relToRoot.startsWith("..") || relToRoot === "" || !existsSync(file)) {
        res.writeHead(404);
        res.end();
        return;
      }
      const body = readFileSync(file);
      res.writeHead(200, { "content-type": rel.endsWith(".js") ? "text/javascript; charset=utf-8" : "application/octet-stream" });
      res.end(body);
      return;
    }
    if (req.method === "GET" && url.pathname === "/enroll") {
      if (!rp.ok) {
        sendJson(res, 503, { error: "passkey-closed", reason: rp.reason });
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        htmlPage(
          "Enroll",
          `<p>Enter the pairing code printed on the desk. The passkey is created on this device.</p>
<form id="enroll">
  <label>Pairing code <input name="code" inputmode="numeric" maxlength="8" autocomplete="one-time-code"></label>
  <button type="submit">Create passkey</button>
</form>
<p id="out"></p>
<script type="module">
  import { startRegistration } from "/vendor/@simplewebauthn/browser/esm/index.js";
  const form = document.getElementById("enroll");
  const out = document.getElementById("out");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    out.textContent = "";
    const code = new FormData(form).get("code");
    const opt = await fetch("/enroll/options", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code }),
    });
    const options = await opt.json();
    if (!opt.ok) { out.textContent = options.error ?? "options-failed"; return; }
    let attestation;
    try { attestation = await startRegistration({ optionsJSON: options }); }
    catch (err) { out.textContent = "cancelled"; return; }
    const done = await fetch("/enroll/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code, response: attestation }),
    });
    const body = await done.json();
    out.textContent = done.ok ? "enrolled" : (body.error ?? "verify-failed");
  });
</script>`,
        ),
      );
      return;
    }
    if (req.method === "POST" && url.pathname === "/enroll/options") {
      if (!rp.ok) {
        sendJson(res, 503, { error: "passkey-closed", reason: rp.reason });
        return;
      }
      let parsed;
      try {
        parsed = await readJson(req);
      } catch {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const code = typeof parsed.code === "string" ? parsed.code : "";
      const checked = checkPairing(stateDir, code);
      if (!checked.ok) {
        sendJson(res, 400, { error: checked.reason });
        return;
      }
      pruneWebauthn();
      const { generateRegistrationOptions } = await webauthn();
      const options = await generateRegistrationOptions({
        rpName: "Verax",
        rpID: rp.config.rpID,
        userName: DEFAULT_OPERATOR_SUB,
        userDisplayName: DEFAULT_OPERATOR_SUB,
        attestationType: "none",
        authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      });
      enrollChallenges.set(options.challenge, { challenge: options.challenge, expiresAtMs: Date.now() + CODE_TTL_MS });
      sendJson(res, 200, options);
      return;
    }
    if (req.method === "POST" && url.pathname === "/enroll/verify") {
      if (!rp.ok) {
        sendJson(res, 503, { error: "passkey-closed", reason: rp.reason });
        return;
      }
      let parsed;
      try {
        parsed = await readJson(req);
      } catch {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const code = typeof parsed.code === "string" ? parsed.code : "";
      const checked = checkPairing(stateDir, code);
      if (!checked.ok) {
        sendJson(res, 400, { error: checked.reason });
        return;
      }
      const response = parsed.response;
      if (!response || typeof response !== "object") {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      pruneWebauthn();
      const { verifyRegistrationResponse, isoBase64URL } = await webauthn();
      let verified;
      try {
        verified = await verifyRegistrationResponse({
          response,
          expectedChallenge: (challenge) => {
            const row = enrollChallenges.get(challenge);
            if (!row || Date.now() > row.expiresAtMs) return false;
            enrollChallenges.delete(challenge);
            return true;
          },
          expectedOrigin: rp.config.origins,
          expectedRPID: rp.config.rpID,
          requireUserVerification: true,
        });
      } catch {
        sendJson(res, 400, { error: "verification-failed" });
        return;
      }
      if (!verified.verified || !verified.registrationInfo) {
        sendJson(res, 400, { error: "verification-failed" });
        return;
      }
      const cred = verified.registrationInfo.credential;
      saveCredential(stateDir, {
        id: cred.id,
        publicKey: isoBase64URL.fromBuffer(cred.publicKey),
        counter: cred.counter,
        sub: DEFAULT_OPERATOR_SUB,
      });
      consumePairing(stateDir);
      sendJson(res, 200, { enrolled: true, sub: DEFAULT_OPERATOR_SUB });
      return;
    }
    if (req.method === "POST" && url.pathname === "/authorize/options") {
      if (!hasRegisteredOperator(stateDir)) {
        sendJson(res, 400, { error: "no-operator" });
        return;
      }
      if (!rp.ok) {
        sendJson(res, 503, { error: "passkey-closed", reason: rp.reason });
        return;
      }
      pruneWebauthn();
      const { generateAuthenticationOptions } = await webauthn();
      const options = await generateAuthenticationOptions({
        rpID: rp.config.rpID,
        userVerification: "required",
      });
      signinChallenges.set(options.challenge, { challenge: options.challenge, expiresAtMs: Date.now() + CODE_TTL_MS });
      sendJson(res, 200, options);
      return;
    }
    if (req.method === "POST" && url.pathname === "/authorize/verify") {
      if (!hasRegisteredOperator(stateDir)) {
        sendJson(res, 400, { error: "no-operator" });
        return;
      }
      if (!rp.ok) {
        sendJson(res, 503, { error: "passkey-closed", reason: rp.reason });
        return;
      }
      let parsed;
      try {
        parsed = await readJson(req);
      } catch {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const responseType = parsed.response_type;
      const clientId = parsed.client_id;
      const redirectUri = parsed.redirect_uri;
      const challenge = parsed.code_challenge;
      const method = parsed.code_challenge_method;
      const state = parsed.state;
      if (responseType !== "code" || !clientId || typeof redirectUri !== "string") {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      if (!challenge || method !== "S256" || !redirectAllowed(redirectUri)) {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const assertion = parsed.response;
      if (!assertion || typeof assertion !== "object" || typeof assertion.id !== "string") {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      const stored = findCredential(stateDir, assertion.id);
      if (!stored) {
        sendJson(res, 400, { error: "unknown-credential" });
        return;
      }
      const { verifyAuthenticationResponse, isoBase64URL } = await webauthn();
      let verified;
      try {
        verified = await verifyAuthenticationResponse({
          response: assertion,
          expectedChallenge: (chal) => {
            const row = signinChallenges.get(chal);
            if (!row || Date.now() > row.expiresAtMs) return false;
            signinChallenges.delete(chal);
            return true;
          },
          expectedOrigin: rp.config.origins,
          expectedRPID: rp.config.rpID,
          requireUserVerification: true,
          credential: {
            id: stored.id,
            publicKey: isoBase64URL.toBuffer(stored.publicKey),
            counter: stored.counter,
          },
        });
      } catch {
        sendJson(res, 400, { error: "verification-failed" });
        return;
      }
      if (!verified.verified) {
        sendJson(res, 400, { error: "verification-failed" });
        return;
      }
      const nextCounter = verified.authenticationInfo.newCounter;
      if (!updateCounter(stateDir, stored.id, nextCounter)) {
        sendJson(res, 400, { error: "cloned-authenticator" });
        return;
      }
      pruneCodes();
      const code = randomBytes(32).toString("base64url");
      codes.set(code, {
        challenge,
        redirectUri,
        expiresAtMs: Date.now() + CODE_TTL_MS,
        grantApprove: true,
        sub: stored.sub,
      });
      const loc = new URL(redirectUri);
      loc.searchParams.set("code", code);
      if (typeof state === "string" && state !== "") loc.searchParams.set("state", state);
      sendJson(res, 200, { location: loc.toString(), sub: stored.sub });
      return;
    }
    if (req.method === "POST" && url.pathname === "/revoke") {
      const role = await bearerRevokeRole(req);
      if (role === "none") {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      if (role !== "operator") {
        sendJson(res, 403, { error: "operator-scope-required" });
        return;
      }
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

trace("listen-called");
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(port, "127.0.0.1", resolve);
});

const bound = server.address();
const listenPort = bound && typeof bound === "object" ? bound.port : port;
process.stderr.write(`dev-issuer listening on http://127.0.0.1:${listenPort}/.well-known/jwks.json\n`);
