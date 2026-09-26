#!/usr/bin/env node
// Development only. One process for a sandbox that cannot hold a token of its
// own, such as a directory's build check: it starts the dev issuer and the body
// on loopback with a temporary ledger, mints itself a short-lived session token
// through the issuer's code flow, and speaks MCP over stdio, forwarding
// tools/list and tools/call to the body's /mcp with that token. The body is not
// changed by this: it still opens only to a verified token, and every call still
// passes the gate and is recorded. Nothing leaves the machine: message.send only
// queues, spend is always held for an operator, and no operator is here.
// NODE_ENV=production exits, as the issuer does. Not a deployment of Verax.
//
// Ports: VERAX_DEMO_ISSUER_PORT (default 8790) and VERAX_DEMO_BODY_PORT
// (default 8787), loopback only. Everything written goes to a directory under
// the OS temp directory and is removed on exit. Nothing is printed to stdout
// but protocol; the token is never printed anywhere.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { get } from "node:http";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

if (process.env.NODE_ENV === "production") {
  process.stderr.write("demo-box refuses NODE_ENV=production\n");
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const issuerPort = Number(process.env.VERAX_DEMO_ISSUER_PORT ?? "8790");
const bodyPort = Number(process.env.VERAX_DEMO_BODY_PORT ?? "8787");
for (const p of [issuerPort, bodyPort]) {
  if (!Number.isInteger(p) || p <= 0 || p >= 65536) {
    process.stderr.write("demo-box: VERAX_DEMO_ISSUER_PORT and VERAX_DEMO_BODY_PORT must be ports\n");
    process.exit(78);
  }
}
const issuerUrl = `http://127.0.0.1:${issuerPort}`;
const audience = `http://127.0.0.1:${bodyPort}`;
// The redirect is a string the issuer compares against its allow-list; nothing listens there.
const redirectUri = "http://127.0.0.1:8791/callback";
// Session tokens live ten minutes; a fresh one is minted before the old one is that old.
const TOKEN_MAX_AGE_MS = 8 * 60_000;
const START_TIMEOUT_MS = 20_000;

const version = JSON.parse(readFileSync(join(repoRoot, "packages", "body", "package.json"), "utf8")).version;

const INSTRUCTIONS =
  "Verax sandbox: a development issuer and the Verax body run inside this process's machine on loopback, " +
  "with a temporary ledger that is discarded on exit. Every tool call passes the policy gate and leaves a signed decision record. " +
  "spend is always held for an operator (deferred:approval-required:<ref>) and no operator is here to approve it; " +
  "message.send only queues, and only for hosts on the sandbox policy's egress list (example.com). " +
  "Nothing leaves this machine. This is a demonstration of the body, not a deployment of it.";

// Six tools, all reachable with the scopes the sandbox token carries. spend and
// message.send are not in the default policy; the sandbox names them so a caller
// can see the gate answer, with a payee list and an egress list of one each.
const DEMO_POLICY = {
  version: 1,
  default: "deny",
  egress: ["example.com"],
  rules: [
    { id: "memory-get", tool: "memory.get", requires: ["verax:read"], text: "Reading memory needs the read scope." },
    { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope." },
    { id: "audit-explain", tool: "audit.explain", requires: ["verax:read"], text: "Reading an explanation needs the read scope." },
    { id: "message-read", tool: "message.read", requires: ["verax:read"], text: "Reading the inbox needs the read scope." },
    {
      id: "message-send",
      tool: "message.send",
      requires: ["verax:memory"],
      egress: true,
      text: "Queueing a message needs the memory scope and a recipient host on the egress list.",
    },
    {
      id: "spend",
      tool: "spend",
      requires: ["verax:pay"],
      mode: "approve",
      text: "A payment is held for an operator.",
      spend: { maxAmountMinor: 5000, currency: "USD", payees: ["sample-merchant"], dailyMaxMinor: 10000 },
    },
  ],
};

const log = (s) => process.stderr.write(`demo-box: ${s}\n`);

const stateDir = mkdtempSync(join(tmpdir(), "verax-demo-"));
const policyFile = join(stateDir, "policy.json");
writeFileSync(policyFile, `${JSON.stringify(DEMO_POLICY, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

let token = "";
let mintedAtMs = 0;
let stopping = false;
const kids = [];

function shutdown(code) {
  if (stopping) return;
  stopping = true;
  for (const kid of kids) {
    try {
      kid.kill();
    } catch {
      // gone
    }
  }
  try {
    rmSync(stateDir, { recursive: true, force: true });
  } catch {
    // the OS temp directory is cleaned by its owner
  }
  process.exit(code);
}

/** Child output goes to our stderr, never stdout, and never with the token in it. */
function forward(chunk) {
  let text = String(chunk);
  if (token !== "" && text.includes(token)) text = text.split(token).join("[token]");
  process.stderr.write(text);
}

function spawnChild(label, args, env) {
  const child = spawn(process.execPath, args, {
    cwd: repoRoot,
    env: { ...env, NO_COLOR: "1", FORCE_COLOR: "0" },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.on("data", forward);
  child.stderr.on("data", forward);
  child.on("exit", (code, signal) => {
    if (stopping) return;
    log(`${label} exited (${code ?? signal}); stopping`);
    shutdown(1);
  });
  kids.push(child);
  return child;
}

function portOpen(port) {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host: "127.0.0.1" });
    sock.once("connect", () => {
      sock.end();
      resolve(true);
    });
    sock.once("error", () => resolve(false));
  });
}

function healthzUp(port) {
  return new Promise((resolve) => {
    const req = get({ host: "127.0.0.1", port, path: "/healthz", timeout: 3_000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.once("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.once("error", () => resolve(false));
  });
}

async function waitFor(probe, ms) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (await probe()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/** The issuer's own code flow, as a panel or a brain would run it. */
async function mintToken() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const q = new URLSearchParams({
    response_type: "code",
    client_id: "demo-box",
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const auth = await fetch(`${issuerUrl}/authorize?${q}`, { redirect: "manual" });
  const location = auth.headers.get("location");
  if (auth.status < 300 || auth.status >= 400 || !location) throw new Error(`authorize ${auth.status}`);
  const code = new URL(location).searchParams.get("code");
  if (!code) throw new Error("authorize gave no code");
  const tok = await fetch(`${issuerUrl}/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }),
  });
  const body = await tok.json();
  if (!tok.ok || typeof body.access_token !== "string") throw new Error(`token ${tok.status}`);
  token = body.access_token;
  mintedAtMs = Date.now();
}

// The transport reads this object on every request, so a fresh token takes
// effect without a new session.
const headers = { authorization: "" };

async function ensureToken() {
  if (token === "" || Date.now() - mintedAtMs > TOKEN_MAX_AGE_MS) {
    await mintToken();
    headers.authorization = `Bearer ${token}`;
  }
}

process.once("SIGINT", () => shutdown(1));
process.once("SIGTERM", () => shutdown(1));
process.stdin.once("end", () => shutdown(0));
process.stdin.once("close", () => shutdown(0));

try {
  const issuerEnv = {
    ...process.env,
    NODE_ENV: "development",
    VERAX_STATE_DIR: stateDir,
    VERAX_DEV_ISSUER_PORT: String(issuerPort),
    VERAX_ISSUER: issuerUrl,
    VERAX_AUDIENCE: audience,
    VERAX_DEV_REDIRECT_URIS: redirectUri,
    VERAX_DEV_SUB: "demo-brain",
    VERAX_DEV_OPERATOR_SUB: "demo-brain",
    // Audit is the passkey session, not this brain. The issuer would drop it anyway.
    VERAX_DEV_SCOPE: "verax:read verax:memory verax:pay",
  };
  delete issuerEnv.VERAX_DEV_TOKEN;
  spawnChild(
    "issuer",
    ["--experimental-strip-types", join(repoRoot, "scripts", "dev-issuer.mjs"), "--out", join(stateDir, "dev-token")],
    issuerEnv,
  );
  if (!(await waitFor(() => portOpen(issuerPort), START_TIMEOUT_MS))) throw new Error("issuer did not start");

  const bodyEnv = {
    ...process.env,
    VERAX_STATE_DIR: stateDir,
    VERAX_ISSUER: issuerUrl,
    VERAX_JWKS_URL: `${issuerUrl}/.well-known/jwks.json`,
    VERAX_AUDIENCE: audience,
    VERAX_BIND: `127.0.0.1:${bodyPort}`,
    VERAX_POLICY_FILE: policyFile,
  };
  delete bodyEnv.VERAX_DEV_TOKEN;
  delete bodyEnv.VERAX_INVENTORY_FILE;
  spawnChild("body", ["--experimental-strip-types", join(repoRoot, "packages", "body", "src", "main.ts")], bodyEnv);
  if (!(await waitFor(() => healthzUp(bodyPort), START_TIMEOUT_MS))) throw new Error("body did not start");

  await ensureToken();
  const client = new Client({ name: "verax-demo-box", version });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${audience}/mcp`), { requestInit: { headers } }),
  );

  const server = new Server({ name: "verax", version }, { capabilities: { tools: {} }, instructions: INSTRUCTIONS });
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    await ensureToken();
    return client.listTools();
  });
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    await ensureToken();
    return client.callTool({ name: request.params.name, arguments: request.params.arguments ?? {} });
  });
  await server.connect(new StdioServerTransport());
  log(`ready issuer=${issuerPort} body=${bodyPort} state=temporary`);
} catch (err) {
  log(`failed: ${err instanceof Error ? err.message : String(err)}`);
  shutdown(1);
}
