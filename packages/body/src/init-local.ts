import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  calculateJwkThumbprint,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importPKCS8,
  SignJWT,
} from "jose";
import { EX_CONFIG } from "./config.ts";

const ISSUER = "verax-local";
const SUBJECT = "local-agent";
const SCOPE = "verax:read verax:memory";
const DEFAULT_DAYS = 30;
const MAX_DAYS = 90;
const DEFAULT_PORT = 8787;
const MIN_PORT = 1024;
const MAX_PORT = 65535;

export type InitIo = {
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
};

export function loadEnvFile(path: string, env: NodeJS.ProcessEnv = process.env): { ok: true } | { ok: false; reason: string } {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { ok: false, reason: "env file is missing or unreadable" };
  }
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    env[key] = value;
  }
  return { ok: true };
}

function shippedPolicyPath(): string | null {
  const here = dirname(fileURLToPath(import.meta.url));
  let resolved: string | null = null;
  try {
    resolved = join(dirname(fileURLToPath(import.meta.resolve("@verax-ai/proxy/package.json"))), "policy", "default.json");
  } catch {
    resolved = null;
  }
  const candidates = [
    resolved,
    join(here, "..", "..", "proxy", "policy", "default.json"),
    join(here, "..", "..", "@verax-ai", "proxy", "policy", "default.json"),
  ];
  for (const path of candidates) {
    if (path && existsSync(path)) return path;
  }
  return null;
}

function ownerOnly(path: string): void {
  try {
    chmodSync(path, 0o600);
  } catch {
    // The platform does not honour the mode bit.
  }
}

function slashPath(path: string): string {
  return path.replaceAll("\\", "/");
}

function shQuote(path: string): string {
  return `'${slashPath(path).replaceAll("'", "'\\''")}'`;
}

function psQuote(path: string): string {
  return `'${slashPath(path).replaceAll("'", "''")}'`;
}

function parseInitArgs(
  argv: readonly string[],
): { stateDir: string; force: boolean; days: number; port: number } | { error: string } {
  let stateDir = "";
  let force = false;
  let days = DEFAULT_DAYS;
  let port = DEFAULT_PORT;
  let sawDays = false;
  let sawPort = false;
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (a === "--local") {
      stateDir = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
    if (a === "--force") {
      force = true;
      continue;
    }
    if (a === "--days") {
      sawDays = true;
      const raw = argv[i + 1] ?? "";
      i += 1;
      if (!/^[0-9]+$/.test(raw)) return { error: "--days wants an integer from 1 to 90" };
      days = Number(raw);
      continue;
    }
    if (a === "--port") {
      sawPort = true;
      const raw = argv[i + 1] ?? "";
      i += 1;
      if (!/^[0-9]+$/.test(raw)) return { error: "--port wants an integer from 1024 to 65535" };
      port = Number(raw);
      continue;
    }
    return { error: `flag-unknown:${a}` };
  }
  if (stateDir === "" || stateDir.startsWith("-")) {
    return { error: "verax init --local <stateDir> [--force] [--days N] [--port N]" };
  }
  if (sawDays && (!Number.isInteger(days) || days < 1 || days > MAX_DAYS)) {
    return { error: "--days wants an integer from 1 to 90" };
  }
  if (sawPort && (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT)) {
    return { error: "--port wants an integer from 1024 to 65535" };
  }
  return { stateDir: resolve(stateDir), force, days, port };
}

export async function runInitLocal(
  argv: readonly string[],
  io: InitIo = { stdout: process.stdout, stderr: process.stderr },
): Promise<number> {
  const parsed = parseInitArgs(argv);
  if ("error" in parsed) {
    io.stderr.write(`${parsed.error}\n`);
    return EX_CONFIG;
  }
  const stateDir = parsed.stateDir;
  const issuerDir = join(stateDir, "local-issuer");
  if (existsSync(issuerDir) && !parsed.force) {
    io.stderr.write(`refusing: ${issuerDir} already exists\n`);
    return EX_CONFIG;
  }
  const policyDest = join(stateDir, "policy.json");
  const policySrc = existsSync(policyDest) ? null : shippedPolicyPath();
  if (!existsSync(policyDest) && !policySrc) {
    io.stderr.write("shipped policy file not found\n");
    return EX_CONFIG;
  }

  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const pem = await exportPKCS8(privateKey);
  const jwk = await exportJWK(publicKey);
  const thumb = await calculateJwkThumbprint(jwk, "sha256");
  const hex = Buffer.from(thumb, "base64url").toString("hex").slice(0, 8);
  const kid = `verax-local-${hex}`;
  const publicJwk = { ...jwk, alg: "ES256", use: "sig", kid };
  const key = await importPKCS8(pem, "ES256");
  const now = Math.floor(Date.now() / 1000);
  const origin = `http://127.0.0.1:${parsed.port}`;
  const token = await new SignJWT({ scope: SCOPE })
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuer(ISSUER)
    .setAudience(origin)
    .setSubject(SUBJECT)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + parsed.days * 24 * 60 * 60)
    .sign(key);

  mkdirSync(issuerDir, { recursive: true, mode: 0o700 });
  const keyPath = join(issuerDir, "key.pem");
  const jwksPath = join(issuerDir, "jwks.json");
  const tokenPath = join(issuerDir, "agent.token");
  const envPath = join(stateDir, "verax.env");
  writeFileSync(keyPath, pem, { encoding: "utf8", mode: 0o600 });
  ownerOnly(keyPath);
  writeFileSync(jwksPath, `${JSON.stringify({ keys: [publicJwk] })}\n`, { encoding: "utf8", mode: 0o600 });
  writeFileSync(tokenPath, token, { encoding: "utf8", mode: 0o600 });
  ownerOnly(tokenPath);

  const wrote: string[] = [keyPath, jwksPath, tokenPath];
  if (!existsSync(policyDest) && policySrc) {
    writeFileSync(policyDest, readFileSync(policySrc));
    wrote.push(policyDest);
  }
  const envBody = [
    `VERAX_ISSUER=${ISSUER}`,
    `VERAX_JWKS_FILE=${jwksPath}`,
    `VERAX_AUDIENCE=${origin}`,
    `VERAX_STATE_DIR=${stateDir}`,
    `VERAX_POLICY_FILE=${policyDest}`,
    `VERAX_BIND=127.0.0.1:${parsed.port}`,
    "",
  ].join("\n");
  writeFileSync(envPath, envBody, { encoding: "utf8" });
  wrote.push(envPath);

  const lines = [
    ...wrote.map((p) => `wrote ${p}`),
    "",
    "A shell as the same user can read this directory and approve its own calls, so for anything that matters run the body as another OS user or in a container, or keep the agent in a sandbox that cannot read the state directory.",
    "",
    "Start the body:",
    `verax serve --env-file ${shQuote(envPath)}`,
    "",
    "Claude Code (sh):",
    `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(cat ${shQuote(tokenPath)})"`,
    "",
    "Claude Code (PowerShell):",
    `claude mcp add --transport http verax ${origin}/mcp --header "Authorization: Bearer $(Get-Content -Raw ${psQuote(tokenPath)})"`,
    "",
    "Cursor / generic mcp.json:",
    `{
  "mcpServers": {
    "verax": {
      "url": "${origin}/mcp",
      "headers": { "Authorization": "Bearer <token from your issuer>" }
    }
  }
}`,
    `The token is the content of ${tokenPath}.`,
    "",
    "A held call is approved on this machine with: verax approve",
    "",
  ];
  io.stdout.write(lines.join("\n"));
  return 0;
}
