import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beginWinOwnerRun, endWinOwnerRun, ensureTokenParent, mkdirLeaf, restrictToOwnerWin32, SystemToolError } from "./install.ts";
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
  const parsed: Array<[string, string]> = [];
  for (const line of text.split(/\r?\n/)) {
    let trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("export ")) trimmed = trimmed.slice("export ".length).trim();
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || !key.startsWith("VERAX_")) {
      return { ok: false, reason: `env file refuses ${key}` };
    }
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    parsed.push([key, value]);
  }
  for (const key of Object.keys(env)) {
    if (key.startsWith("VERAX_")) delete env[key];
  }
  for (const [key, value] of parsed) env[key] = value;
  return { ok: true };
}

/** `serve --env-file` refuses a file that names neither JWKS source. */
export function envFileJwksMissing(env: NodeJS.ProcessEnv): string | null {
  const file = env.VERAX_JWKS_FILE?.trim() ?? "";
  const url = env.VERAX_JWKS_URL?.trim() ?? "";
  if (file === "" && url === "") return "env file sets neither VERAX_JWKS_FILE nor VERAX_JWKS_URL";
  return null;
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

/** POSIX keeps owner-only mode. Windows grants the current user only outside install mode. */
function ownerOnly(path: string, grantOwner: boolean): void {
  if (process.platform === "win32") {
    if (grantOwner) restrictToOwnerWin32(path);
    return;
  }
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

export type InitLocalOpts = {
  /** Write the agent token here and leave no copy under the state directory. */
  tokenPath?: string;
  /** Installed body prints its own summary. Skip this command's user-facing text. */
  quiet?: boolean;
  /**
   * Install mode. State files inherit the state directory ACL (svc, Administrators, SYSTEM).
   * Do not grant the invoking user and do not call `restrictToOwnerWin32`.
   * The profile token is locked by the install plan, not here.
   */
  noOwnerGrant?: boolean;
  /** Install mode. Defaults to process.env. SUDO_USER names the POSIX owner. */
  env?: NodeJS.ProcessEnv;
};

export async function runInitLocal(
  argv: readonly string[],
  io: InitIo = { stdout: process.stdout, stderr: process.stderr },
  opts: InitLocalOpts = {},
): Promise<number> {
  beginWinOwnerRun();
  try {
  return await runInitLocalBody(argv, io, opts);
  } finally {
    endWinOwnerRun();
  }
}

async function runInitLocalBody(
  argv: readonly string[],
  io: InitIo,
  opts: InitLocalOpts,
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

  const createdState = !existsSync(stateDir);
  const wrote: string[] = [];
  const rollback = (): void => {
    if (createdState) {
      rmSync(stateDir, { recursive: true, force: true });
      return;
    }
    for (const p of [...wrote].reverse()) rmSync(p, { force: true });
    rmSync(issuerDir, { recursive: true, force: true });
  };
  const grantOwner = opts.noOwnerGrant !== true;
  try {
  if (createdState) mkdirLeaf(stateDir, 0o700);
  if (process.platform === "win32" && grantOwner) restrictToOwnerWin32(stateDir);
  mkdirLeaf(issuerDir, 0o700);
  const keyPath = join(issuerDir, "key.pem");
  const jwksPath = join(issuerDir, "jwks.json");
  const insideToken = join(issuerDir, "agent.token");
  const external = opts.tokenPath !== undefined && resolve(opts.tokenPath) !== resolve(insideToken);
  const tokenPath = external ? resolve(opts.tokenPath!) : insideToken;
  if (external) ensureTokenParent(dirname(tokenPath), opts.env ?? process.env);
  const envPath = join(stateDir, "verax.env");
  writeFileSync(keyPath, pem, { encoding: "utf8", mode: 0o600 });
  wrote.push(keyPath);
  ownerOnly(keyPath, grantOwner);
  writeFileSync(jwksPath, `${JSON.stringify({ keys: [publicJwk] })}\n`, { encoding: "utf8", mode: 0o600 });
  wrote.push(jwksPath);
  ownerOnly(jwksPath, grantOwner);
  writeFileSync(tokenPath, token, { encoding: "utf8", mode: 0o600 });
  wrote.push(tokenPath);
  ownerOnly(tokenPath, grantOwner);
  if (external && existsSync(insideToken)) unlinkSync(insideToken);

  if (!existsSync(policyDest) && policySrc) {
    writeFileSync(policyDest, readFileSync(policySrc));
    wrote.push(policyDest);
    ownerOnly(policyDest, grantOwner);
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
  ownerOnly(envPath, grantOwner);

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
  if (!opts.quiet) io.stdout.write(lines.join("\n"));
  return 0;
  } catch (err) {
    const externalToken = wrote.find((p) => !p.startsWith(stateDir));
    rollback();
    if (externalToken) rmSync(externalToken, { force: true });
    const detail = err instanceof Error ? err.message : "owner-only failed";
    io.stderr.write(`${detail}\n`);
    return err instanceof SystemToolError ? EX_CONFIG : 1;
  }
}
