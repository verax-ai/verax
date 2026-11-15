/**
 * Configuration from the environment. Missing or unreadable required values
 * refuse to start with exit 64.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";

import { loadTokenMap, type TokenMap } from "./auth.ts";
import { publicKeyPemFromPrivate } from "./receipt.ts";

export const EX_USAGE = 64;

export type ServiceConfig = {
  tokens: TokenMap;
  privateKeyPem: string;
  publicKeyPem: string;
  storePath: string;
  host: string;
  port: number;
  ratePerMinute: number;
  /** Milliseconds to wait for request headers (Node `headersTimeout`). */
  headersTimeoutMs: number;
  /** Milliseconds for the whole request including the body (Node `requestTimeout`). */
  requestTimeoutMs: number;
  /** Idle keep-alive timeout (Node `keepAliveTimeout`). */
  keepAliveTimeoutMs: number;
  /** Max concurrent TCP connections (Node `maxConnections`). */
  maxConnections: number;
};

const DEFAULT_HEADERS_TIMEOUT_MS = 10_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_KEEP_ALIVE_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_CONNECTIONS = 64;

function boundedInt(
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number,
  name: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer ${min}..${max}`);
  }
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServiceConfig {
  const tokensPath = env.VERAX_ANCHOR_SVC_TOKENS?.trim() ?? "";
  if (tokensPath === "") throw new Error("VERAX_ANCHOR_SVC_TOKENS is required (JSON file of token digests to owner ids)");
  const tokens = loadTokenMap(tokensPath);

  const keyPath = env.VERAX_ANCHOR_SVC_SIGNING_KEY?.trim() ?? "";
  if (keyPath === "") throw new Error("VERAX_ANCHOR_SVC_SIGNING_KEY is required (private key PEM file)");
  let privateKeyPem: string;
  try {
    privateKeyPem = readFileSync(keyPath, "utf8");
  } catch {
    throw new Error(`cannot read VERAX_ANCHOR_SVC_SIGNING_KEY file ${keyPath}`);
  }
  try {
    const key = createPrivateKey(privateKeyPem);
    if (key.asymmetricKeyType !== "ed25519") throw new Error("not ed25519");
    createPublicKey(key);
  } catch {
    throw new Error(`VERAX_ANCHOR_SVC_SIGNING_KEY file ${keyPath} is not an Ed25519 private key`);
  }
  const publicKeyPem = publicKeyPemFromPrivate(privateKeyPem);

  const storePath = env.VERAX_ANCHOR_SVC_STORE?.trim() ?? "";
  if (storePath === "") throw new Error("VERAX_ANCHOR_SVC_STORE is required (append-only JSONL path)");

  const host = (env.VERAX_ANCHOR_SVC_HOST?.trim() || "127.0.0.1");
  const portRaw = env.VERAX_ANCHOR_SVC_PORT?.trim() || "8798";
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("VERAX_ANCHOR_SVC_PORT must be an integer 0..65535");
  }

  const rateRaw = env.VERAX_ANCHOR_SVC_RATE?.trim() || "60";
  const ratePerMinute = Number(rateRaw);
  if (!Number.isInteger(ratePerMinute) || ratePerMinute < 1) {
    throw new Error("VERAX_ANCHOR_SVC_RATE must be a positive integer");
  }

  const headersTimeoutMs = boundedInt(
    env.VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS,
    DEFAULT_HEADERS_TIMEOUT_MS,
    100,
    120_000,
    "VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS",
  );
  const requestTimeoutMs = boundedInt(
    env.VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS,
    DEFAULT_REQUEST_TIMEOUT_MS,
    100,
    300_000,
    "VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS",
  );
  const keepAliveTimeoutMs = boundedInt(
    env.VERAX_ANCHOR_SVC_KEEP_ALIVE_TIMEOUT_MS,
    DEFAULT_KEEP_ALIVE_TIMEOUT_MS,
    100,
    120_000,
    "VERAX_ANCHOR_SVC_KEEP_ALIVE_TIMEOUT_MS",
  );
  const maxConnections = boundedInt(
    env.VERAX_ANCHOR_SVC_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS,
    1,
    10_000,
    "VERAX_ANCHOR_SVC_MAX_CONNECTIONS",
  );
  if (requestTimeoutMs < headersTimeoutMs) {
    throw new Error("VERAX_ANCHOR_SVC_REQUEST_TIMEOUT_MS must be >= VERAX_ANCHOR_SVC_HEADERS_TIMEOUT_MS");
  }

  return {
    tokens,
    privateKeyPem,
    publicKeyPem,
    storePath,
    host,
    port,
    ratePerMinute,
    headersTimeoutMs,
    requestTimeoutMs,
    keepAliveTimeoutMs,
    maxConnections,
  };
}
