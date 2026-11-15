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
};

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

  return { tokens, privateKeyPem, publicKeyPem, storePath, host, port, ratePerMinute };
}
