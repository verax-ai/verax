/**
 * Tokens are never stored. The operator's file maps SHA-256(token) hex to an
 * owner id; comparison is constant-time over the hash of the presented token.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

import { assertSecretFile, type AssertSecretFileOpts } from "./secret-file.ts";

const HASH = /^[0-9a-f]{64}$/;

export type TokenMap = Map<string, string>;

export function loadTokenMap(path: string, secretOpts?: AssertSecretFileOpts): TokenMap {
  assertSecretFile(path, "token map", secretOpts);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`cannot read token map`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`token map ${path} must be a JSON object`);
  }
  const map: TokenMap = new Map();
  for (const [hash, owner] of Object.entries(raw as Record<string, unknown>)) {
    if (!HASH.test(hash)) throw new Error(`token map ${path} has a key that is not a SHA-256 hex digest`);
    if (typeof owner !== "string" || owner === "") {
      throw new Error(`token map ${path} has an empty owner id`);
    }
    map.set(hash, owner);
  }
  return map;
}

/**
 * Returns the owner id for `token`, or null. Every map entry is compared so
 * the work does not stop early on the first match; only digests of equal
 * length use `timingSafeEqual`.
 */
export function ownerForToken(token: string, tokens: TokenMap): string | null {
  const digest = createHash("sha256").update(token, "utf8").digest();
  let owner: string | null = null;
  for (const [hex, id] of tokens) {
    const expected = Buffer.from(hex, "hex");
    if (expected.length === digest.length && timingSafeEqual(digest, expected)) {
      owner = id;
    }
  }
  return owner;
}

/** `Authorization: Bearer <token>`; anything else is absent. */
export function bearerToken(authorization: string | undefined): string | null {
  if (typeof authorization !== "string") return null;
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return match ? match[1]! : null;
}
