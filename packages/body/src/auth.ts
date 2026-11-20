import { readFileSync } from "node:fs";
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";
import type { Principal } from "@verax-ai/proxy";

/**
 * Accepted signature algorithms for agent tokens. RS256 is the default of most
 * hosted identity providers; jose refuses an RSA key under 2048 bits when it
 * verifies, and checks that the key type matches the algorithm. HS* and `none`
 * are not in the list, so a token signed with a shared secret is refused.
 */
export const AGENT_TOKEN_ALGS = ["ES256", "EdDSA", "RS256"] as const;

export type VerifiedBearer = {
  principal: Principal;
  payload: JWTPayload;
};

/**
 * The protected-resource metadata URL for this audience (RFC 9728), or null
 * when the audience is not an http(s) URL. A token audience may be any
 * string, but only a URL names a resource whose metadata a client can fetch.
 */
export function resourceMetadataUrl(audience: string): string | null {
  let u: URL;
  try {
    u = new URL(audience);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  const path = u.pathname.replace(/\/+$/, "").replace(/^\/+/, "");
  if (path === "") {
    return `${u.origin}/.well-known/oauth-protected-resource`;
  }
  return `${u.origin}/.well-known/oauth-protected-resource/${path}`;
}

/** A 401's challenge. Without a URL audience there is no metadata to point at. */
export function wwwAuthenticate(audience: string): string {
  const metadata = resourceMetadataUrl(audience);
  return metadata === null ? "Bearer" : `Bearer resource_metadata="${metadata}"`;
}

function localJwks(path: string): ReturnType<typeof createLocalJWKSet> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch {
    throw new JwksFileError();
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    !Array.isArray((parsed as { keys?: unknown }).keys) ||
    (parsed as { keys: unknown[] }).keys.length === 0
  ) {
    throw new JwksFileError();
  }
  return createLocalJWKSet(parsed as Parameters<typeof createLocalJWKSet>[0]);
}

export class JwksFileError extends Error {
  readonly code = 78;
  constructor(message = "VERAX_JWKS_FILE is missing or unparsable") {
    super(message);
    this.name = "JwksFileError";
  }
}

export function createVerifier(
  jwksUrl: string,
  issuer: string,
  audience: string,
  jwksFile?: string | null,
  /**
   * Keys fetched once, before this process started accepting tokens.
   * `createLocalJWKSet` does not refetch. A `kid` that was not in this set
   * fails closed. This is not `VERAX_JWKS_FILE`: that mode refuses operator scopes.
   */
  jwksPin?: { keys: Record<string, unknown>[] } | null,
) {
  const jwks = jwksFile
    ? localJwks(jwksFile)
    : jwksPin
      ? createLocalJWKSet(jwksPin as JSONWebKeySet)
      : createRemoteJWKSet(new URL(jwksUrl));
  return async (token: string): Promise<VerifiedBearer> => {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience,
      algorithms: [...AGENT_TOKEN_ALGS],
      requiredClaims: ["exp", "iat", "sub"],
      clockTolerance: 60,
    });
    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.iat === "number" && payload.iat > nowSec + 60) {
      throw new Error("iat-in-future");
    }
    const sub = typeof payload.sub === "string" ? payload.sub : "";
    if (sub === "") {
      throw new Error("missing-sub");
    }
    const scopes = new Set<string>();
    if (typeof payload.scope === "string") {
      for (const part of payload.scope.split(/\s+/)) {
        if (part !== "") scopes.add(part);
      }
    }
    const iss = typeof payload.iss === "string" ? payload.iss : undefined;
    const tenant = typeof payload.tenant === "string" && payload.tenant !== "" ? payload.tenant : undefined;
    const org = typeof payload.org === "string" && payload.org !== "" ? payload.org : undefined;
    return {
      principal: {
        brain: sub,
        scopes,
        ...(iss ? { iss } : {}),
        ...(tenant ? { tenant } : {}),
        ...(org ? { org } : {}),
      },
      payload,
    };
  };
}

export function readBearer(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(\S+)/i.exec(header);
  return match ? match[1] : null;
}
