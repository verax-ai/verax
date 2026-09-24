import { readFileSync } from "node:fs";
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Principal } from "@verax-ai/proxy";

const ALGS = ["ES256", "EdDSA"] as const;

export type VerifiedBearer = {
  principal: Principal;
  payload: JWTPayload;
};

export function resourceMetadataUrl(audience: string): string {
  const u = new URL(audience);
  const path = u.pathname.replace(/\/+$/, "").replace(/^\/+/, "");
  if (path === "") {
    return `${u.origin}/.well-known/oauth-protected-resource`;
  }
  return `${u.origin}/.well-known/oauth-protected-resource/${path}`;
}

export function wwwAuthenticate(audience: string): string {
  return `Bearer resource_metadata="${resourceMetadataUrl(audience)}"`;
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
) {
  const jwks = jwksFile ? localJwks(jwksFile) : createRemoteJWKSet(new URL(jwksUrl));
  return async (token: string): Promise<VerifiedBearer> => {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience,
      algorithms: [...ALGS],
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
