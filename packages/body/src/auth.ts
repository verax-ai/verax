import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
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

export function createVerifier(jwksUrl: string, issuer: string, audience: string) {
  const jwks = createRemoteJWKSet(new URL(jwksUrl));
  return async (token: string): Promise<VerifiedBearer> => {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience,
      algorithms: [...ALGS],
      requiredClaims: ["exp", "iat", "sub"],
      maxTokenAge: "1h",
      clockTolerance: 60,
    });
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
    return { principal: { brain: sub, scopes }, payload };
  };
}

export function readBearer(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(\S+)/i.exec(header);
  return match ? match[1] : null;
}
