import { sha256Canonical } from "./hash.ts";

/** Fields that enter the tenant key. `aud` is intentionally absent. */
export type TenantPrincipal = {
  brain: string;
  iss?: string;
  tenant?: string;
  org?: string;
};

/**
 * SHA-256 of `{ iss, sub }` plus `tenant` or `org` when present.
 * `aud` is not a field and must not be added: it names the body.
 */
export function tenantKey(principal: TenantPrincipal): string {
  const material: Record<string, string> = {
    iss: principal.iss ?? "",
    sub: principal.brain,
  };
  if (typeof principal.tenant === "string" && principal.tenant !== "") {
    material.tenant = principal.tenant;
  } else if (typeof principal.org === "string" && principal.org !== "") {
    material.org = principal.org;
  }
  return sha256Canonical(material);
}
