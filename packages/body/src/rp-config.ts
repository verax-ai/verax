export type RpConfig = {
  rpID: string;
  origins: string[];
};

/**
 * WebAuthn will not take an IP address as an RP ID. The values come from the
 * environment so a machine name never has to be written into the source.
 */
export function readRpConfig(
  env: NodeJS.ProcessEnv = process.env,
): { ok: true; config: RpConfig } | { ok: false; reason: string } {
  const rpID = (env.VERAX_RP_ID ?? "").trim();
  const rawOrigins = (env.VERAX_RP_ORIGINS ?? "").trim();
  if (rpID === "") {
    return { ok: false, reason: "VERAX_RP_ID is unset" };
  }
  if (rawOrigins === "") {
    return { ok: false, reason: "VERAX_RP_ORIGINS is unset" };
  }
  const origins = rawOrigins
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  if (origins.length === 0) {
    return { ok: false, reason: "VERAX_RP_ORIGINS is empty" };
  }
  for (const origin of origins) {
    try {
      new URL(origin);
    } catch {
      return { ok: false, reason: `VERAX_RP_ORIGINS has an unparsable origin` };
    }
  }
  return { ok: true, config: { rpID, origins } };
}
