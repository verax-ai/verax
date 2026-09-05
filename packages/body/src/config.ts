export const EX_CONFIG = 78;

export type BodyConfig = {
  issuer: string;
  jwksUrl: string;
  audience: string;
  stateDir: string;
  bindHost: string;
  bindPort: number;
  policyFile: string;
  tlsTerminated: boolean;
};

export type ConfigResult =
  | { ok: true; value: BodyConfig }
  | { ok: false; reason: string; code: typeof EX_CONFIG };

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

function parseBind(raw: string | undefined): { host: string; port: number } {
  const text = raw && raw.trim() !== "" ? raw.trim() : "127.0.0.1:8787";
  const idx = text.lastIndexOf(":");
  if (idx <= 0) {
    return { host: text, port: 8787 };
  }
  const host = text.slice(0, idx);
  const port = Number(text.slice(idx + 1));
  return { host, port: Number.isInteger(port) ? port : 8787 };
}

export function isLoopbackHost(host: string): boolean {
  const stripped = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  return LOOPBACK.has(stripped);
}

export function loadConfig(env: NodeJS.ProcessEnv): ConfigResult {
  const issuer = env.VERAX_ISSUER?.trim() ?? "";
  const jwksUrl = env.VERAX_JWKS_URL?.trim() ?? "";
  const audience = env.VERAX_AUDIENCE?.trim() ?? "";
  if (issuer === "" || jwksUrl === "" || audience === "") {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "missing VERAX_ISSUER, VERAX_JWKS_URL, or VERAX_AUDIENCE",
    };
  }
  const bind = parseBind(env.VERAX_BIND);
  const tlsTerminated = env.VERAX_TLS_TERMINATED === "1";
  if (!isLoopbackHost(bind.host) && !tlsTerminated) {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "non-loopback bind without VERAX_TLS_TERMINATED=1",
    };
  }
  const stateDir = env.VERAX_STATE_DIR?.trim() ?? "";
  if (stateDir === "") {
    return { ok: false, code: EX_CONFIG, reason: "missing VERAX_STATE_DIR" };
  }
  const policyFile = env.VERAX_POLICY_FILE?.trim() ?? "";
  if (policyFile === "") {
    return { ok: false, code: EX_CONFIG, reason: "missing VERAX_POLICY_FILE" };
  }
  return {
    ok: true,
    value: {
      issuer,
      jwksUrl,
      audience,
      stateDir,
      bindHost: bind.host,
      bindPort: bind.port,
      policyFile,
      tlsTerminated,
    },
  };
}
