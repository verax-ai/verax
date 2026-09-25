import { readFileSync } from "node:fs";

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
  /**
   * Path to a JWKS file read once at start. Set instead of `jwksUrl`.
   * Loopback binds only.
   */
  jwksFile?: string | null;
  /** Path to an inventory JSON file. Missing file is absence, not a fault. */
  inventoryFile?: string | null;
  /**
   * Path to the `VERAX_DOWNSTREAM` document. A path, not the JSON itself: the
   * document may name a key in `env`, and a secret does not belong in the
   * process environment of every child the operator later starts. Unset means
   * no downstream; a named file that cannot be attached stops the body.
   */
  downstreamFile?: string | null;
  /** Origins allowed to call this HTTP server. Empty means no browser origin. */
  allowedOrigins?: readonly string[];
  /**
   * Bytes one tenant may keep under `memory/`, summed across stored versions.
   * Default is 1 MiB. `VERAX_MEMORY_QUOTA_BYTES` overrides it.
   */
  memoryQuotaBytes?: number;
};

/** Per-tenant `memory.put` cap. The HTTP body cap does not reset this total. */
export const DEFAULT_MEMORY_QUOTA_BYTES = 1024 * 1024;

export function memoryQuotaBytes(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.VERAX_MEMORY_QUOTA_BYTES?.trim() ?? "";
  if (raw === "") return DEFAULT_MEMORY_QUOTA_BYTES;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) return DEFAULT_MEMORY_QUOTA_BYTES;
  return n;
}

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

function jwksFileParses(path: string): boolean {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { keys?: unknown };
    return Array.isArray(parsed.keys) && parsed.keys.length > 0;
  } catch {
    return false;
  }
}

export function loadConfig(env: NodeJS.ProcessEnv): ConfigResult {
  const issuer = env.VERAX_ISSUER?.trim() ?? "";
  const jwksUrl = env.VERAX_JWKS_URL?.trim() ?? "";
  const jwksFile = env.VERAX_JWKS_FILE?.trim() ?? "";
  const audience = env.VERAX_AUDIENCE?.trim() ?? "";
  if (jwksUrl !== "" && jwksFile !== "") {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "both VERAX_JWKS_URL and VERAX_JWKS_FILE",
    };
  }
  if (issuer === "" || audience === "" || (jwksUrl === "" && jwksFile === "")) {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "missing VERAX_ISSUER, VERAX_JWKS_URL, or VERAX_AUDIENCE",
    };
  }
  const bind = parseBind(env.VERAX_BIND);
  const tlsTerminated = env.VERAX_TLS_TERMINATED === "1";
  if (jwksFile !== "" && !isLoopbackHost(bind.host)) {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "VERAX_JWKS_FILE needs a loopback bind",
    };
  }
  if (!isLoopbackHost(bind.host) && !tlsTerminated) {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "non-loopback bind without VERAX_TLS_TERMINATED=1",
    };
  }
  if (jwksFile !== "" && !jwksFileParses(jwksFile)) {
    return {
      ok: false,
      code: EX_CONFIG,
      reason: "VERAX_JWKS_FILE is missing or unparsable",
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
  const inventoryRaw = env.VERAX_INVENTORY_FILE?.trim() ?? "";
  const downstreamRaw = env.VERAX_DOWNSTREAM?.trim() ?? "";
  return {
    ok: true,
    value: {
      issuer,
      jwksUrl,
      jwksFile: jwksFile === "" ? null : jwksFile,
      audience,
      stateDir,
      bindHost: bind.host,
      bindPort: bind.port,
      policyFile,
      tlsTerminated,
      inventoryFile: inventoryRaw === "" ? null : inventoryRaw,
      downstreamFile: downstreamRaw === "" ? null : downstreamRaw,
      allowedOrigins: (env.VERAX_ALLOWED_ORIGINS ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item !== ""),
      memoryQuotaBytes: memoryQuotaBytes(env),
    },
  };
}

/** `--inventory <file>` wins over VERAX_INVENTORY_FILE. */
export function overlayInventoryArg(env: NodeJS.ProcessEnv, argv: readonly string[]): NodeJS.ProcessEnv | { error: string } {
  const i = argv.indexOf("--inventory");
  if (i === -1) return env;
  const path = argv[i + 1];
  if (!path || path.startsWith("-")) {
    return { error: "missing --inventory path" };
  }
  return { ...env, VERAX_INVENTORY_FILE: path };
}
